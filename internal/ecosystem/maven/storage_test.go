package maven

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"github.com/radiergummi/tspackages/internal/config"
	"github.com/radiergummi/tspackages/internal/identity"
	"github.com/radiergummi/tspackages/internal/records"
	"github.com/radiergummi/tspackages/internal/resolve"
	"github.com/radiergummi/tspackages/internal/storage"
	"github.com/radiergummi/tspackages/internal/testutil"
)

var deployCaller = identity.Caller{Login: "ci@example.com", NodeName: "ci", NodeStableID: "n1"}

func fsDriver(t *testing.T) storage.Driver {
	t.Helper()
	d, err := storage.NewFS(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// s3Driver returns a driver on a fresh bucket of the S3 test service,
// emptied and removed after the test; it skips without the service.
func s3Driver(t *testing.T) storage.Driver {
	t.Helper()
	endpoint, accessKey, secretKey, bucket := testutil.S3Env(t)
	ctx := context.Background()
	cfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion("us-east-1"),
		awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(accessKey, secretKey, "")))
	if err != nil {
		t.Fatal(err)
	}
	client := s3.NewFromConfig(cfg, func(o *s3.Options) { o.BaseEndpoint = aws.String(endpoint); o.UsePathStyle = true })
	if _, err := client.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: &bucket}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		pager := s3.NewListObjectsV2Paginator(client, &s3.ListObjectsV2Input{Bucket: &bucket})
		for pager.HasMorePages() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				t.Logf("list %s: %v", bucket, err)
				return
			}
			for _, o := range page.Contents {
				client.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: &bucket, Key: o.Key})
			}
		}
		client.DeleteBucket(ctx, &s3.DeleteBucketInput{Bucket: &bucket})
	})
	d, err := storage.Open(ctx, config.StoreConfig{Driver: "s3", Endpoint: endpoint, Bucket: bucket, AccessKeyID: accessKey, SecretAccessKey: secretKey})
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// drivers runs f against the fs driver and, when the S3 test service is
// configured, against S3.
func drivers(t *testing.T, f func(t *testing.T, d func(t *testing.T) storage.Driver)) {
	t.Run("fs", func(t *testing.T) { f(t, fsDriver) })
	t.Run("s3", func(t *testing.T) { f(t, s3Driver) })
}

type stEnv struct {
	src  *StorageSource
	d    storage.Driver
	recD storage.Driver
	tmp  string // spooled deploy bodies
}

func newStEnv(t *testing.T, d storage.Driver) *stEnv {
	t.Helper()
	recD := fsDriver(t)
	src := NewStorageSource("hosted", []string{"com.matchory:*"}, d, records.New(recD), 16<<20, slog.New(slog.DiscardHandler))
	return &stEnv{src: src, d: d, recD: recD, tmp: t.TempDir()}
}

// deploy spools body and deploys it at path. Every failure is returned,
// so it may run on another goroutine than the test.
func (e *stEnv) deploy(t *testing.T, path, body string) error {
	t.Helper()
	p, err := ParsePath(strings.TrimPrefix(path, "/"))
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(e.tmp, "body-*")
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := io.WriteString(f, body); err != nil {
		return err
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return err
	}
	return e.src.Deploy(context.Background(), deployCaller, p, f, int64(len(body)))
}

func (e *stEnv) mustDeploy(t *testing.T, path, body string) {
	t.Helper()
	if err := e.deploy(t, path, body); err != nil {
		t.Fatalf("deploy %s: %v", path, err)
	}
}

// file reads the stored file at path.
func (e *stEnv) file(t *testing.T, path string) (string, File) {
	t.Helper()
	f, err := e.src.File(context.Background(), mustPath(t, path))
	if err != nil {
		t.Fatalf("File(%s): %v", path, err)
	}
	b, err := readFile(f, nil)
	if err != nil {
		t.Fatal(err)
	}
	return string(b), f
}

type parsedMetadata struct {
	GroupID    string `xml:"groupId"`
	ArtifactID string `xml:"artifactId"`
	Version    string `xml:"version"`
	Versioning struct {
		Latest   string   `xml:"latest"`
		Release  string   `xml:"release"`
		Versions []string `xml:"versions>version"`
		Snapshot struct {
			Timestamp   string `xml:"timestamp"`
			BuildNumber int    `xml:"buildNumber"`
		} `xml:"snapshot"`
		LastUpdated      string `xml:"lastUpdated"`
		SnapshotVersions []struct {
			Classifier string `xml:"classifier"`
			Extension  string `xml:"extension"`
			Value      string `xml:"value"`
		} `xml:"snapshotVersions>snapshotVersion"`
	} `xml:"versioning"`
}

func (e *stEnv) metadata(t *testing.T, path string) parsedMetadata {
	t.Helper()
	b, err := e.src.Metadata(context.Background(), mustPath(t, path))
	if err != nil {
		t.Fatalf("Metadata(%s): %v", path, err)
	}
	var m parsedMetadata
	if err := xml.Unmarshal(b, &m); err != nil {
		t.Fatalf("Metadata(%s): %v\n%s", path, err, b)
	}
	return m
}

func (e *stEnv) audits(t *testing.T) []records.Audit {
	t.Helper()
	var out []records.Audit
	for info, err := range e.recD.List(context.Background(), "audit/") {
		if err != nil {
			t.Fatal(err)
		}
		rc, _, err := e.recD.Get(context.Background(), info.Key)
		if err != nil {
			t.Fatal(err)
		}
		var a records.Audit
		err = json.NewDecoder(rc).Decode(&a)
		rc.Close()
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, a)
	}
	return out
}

const (
	artMeta = "com/matchory/lib/maven-metadata.xml"
	relDir  = "com/matchory/lib/1.0/"
	snapDir = "com/matchory/lib/1.0-SNAPSHOT/"
)

// libPOM is a POM of com.matchory:lib at version v with extra elements.
func libPOM(v, extra string) string {
	return pom(`<groupId>com.matchory</groupId><artifactId>lib</artifactId><version>` + v + `</version>` + extra)
}

const clientArtifactMetadata = `<?xml version="1.0" encoding="UTF-8"?>
<metadata><groupId>com.matchory</groupId><artifactId>lib</artifactId><versioning><versions><version>1.0</version></versions></versioning></metadata>`

func TestReleaseDeployAndRead(t *testing.T) {
	drivers(t, func(t *testing.T, d func(t *testing.T) storage.Driver) {
		e := newStEnv(t, d(t))
		p := libPOM("1.0", "")
		jar := "PK\x03\x04 the jar"
		pd, jd := allDigests(p), allDigests(jar)
		// Maven's order.
		e.mustDeploy(t, relDir+"lib-1.0.pom", p)
		e.mustDeploy(t, relDir+"lib-1.0.pom.sha1", pd.SHA1)
		e.mustDeploy(t, relDir+"lib-1.0.pom.md5", pd.MD5)
		e.mustDeploy(t, relDir+"lib-1.0.jar", jar)
		e.mustDeploy(t, relDir+"lib-1.0.jar.sha1", jd.SHA1)
		e.mustDeploy(t, relDir+"lib-1.0.jar.md5", jd.MD5)
		e.mustDeploy(t, artMeta, clientArtifactMetadata)
		e.mustDeploy(t, artMeta+".sha1", strings.Repeat("ab", 20))
		e.mustDeploy(t, artMeta+".md5", strings.Repeat("cd", 16))

		m := e.metadata(t, artMeta)
		if m.GroupID != "com.matchory" || m.ArtifactID != "lib" || !slices.Equal(m.Versioning.Versions, []string{"1.0"}) ||
			m.Versioning.Release != "1.0" || m.Versioning.Latest != "1.0" || len(m.Versioning.LastUpdated) != 14 {
			t.Errorf("metadata = %+v", m)
		}
		body, f := e.file(t, relDir+"lib-1.0.jar")
		if body != jar || f.Digests != jd || !f.Immutable || f.Size != int64(len(jar)) || f.Modified.IsZero() {
			t.Errorf("File = %q %+v", body, f)
		}
		got, err := e.src.Digests(context.Background(), mustPath(t, relDir+"lib-1.0.pom"))
		if err != nil || got != pd {
			t.Errorf("Digests(pom) = %+v, %v; want %+v", got, err, pd)
		}
		var files []string
		for _, a := range e.audits(t) {
			if a.Action != "deploy" || a.Package != "com.matchory:lib" || a.Version != "1.0" || a.Uploader.Login != deployCaller.Login {
				t.Errorf("audit = %+v", a)
			}
			files = append(files, a.File)
		}
		slices.Sort(files)
		if !slices.Equal(files, []string{"lib-1.0.jar", "lib-1.0.pom"}) {
			t.Errorf("audited files = %v", files)
		}
		provs, err := records.New(e.recD).FileProvenance(context.Background(), ecoName, "com.matchory:lib", "1.0", "lib-1.0.jar")
		if err != nil || len(provs) != 1 || provs[0].File != "lib-1.0.jar" || provs[0].SourceType != "storage" || provs[0].SHA1 != jd.SHA1 || provs[0].SHA256 != jd.SHA256 || provs[0].Uploader == nil {
			t.Errorf("provenance = %+v, %v", provs, err)
		}
		// Group-level metadata is never served from storage.
		if _, err := e.src.Metadata(context.Background(), mustPath(t, "com/matchory/maven-metadata.xml")); !errors.Is(err, resolve.ErrNotFound) {
			t.Errorf("group-level Metadata err = %v, want ErrNotFound", err)
		}
	})
}

func TestGradleOrder(t *testing.T) {
	drivers(t, func(t *testing.T, d func(t *testing.T) storage.Driver) {
		e := newStEnv(t, d(t))
		jar := "PK\x03\x04 gradle jar"
		e.mustDeploy(t, relDir+"lib-1.0.jar", jar)
		e.mustDeploy(t, relDir+"lib-1.0.jar.sha256", allDigests(jar).SHA256)
		if _, err := e.src.Metadata(context.Background(), mustPath(t, artMeta)); !errors.Is(err, resolve.ErrNotFound) {
			t.Errorf("Metadata before the POM: err = %v, want ErrNotFound", err)
		}
		e.mustDeploy(t, relDir+"lib-1.0.pom", readTestdata(t, "lib-1.0.pom"))
		module := readTestdata(t, "lib-1.0.module")
		e.mustDeploy(t, relDir+"lib-1.0.module", module)
		if got, _ := e.file(t, relDir+"lib-1.0.module"); got != module {
			t.Errorf(".module = %q", got)
		}
		if m := e.metadata(t, artMeta); !slices.Equal(m.Versioning.Versions, []string{"1.0"}) {
			t.Errorf("versions = %v", m.Versioning.Versions)
		}
		// A .module naming other coordinates is refused.
		bad := strings.Replace(module, `"version": "1.0"`, `"version": "2.0"`, 1)
		wantRequestError(t, "bad .module", e.deploy(t, "com/matchory/lib/1.1/lib-1.1.module", bad), 400, "component.version")
	})
}

func TestWriteOnce(t *testing.T) {
	drivers(t, func(t *testing.T, d func(t *testing.T) storage.Driver) {
		e := newStEnv(t, d(t))
		jar := "PK\x03\x04 one"
		e.mustDeploy(t, relDir+"lib-1.0.jar", jar)
		e.mustDeploy(t, relDir+"lib-1.0.jar", jar)
		if err := e.deploy(t, relDir+"lib-1.0.jar", "PK\x03\x04 two"); !errors.Is(err, ErrExists) {
			t.Errorf("other bytes: err = %v, want ErrExists", err)
		}
		e.mustDeploy(t, relDir+"lib-1.0.pom", libPOM("1.0", ""))
		e.mustDeploy(t, relDir+"lib-1.0.pom", libPOM("1.0", ""))
		if err := e.deploy(t, relDir+"lib-1.0.pom", libPOM("1.0", "<packaging>pom</packaging>")); !errors.Is(err, ErrExists) {
			t.Errorf("other POM: err = %v, want ErrExists", err)
		}
		e.mustDeploy(t, relDir+"lib-1.0-sources.jar", "sources")
		e.mustDeploy(t, relDir+"lib-1.0.jar.asc", "signature")
		if err := e.deploy(t, relDir+"lib-1.0-sources.jar", "other sources"); !errors.Is(err, ErrExists) {
			t.Errorf("replaced classifier: err = %v, want ErrExists", err)
		}
		if got, _ := e.file(t, relDir+"lib-1.0.jar"); got != jar {
			t.Errorf("jar = %q", got)
		}
		if err := e.deploy(t, relDir+"lib-1.0.jar", "x"); err == nil || !strings.Contains(err.Error(), "lib-1.0.jar already exists with other content") {
			t.Errorf("err = %v", err)
		}
	})
}

func TestConcurrentReleaseDeploy(t *testing.T) {
	drivers(t, func(t *testing.T, d func(t *testing.T) storage.Driver) {
		for range 20 {
			e := newStEnv(t, d(t))
			files := []string{"lib-1.0.pom", "lib-1.0.jar"}
			bodies := [2][2]string{
				{libPOM("1.0", "<description>a</description>"), "PK\x03\x04 a"},
				{libPOM("1.0", "<description>b</description>"), "PK\x03\x04 b"},
			}
			var errs [2][2]error
			var wg sync.WaitGroup
			for i := range 2 {
				wg.Go(func() {
					for j, f := range files {
						errs[i][j] = e.deploy(t, relDir+f, bodies[i][j])
					}
				})
			}
			wg.Wait()
			for j, f := range files {
				winner := -1
				for i := range 2 {
					switch err := errs[i][j]; {
					case err == nil:
						if winner >= 0 {
							t.Fatalf("%s: both deploys succeeded", f)
						}
						winner = i
					case !errors.Is(err, ErrExists):
						t.Fatalf("%s: deployer %d: %v", f, i, err)
					}
				}
				if winner < 0 {
					t.Fatalf("%s: no deploy succeeded", f)
				}
				body, sf := e.file(t, relDir+f)
				if body != bodies[winner][j] || sf.Digests != allDigests(body) {
					t.Fatalf("%s: served %q (%+v), winner deployed %q", f, body, sf.Digests, bodies[winner][j])
				}
			}
			if m := e.metadata(t, artMeta); !slices.Equal(m.Versioning.Versions, []string{"1.0"}) {
				t.Fatalf("versions = %v", m.Versioning.Versions)
			}
		}
	})
}

func TestSnapshotDeploy(t *testing.T) {
	drivers(t, func(t *testing.T, d func(t *testing.T) storage.Driver) {
		e := newStEnv(t, d(t))
		verMeta := snapDir + "maven-metadata.xml"
		if _, err := e.src.Metadata(context.Background(), mustPath(t, verMeta)); !errors.Is(err, resolve.ErrNotFound) {
			t.Errorf("version Metadata before a deploy: err = %v, want ErrNotFound", err)
		}
		b1, b2 := "lib-1.0-20261123.101010-1", "lib-1.0-20261123.101500-2"
		p := libPOM("1.0-SNAPSHOT", "")
		e.mustDeploy(t, snapDir+b1+".pom", p)
		e.mustDeploy(t, snapDir+b1+".jar", "jar 1")
		e.mustDeploy(t, snapDir+b1+"-sources.jar", "sources 1")
		e.mustDeploy(t, verMeta, `<metadata><groupId>com.matchory</groupId><artifactId>lib</artifactId><version>1.0-SNAPSHOT</version></metadata>`)
		if m := e.metadata(t, verMeta); m.Versioning.Snapshot.BuildNumber != 1 {
			t.Errorf("after build 1: snapshot = %+v", m.Versioning.Snapshot)
		}
		e.mustDeploy(t, snapDir+b2+".pom", p)
		e.mustDeploy(t, snapDir+b2+".jar", "jar 2")

		m := e.metadata(t, verMeta)
		if m.Version != "1.0-SNAPSHOT" || m.Versioning.Snapshot.Timestamp != "20261123.101500" || m.Versioning.Snapshot.BuildNumber != 2 {
			t.Errorf("version metadata = %+v", m)
		}
		var sv []string
		for _, s := range m.Versioning.SnapshotVersions {
			sv = append(sv, s.Classifier+":"+s.Extension+"="+s.Value)
		}
		want := []string{":jar=1.0-20261123.101500-2", ":pom=1.0-20261123.101500-2", "sources:jar=1.0-20261123.101010-1"}
		if !slices.Equal(sv, want) {
			t.Errorf("snapshotVersions = %v, want %v", sv, want)
		}
		am := e.metadata(t, artMeta)
		if !slices.Equal(am.Versioning.Versions, []string{"1.0-SNAPSHOT"}) || am.Versioning.Latest != "1.0-SNAPSHOT" || am.Versioning.Release != "" {
			t.Errorf("artifact metadata = %+v", am)
		}

		// Timestamped files are immutable to clients, so they are written
		// once: the same bytes again succeed, other bytes are 409.
		if _, f := e.file(t, snapDir+b2+".jar"); !f.Immutable {
			t.Error("timestamped file not immutable")
		}
		e.mustDeploy(t, snapDir+b2+".jar", "jar 2")
		if err := e.deploy(t, snapDir+b2+".jar", "jar 2 again"); !errors.Is(err, ErrExists) {
			t.Errorf("timestamped overwrite: err = %v, want ErrExists", err)
		}
		if got, _ := e.file(t, snapDir+b2+".jar"); got != "jar 2" {
			t.Errorf("timestamped jar after refused overwrite = %q", got)
		}

		// Non-timestamped SNAPSHOT names are overwritable and not immutable;
		// an overwrite is audited with the replaced sha256.
		plain := "lib-1.0-SNAPSHOT.jar"
		e.mustDeploy(t, snapDir+plain, "plain 1")
		e.mustDeploy(t, snapDir+plain, "plain 2")
		if got, f := e.file(t, snapDir+plain); got != "plain 2" || f.Immutable || f.Digests != allDigests(got) {
			t.Errorf("plain SNAPSHOT jar = %q, immutable %v, digests %+v", got, f.Immutable, f.Digests)
		}
		var previous []string
		for _, a := range e.audits(t) {
			if a.Previous != "" {
				previous = append(previous, a.File+" "+a.Previous+" "+a.SHA256)
			}
		}
		if want := plain + " " + allDigests("plain 1").SHA256 + " " + allDigests("plain 2").SHA256; !slices.Equal(previous, []string{want}) {
			t.Errorf("audits with Previous = %v, want %v", previous, want)
		}
	})
}

// TestConcurrentSnapshotOverwrite deploys other bytes to one
// non-timestamped SNAPSHOT file from two goroutines: every deploy succeeds
// and the served digests match the served bytes.
func TestConcurrentSnapshotOverwrite(t *testing.T) {
	drivers(t, func(t *testing.T, d func(t *testing.T) storage.Driver) {
		e := newStEnv(t, d(t))
		path := snapDir + "lib-1.0-SNAPSHOT.jar"
		for run := range 10 {
			var wg sync.WaitGroup
			var errs [2]error
			for i := range 2 {
				wg.Go(func() { errs[i] = e.deploy(t, path, fmt.Sprintf("jar %d/%d", run, i)) })
			}
			wg.Wait()
			if errs[0] != nil || errs[1] != nil {
				t.Fatalf("run %d: %v, %v", run, errs[0], errs[1])
			}
			if body, f := e.file(t, path); f.Digests != allDigests(body) {
				t.Fatalf("run %d: served %q with digests %+v", run, body, f.Digests)
			}
		}
	})
}

func TestChecksumUploads(t *testing.T) {
	drivers(t, func(t *testing.T, d func(t *testing.T) storage.Driver) {
		e := newStEnv(t, d(t))
		jar := "PK\x03\x04 sums"
		wantRequestError(t, "before the file", e.deploy(t, relDir+"lib-1.0.jar.sha1", allDigests(jar).SHA1), 400, "upload lib-1.0.jar first")
		e.mustDeploy(t, relDir+"lib-1.0.jar", jar)
		wantRequestError(t, "mismatch", e.deploy(t, relDir+"lib-1.0.jar.sha1", allDigests("other").SHA1), 400, "checksum mismatch")
		e.mustDeploy(t, relDir+"lib-1.0.jar.sha1", strings.ToUpper(allDigests(jar).SHA1)+"  lib-1.0.jar\n")
		e.mustDeploy(t, relDir+"lib-1.0.jar.sha512", allDigests(jar).SHA512)
		e.mustDeploy(t, artMeta+".sha256", strings.Repeat("0", 64))
		e.mustDeploy(t, snapDir+"maven-metadata.xml.sha1", strings.Repeat("f", 40))
		wantRequestError(t, "malformed metadata checksum", e.deploy(t, artMeta+".sha1", "xyz"), 400, "invalid checksum file")
	})
}

func TestCaseCollision(t *testing.T) {
	drivers(t, func(t *testing.T, d func(t *testing.T) storage.Driver) {
		e := newStEnv(t, d(t))
		e.mustDeploy(t, relDir+"lib-1.0.jar", "jar")
		wantRequestError(t, "group case", e.deploy(t, "com/Matchory/lib/1.0/lib-1.0.jar", "jar"), 409,
			"com.Matchory:lib differs only in case from com.matchory:lib")
		wantRequestError(t, "artifact case", e.deploy(t, "com/matchory/Lib/1.0/Lib-1.0.jar", "jar"), 409, "differs only in case")
		e.mustDeploy(t, "com/matchory/lib/1.1/lib-1.1.jar", "jar")
	})
}

func TestIndexRebuild(t *testing.T) {
	drivers(t, func(t *testing.T, d func(t *testing.T) storage.Driver) {
		e := newStEnv(t, d(t))
		ctx := context.Background()
		e.mustDeploy(t, relDir+"lib-1.0.pom", libPOM("1.0", "<packaging>pom</packaging>"))
		e.mustDeploy(t, "com/matchory/lib/1.1/lib-1.1.pom", libPOM("1.1", ""))
		e.mustDeploy(t, snapDir+"lib-1.0-20261123.101010-1.pom", libPOM("1.0-SNAPSHOT", ""))
		e.mustDeploy(t, "com/matchory/lib/2.0/lib-2.0.jar", "no POM yet")
		all := []string{"1.0-SNAPSHOT", "1.0", "1.1"}
		if m := e.metadata(t, artMeta); !slices.Equal(m.Versioning.Versions, all) {
			t.Fatalf("versions = %v", m.Versioning.Versions)
		}
		key := "maven/" + storage.EscapeSegment("com.matchory") + "/" + storage.EscapeSegment("lib") + "/index.json"
		if err := e.d.Delete(ctx, key); err != nil {
			t.Fatal(err)
		}
		if m := e.metadata(t, artMeta); !slices.Equal(m.Versioning.Versions, all) {
			t.Errorf("after delete: versions = %v", m.Versioning.Versions)
		}
		if _, err := e.d.Put(ctx, key, strings.NewReader("{")); err != nil {
			t.Fatal(err)
		}
		if m := e.metadata(t, artMeta); !slices.Equal(m.Versioning.Versions, all) {
			t.Errorf("after corruption: versions = %v", m.Versioning.Versions)
		}
		// The next POM writes the rebuilt index, packaging included.
		e.mustDeploy(t, "com/matchory/lib/1.2/lib-1.2.pom", libPOM("1.2", ""))
		rc, _, err := e.d.Get(ctx, key)
		if err != nil {
			t.Fatal(err)
		}
		defer rc.Close()
		var idx struct {
			Versions map[string]struct{ Packaging string } `json:"versions"`
		}
		if err := json.NewDecoder(rc).Decode(&idx); err != nil {
			t.Fatal(err)
		}
		if len(idx.Versions) != 4 || idx.Versions["1.0"].Packaging != "pom" || idx.Versions["1.2"].Packaging != "jar" {
			t.Errorf("index = %+v", idx)
		}
	})
}

func TestLongNames(t *testing.T) {
	e := newStEnv(t, fsDriver(t))
	// A sidecar key segment is the escaped name plus ".json".
	art := strings.Repeat("a", 147)
	e.mustDeploy(t, "g/"+art+"/1/"+art+"-1.jar", "jar") // 153 bytes
	art += "a"
	wantRequestError(t, "154-byte file", e.deploy(t, "g/"+art+"/1/"+art+"-1.jar", "jar"), 400, "longer than 153 bytes")
	// "<g>:<a>" is one key segment too.
	art = strings.Repeat("a", 140)
	group := strings.Repeat("g", 16)
	wantRequestError(t, "157-byte g:a", e.deploy(t, group+"/"+art+"/1/"+art+"-1.jar", "jar"), 400, "longer than 156 bytes")
	e.mustDeploy(t, group[1:]+"/"+art+"/1/"+art+"-1.jar", "jar")
}

// TestSidecarOfOtherBytes: a stored file whose sidecar was recorded for
// other bytes (a SNAPSHOT overwrite between its file and sidecar writes) is
// served without digests and not immutable; Digests hashes the bytes.
func TestSidecarOfOtherBytes(t *testing.T) {
	drivers(t, func(t *testing.T, d func(t *testing.T) storage.Driver) {
		e := newStEnv(t, d(t))
		ctx := context.Background()
		path := snapDir + "lib-1.0-20261123.101010-1.jar"
		e.mustDeploy(t, path, "jar 1")
		p := mustPath(t, path)
		fk := fileKey(p.Coords, p.File)
		info, err := e.d.Stat(ctx, fk)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := e.d.PutIfMatch(ctx, fk, strings.NewReader("jar 2"), info.ETag); err != nil {
			t.Fatal(err)
		}
		body, f := e.file(t, path)
		if body != "jar 2" || f.Digests != (Digests{}) || f.Immutable {
			t.Errorf("served %q, digests %+v, immutable %v", body, f.Digests, f.Immutable)
		}
		if got, err := e.src.Digests(ctx, p); err != nil || got != allDigests("jar 2") {
			t.Errorf("Digests = %+v, %v; want %+v", got, err, allDigests("jar 2"))
		}
	})
}

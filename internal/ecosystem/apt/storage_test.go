package apt

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp"
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

var uploadCaller = identity.Caller{Login: "ci@example.com", NodeName: "ci", NodeStableID: "n1"}

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
	t      *testing.T
	src    *StorageSource
	d      storage.Driver
	rec    storage.Driver
	cacheD storage.Driver
	entity *openpgp.Entity
}

func newStEnv(t *testing.T, d storage.Driver) *stEnv {
	t.Helper()
	return newStEnvLog(t, d, slog.New(slog.DiscardHandler))
}

func newStEnvLog(t *testing.T, d storage.Driver, log *slog.Logger) *stEnv {
	t.Helper()
	recD, cacheD := fsDriver(t), fsDriver(t)
	cache, err := storage.NewCache(context.Background(), cacheD, 1<<30, log)
	if err != nil {
		t.Fatal(err)
	}
	e := newEntity(t, "repo", nil)
	src := NewStorageSource("hosted", []string{"acme*"}, d, cache, records.New(recD), signer(t, e), log)
	return &stEnv{t: t, src: src, d: d, rec: recD, cacheD: cacheD, entity: e}
}

// upload builds a .deb whose control is control (plus a description line
// carrying marker, to vary the bytes) and uploads it.
func (e *stEnv) upload(suite, component, name, version, marker string) (Deb, bool, error) {
	ctl := fmt.Sprintf("Package: %s\nVersion: %s\nArchitecture: all\nMaintainer: A <a@example.com>\nDescription: %s\nX-Secret: no\n", name, version, marker)
	b := testutil.Deb(e.t, ctl, testutil.DebOptions{})
	return e.uploadBytes(suite, component, b)
}

func (e *stEnv) uploadBytes(suite, component string, b []byte) (Deb, bool, error) {
	c, err := Inspect(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		return Deb{}, false, err
	}
	f, err := os.CreateTemp("", "apt-body-*")
	if err != nil {
		return Deb{}, false, err
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if _, err := f.Write(b); err != nil {
		return Deb{}, false, err
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return Deb{}, false, err
	}
	created, err := e.src.Upload(context.Background(), uploadCaller, suite, component, c, f, int64(len(b)))
	return c.Deb, created, err
}

func (e *stEnv) members(t *testing.T, suite string) []member {
	t.Helper()
	ms, _, err := e.src.suite(context.Background(), suite)
	if err != nil {
		t.Fatal(err)
	}
	return ms
}

func names(ms []member) []string {
	var out []string
	for _, m := range ms {
		out = append(out, m.Component+"/"+m.Deb.Name)
	}
	return out
}

func allow(string) bool { return true }

func TestUploadWriteOnce(t *testing.T) {
	drivers(t, func(t *testing.T, newDriver func(*testing.T) storage.Driver) {
		e := newStEnv(t, newDriver(t))
		d, created, err := e.upload("bookworm", "main", "acme", "1.0-1", "one")
		if err != nil || !created {
			t.Fatalf("first upload: created=%v err=%v", created, err)
		}
		_, created, err = e.upload("trixie", "main", "acme", "1.0-1", "one")
		if err != nil || created {
			t.Fatalf("same bytes: created=%v err=%v", created, err)
		}
		for _, s := range []string{"bookworm", "trixie"} {
			if got := names(e.members(t, s)); !slices.Equal(got, []string{"main/acme"}) {
				t.Errorf("suite %s lists %v", s, got)
			}
		}
		_, _, err = e.upload("bookworm", "main", "acme", "1.0-1", "other")
		if !errors.Is(err, ErrExists) {
			t.Fatalf("other bytes: %v, want ErrExists", err)
		}
		m := e.members(t, "bookworm")[0]
		want := Stanza{{"Package", "acme"}, {"Version", "1.0-1"}, {"Architecture", "all"}, {"Maintainer", "A <a@example.com>"}, {"Description", "one"}}
		if !slices.Equal(m.Fields, want) || m.Deb != d || m.Size == 0 || len(m.SHA256) != 64 {
			t.Errorf("member = %+v", m)
		}
		// Provenance once per file; audit: one upload, two suite-adds.
		var actions []string
		for info, err := range e.rec.List(context.Background(), "audit/") {
			if err != nil {
				t.Fatal(err)
			}
			rc, _, _ := e.rec.Get(context.Background(), info.Key)
			b, _ := io.ReadAll(rc)
			rc.Close()
			for _, a := range []string{"upload", "suite-add"} {
				if bytes.Contains(b, []byte(`"action":"`+a+`"`)) {
					actions = append(actions, a)
				}
			}
		}
		slices.Sort(actions)
		if !slices.Equal(actions, []string{"suite-add", "suite-add", "upload"}) {
			t.Errorf("audit actions = %v", actions)
		}
	})
}

func TestUploadEpoch(t *testing.T) {
	drivers(t, func(t *testing.T, newDriver func(*testing.T) storage.Driver) {
		e := newStEnv(t, newDriver(t))
		if _, _, err := e.upload("bookworm", "main", "acme", "1:2.0-1", "one"); err != nil {
			t.Fatal(err)
		}
		if _, _, err := e.upload("bookworm", "main", "acme", "2.0-1", "other"); !errors.Is(err, ErrExists) {
			t.Fatalf("got %v, want ErrExists", err)
		}
		if ms := e.members(t, "bookworm"); len(ms) != 1 || ms[0].Deb.Version != "1:2.0-1" {
			t.Errorf("members = %+v", ms)
		}
	})
}

func TestConcurrentUploadsSameSuite(t *testing.T) {
	drivers(t, func(t *testing.T, newDriver func(*testing.T) storage.Driver) {
		e := newStEnv(t, newDriver(t))
		var wg sync.WaitGroup
		errs := make(chan error, 8)
		for i := range 8 {
			wg.Go(func() {
				_, _, err := e.upload("bookworm", "main", fmt.Sprintf("acme-%d", i), "1.0", "x")
				errs <- err
			})
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			if err != nil {
				t.Fatal(err)
			}
		}
		if got := e.members(t, "bookworm"); len(got) != 8 {
			t.Fatalf("suite lists %d members: %v", len(got), names(got))
		}
	})
}

func TestIndexRebuild(t *testing.T) {
	drivers(t, func(t *testing.T, newDriver func(*testing.T) storage.Driver) {
		e := newStEnv(t, newDriver(t))
		for _, n := range []string{"acme-a", "acme-b"} {
			if _, _, err := e.upload("bookworm", "main", n, "1.0", "x"); err != nil {
				t.Fatal(err)
			}
		}
		before := e.members(t, "bookworm")
		ctx := context.Background()
		key := "apt/hosted/dists/" + storage.EscapeSegment("bookworm") + "/index.json"
		if err := e.d.Delete(ctx, key); err != nil {
			t.Fatal(err)
		}
		after := e.members(t, "bookworm")
		if !slices.EqualFunc(before, after, func(a, b member) bool {
			return a.Component == b.Component && a.Deb == b.Deb && slices.Equal(a.Fields, b.Fields) && a.Size == b.Size && a.SHA256 == b.SHA256 && a.Uploaded.Equal(b.Uploaded)
		}) {
			t.Errorf("rebuilt %+v, want %+v", after, before)
		}
		// A corrupt index is rebuilt too.
		if _, err := e.d.Put(ctx, key, bytes.NewReader([]byte("{"))); err != nil {
			t.Fatal(err)
		}
		if got := e.members(t, "bookworm"); len(got) != 2 {
			t.Errorf("after corrupt index: %v", names(got))
		}
		// A file stored without its member object (a crash) is not listed.
		d := Deb{"acme-c", "1.0", "all"}
		pk := poolPrefix("hosted", d)
		if _, err := e.d.Put(ctx, pk+"deb", bytes.NewReader([]byte("x"))); err != nil {
			t.Fatal(err)
		}
		if _, err := e.d.Put(ctx, pk+"deb.json", bytes.NewReader([]byte(`{"fields":[["Package","acme-c"]],"size":1,"sha256":"`+fmt.Sprintf("%064d", 0)+`"}`))); err != nil {
			t.Fatal(err)
		}
		if err := e.d.Delete(ctx, key); err != nil {
			t.Fatal(err)
		}
		if got := e.members(t, "bookworm"); len(got) != 2 {
			t.Errorf("orphan file listed: %v", names(got))
		}
	})
}

func TestUploadCompletesAfterCrash(t *testing.T) {
	e := newStEnv(t, fsDriver(t))
	b := testutil.Deb(t, "Package: acme\nVersion: 1.0\nArchitecture: all\nMaintainer: A <a@example.com>\nDescription: d\n", testutil.DebOptions{})
	c, _ := Inspect(bytes.NewReader(b), int64(len(b)))
	sum := fmt.Sprintf("%x", sha256sum(b))
	// Only the claim survived.
	if _, err := e.d.PutIfAbsent(context.Background(), poolPrefix("hosted", c.Deb)+"~claim", bytes.NewReader([]byte(sum))); err != nil {
		t.Fatal(err)
	}
	if _, created, err := e.uploadBytes("bookworm", "main", b); err != nil || created {
		t.Fatalf("created=%v err=%v", created, err)
	}
	if ms := e.members(t, "bookworm"); len(ms) != 1 {
		t.Fatalf("members = %v", ms)
	}
	blob, err := e.src.Pool(context.Background(), ReadAccess{Name: allow}, Path{Kind: KindPool, Rel: "pool/acme/" + c.Deb.FileName()})
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(blob.Body)
	blob.Body.Close()
	if !bytes.Equal(got, b) {
		t.Error("stored bytes differ")
	}
}

func TestPoolHidden(t *testing.T) {
	drivers(t, func(t *testing.T, newDriver func(*testing.T) storage.Driver) {
		e := newStEnv(t, newDriver(t))
		d, _, err := e.upload("bookworm", "main", "acme", "1:1.0-1", "one")
		if err != nil {
			t.Fatal(err)
		}
		p := Path{Kind: KindPool, Rel: "pool/acme/" + d.FileName()}
		ctx := context.Background()
		_, err = e.src.Pool(ctx, ReadAccess{Any: true, Name: func(string) bool { return false }}, p)
		if !errors.Is(err, resolve.ErrNotFound) {
			t.Fatalf("hidden: %v", err)
		}
		blob, err := e.src.Pool(ctx, ReadAccess{Any: true, Name: allow}, p)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(blob.Body)
		blob.Body.Close()
		m := e.members(t, "bookworm")[0]
		if int64(len(b)) != blob.Size || blob.Size != m.Size || !blob.Immutable || blob.ETag != `"sha256-`+m.SHA256+`"` || !blob.Modified.Equal(m.Uploaded) {
			t.Errorf("blob = %+v", blob)
		}
		for _, rel := range []string{"pool/other/" + d.FileName(), "pool/acme/acme_9.9_all.deb", "pool/acme/x.deb", "pool/acme/main/" + d.FileName()} {
			if _, err := e.src.Pool(ctx, ReadAccess{Name: allow}, Path{Kind: KindPool, Rel: rel}); !errors.Is(err, resolve.ErrNotFound) {
				t.Errorf("%s: %v", rel, err)
			}
		}
	})
}

func sha256sum(b []byte) [32]byte { return sha256.Sum256(b) }

func TestUploadLongNames(t *testing.T) {
	drivers(t, func(t *testing.T, newDriver func(*testing.T) storage.Driver) {
		e := newStEnv(t, newDriver(t))
		name := "acme" + strings.Repeat("x", 152)
		version := "1:" + strings.Repeat("1", 150) + "-1"
		d, _, err := e.upload("bookworm", "main", name, version, "long")
		if err != nil {
			t.Fatal(err)
		}
		ms := e.members(t, "bookworm")
		if len(ms) != 1 || ms[0].Deb != d || len(d.Name) != 156 {
			t.Fatalf("members = %+v", ms)
		}
		if err := e.d.Delete(context.Background(), suitePrefix("hosted", "bookworm")+"index.json"); err != nil {
			t.Fatal(err)
		}
		if ms := e.members(t, "bookworm"); len(ms) != 1 || ms[0].Deb != d {
			t.Fatalf("rebuilt = %+v", ms)
		}
	})
}

// failRecords fails the first PutIfAbsent of a key with prefix, then works.
type failRecords struct {
	storage.Driver
	mu     sync.Mutex
	prefix string
	failed bool
}

func (d *failRecords) PutIfAbsent(ctx context.Context, key string, r io.Reader) (storage.Info, error) {
	d.mu.Lock()
	fail := !d.failed && strings.HasPrefix(key, d.prefix)
	d.failed = d.failed || fail
	d.mu.Unlock()
	if fail {
		return storage.Info{}, errors.New("records store down")
	}
	return d.Driver.PutIfAbsent(ctx, key, r)
}

// auditActions lists the actions of the audit records in rec, sorted.
func auditActions(t *testing.T, rec storage.Driver) []string {
	t.Helper()
	var actions []string
	for info, err := range rec.List(context.Background(), "audit/") {
		if err != nil {
			t.Fatal(err)
		}
		rc, _, err := rec.Get(context.Background(), info.Key)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(rc)
		rc.Close()
		for _, a := range []string{"upload", "suite-add"} {
			if bytes.Contains(b, []byte(`"action":"`+a+`"`)) {
				actions = append(actions, a)
			}
		}
	}
	slices.Sort(actions)
	return actions
}

func TestUploadRecordsSurviveRetry(t *testing.T) {
	for _, prefix := range []string{"provenance/", "audit/"} {
		t.Run(prefix, func(t *testing.T) {
			e := newStEnv(t, fsDriver(t))
			fr := &failRecords{Driver: e.rec, prefix: prefix}
			e.src = NewStorageSource("hosted", []string{"acme*"}, e.d, e.src.cache, records.New(fr), e.src.signer, e.src.log)
			if _, _, err := e.upload("bookworm", "main", "acme", "1.0", "one"); err == nil {
				t.Fatal("first upload succeeded although the records store failed")
			}
			if _, _, err := e.upload("bookworm", "main", "acme", "1.0", "one"); err != nil {
				t.Fatalf("retry: %v", err)
			}
			recs, err := records.New(e.rec).FileProvenance(context.Background(), ecoName, "acme", "1.0", "acme_1.0_all.deb")
			if err != nil || len(recs) == 0 {
				t.Errorf("provenance = %+v, %v", recs, err)
			}
			if got := auditActions(t, e.rec); !slices.Contains(got, "upload") || !slices.Contains(got, "suite-add") {
				t.Errorf("audit actions = %v", got)
			}
		})
	}
	// A suite-add audit that fails is written by the retry too.
	e := newStEnv(t, fsDriver(t))
	if _, _, err := e.upload("bookworm", "main", "acme", "1.0", "one"); err != nil {
		t.Fatal(err)
	}
	fr := &failRecords{Driver: e.rec, prefix: "audit/"}
	e.src = NewStorageSource("hosted", []string{"acme*"}, e.d, e.src.cache, records.New(fr), e.src.signer, e.src.log)
	if _, _, err := e.upload("trixie", "main", "acme", "1.0", "one"); err == nil {
		t.Fatal("suite add succeeded although the records store failed")
	}
	if _, _, err := e.upload("trixie", "main", "acme", "1.0", "one"); err != nil {
		t.Fatalf("retry: %v", err)
	}
	if got := auditActions(t, e.rec); !slices.Equal(got, []string{"suite-add", "suite-add", "upload"}) {
		t.Errorf("audit actions = %v", got)
	}
}

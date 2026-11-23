package npm

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

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

var publisher = identity.Caller{Login: "ci@example.com", NodeName: "ci", NodeStableID: "n1"}

type storeEnv struct {
	src  *StorageSource
	d    storage.Driver // the hosted store
	recD storage.Driver // the records' state store
	rec  *records.Store
	dir  string
}

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

func newStoreEnv(t *testing.T, d storage.Driver) *storeEnv {
	t.Helper()
	recD := fsDriver(t)
	rec := records.New(recD)
	dir := t.TempDir()
	src := NewStorageSource("hosted", []string{"@s/*", "pkg"}, d, rec, inspectLimits, 16<<20, dir, slog.New(slog.DiscardHandler))
	return &storeEnv{src: src, d: d, recD: recD, rec: rec, dir: dir}
}

func (e *storeEnv) publish(t testing.TB, name string, body []byte) (string, error) {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "body")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.Write(body); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	n, err := ParseName(name)
	if err != nil {
		t.Fatal(err)
	}
	return e.src.Publish(context.Background(), publisher, n, f, int64(len(body)))
}

func (e *storeEnv) mustPublish(t *testing.T, name string, body []byte) string {
	t.Helper()
	notice, err := e.publish(t, name, body)
	if err != nil {
		t.Fatalf("publish %s: %v", name, err)
	}
	return notice
}

type packumentDoc struct {
	Name     string                     `json:"name"`
	DistTags map[string]string          `json:"dist-tags"`
	Versions map[string]json.RawMessage `json:"versions"`
	Time     map[string]string          `json:"time"`
}

func (e *storeEnv) packument(t *testing.T, name string, corgi bool) packumentDoc {
	t.Helper()
	doc, err := e.src.Packument(context.Background(), mustName(t, name), corgi)
	if err != nil {
		t.Fatalf("packument %s: %v", name, err)
	}
	defer doc.Body.Close()
	b, err := io.ReadAll(doc.Body)
	if err != nil {
		t.Fatal(err)
	}
	if int64(len(b)) != doc.Size || bytes.Count(b, []byte(BaseToken)) != doc.Tokens {
		t.Errorf("doc size %d tokens %d, body has %d bytes and %d tokens", doc.Size, doc.Tokens, len(b), bytes.Count(b, []byte(BaseToken)))
	}
	if sum := sha256.Sum256(b); hex.EncodeToString(sum[:]) != doc.SHA256 {
		t.Errorf("doc SHA256 %s does not match its body", doc.SHA256)
	}
	var p packumentDoc
	if err := json.Unmarshal(bytes.ReplaceAll(b, []byte(BaseToken), []byte("https://h/npm/")), &p); err != nil {
		t.Fatalf("packument %s: %v\n%s", name, err, b)
	}
	return p
}

func (e *storeEnv) tags(t *testing.T, name string) map[string]string {
	t.Helper()
	tags, err := e.src.DistTags(context.Background(), mustName(t, name))
	if err != nil {
		t.Fatalf("dist-tags %s: %v", name, err)
	}
	return tags
}

func (e *storeEnv) audits(t *testing.T) []records.Audit {
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

func pkgKey(name, file string) string {
	return "npm/" + storage.EscapeSegment(name) + "/" + file
}

func withTag(tag, version string) bodyOpt {
	return withTop("dist-tags", fmt.Sprintf(`{%q:%q}`, tag, version))
}

func requestStatus(err error) int {
	if re, ok := errors.AsType[*RequestError](err); ok {
		return re.Status
	}
	return 0
}

func TestPublishAndRead(t *testing.T) {
	drivers(t, func(t *testing.T, d func(t *testing.T) storage.Driver) {
		e := newStoreEnv(t, d(t))
		ctx := context.Background()
		body := npmBody(t, withName("@s/a"))
		if notice := e.mustPublish(t, "@s/a", body); notice != "" {
			t.Errorf("notice %q", notice)
		}
		tgz := attachedTarball(t, body)
		for _, corgi := range []bool{false, true} {
			p := e.packument(t, "@s/a", corgi)
			if p.Name != "@s/a" || p.DistTags["latest"] != "1.0.0" || len(p.DistTags) != 1 {
				t.Errorf("corgi=%v: name %q dist-tags %v", corgi, p.Name, p.DistTags)
			}
			var v struct {
				Name string
				Dist struct{ Tarball, Integrity, Shasum string }
			}
			if err := json.Unmarshal(p.Versions["1.0.0"], &v); err != nil {
				t.Fatalf("corgi=%v: %v", corgi, err)
			}
			if v.Name != "@s/a" || v.Dist.Tarball != "https://h/npm/@s/a/-/a-1.0.0.tgz" || v.Dist.Integrity != sriSHA512(tgz) || v.Dist.Shasum != hexSHA1(tgz) {
				t.Errorf("corgi=%v: version %+v", corgi, v)
			}
			if p.Time["1.0.0"] == "" || p.Time["created"] != p.Time["1.0.0"] || p.Time["modified"] < p.Time["1.0.0"] {
				t.Errorf("corgi=%v: time %v", corgi, p.Time)
			}
		}
		obj, err := e.src.Version(ctx, mustName(t, "@s/a"), "latest")
		if err != nil || !bytes.Contains(obj, []byte(BaseToken+"@s/a/-/a-1.0.0.tgz")) {
			t.Errorf("Version(latest): %v %s", err, obj)
		}
		if _, err := e.src.Version(ctx, mustName(t, "@s/a"), "2.0.0"); !errors.Is(err, resolve.ErrNotFound) {
			t.Errorf("Version(2.0.0): %v", err)
		}
		got, err := readArtifact(e.src.Tarball(ctx, mustName(t, "@s/a"), "a-1.0.0.tgz"))
		if err != nil || !bytes.Equal(got, tgz) {
			t.Errorf("Tarball: %v, %d bytes", err, len(got))
		}
		if _, err := e.src.Tarball(ctx, mustName(t, "@s/a"), "a-1.0.1.tgz"); !errors.Is(err, resolve.ErrNotFound) {
			t.Errorf("Tarball of an unknown file: %v", err)
		}
		if _, err := e.src.Packument(ctx, mustName(t, "@s/b"), false); !errors.Is(err, resolve.ErrNotFound) {
			t.Errorf("Packument of an unknown name: %v", err)
		}
		sum := sha256.Sum256(tgz)
		prov, err := e.rec.GetProvenance(ctx, "npm", "@s/a", "1.0.0", hex.EncodeToString(sum[:]))
		if err != nil || prov.SourceType != "storage" || prov.Source != "hosted" || prov.Uploader == nil || prov.Uploader.Login != publisher.Login {
			t.Errorf("provenance: %+v %v", prov, err)
		}
		a := e.audits(t)
		if len(a) != 3 || a[0].Action != "publish" || a[0].Package != "@s/a" || a[0].Version != "1.0.0" || a[0].Uploader.Login != publisher.Login ||
			a[1].Action != "dist-tag" || a[1].Tag != "latest" || a[1].Version != "1.0.0" || a[1].Attempt == "" ||
			a[2].Action != "dist-tag-commit" || a[2].Package != "@s/a" || a[2].Attempt != a[1].Attempt {
			t.Errorf("audit: %+v", a)
		}
	})
}

// keyRecorder records every key written.
type keyRecorder struct {
	storage.Driver
	mu   sync.Mutex
	keys []string
}

func (k *keyRecorder) note(key string) {
	k.mu.Lock()
	k.keys = append(k.keys, key)
	k.mu.Unlock()
}

func (k *keyRecorder) PutIfAbsent(ctx context.Context, key string, r io.Reader) (storage.Info, error) {
	k.note(key)
	return k.Driver.PutIfAbsent(ctx, key, r)
}

func (k *keyRecorder) PutIfMatch(ctx context.Context, key string, r io.Reader, etag string) (storage.Info, error) {
	k.note(key)
	return k.Driver.PutIfMatch(ctx, key, r, etag)
}

func (k *keyRecorder) Put(ctx context.Context, key string, r io.Reader) (storage.Info, error) {
	k.note(key)
	return k.Driver.Put(ctx, key, r)
}

func TestKeysEscaped(t *testing.T) {
	kr := &keyRecorder{Driver: fsDriver(t)}
	e := newStoreEnv(t, kr)
	e.mustPublish(t, "@s/a", npmBody(t, withName("@s/a"), withVersion("1.0.0-Beta")))
	e.mustPublish(t, "@s/a", npmBody(t, withName("@s/a"), withVersion("1.0.0-beta")))
	dirs := map[string]bool{}
	for _, k := range kr.keys {
		if err := storage.ValidKey(k); err != nil {
			t.Errorf("key %q: %v", k, err)
		}
		if strings.HasSuffix(k, "/package.tgz") {
			dirs[k] = true
		}
	}
	if len(dirs) != 2 {
		t.Errorf("tarball keys %v, want two", dirs)
	}
	p := e.packument(t, "@s/a", false)
	if len(p.Versions) != 2 || p.Versions["1.0.0-Beta"] == nil || p.Versions["1.0.0-beta"] == nil {
		t.Errorf("versions %v", p.Versions)
	}
}

func TestRepublishSameBytes(t *testing.T) {
	e := newStoreEnv(t, fsDriver(t))
	body := npmBody(t)
	e.mustPublish(t, "pkg", body)
	e.mustPublish(t, "pkg", body)
	_, err := e.publish(t, "pkg", npmBody(t, withFile("index.js", "module.exports = 2\n")))
	if !errors.Is(err, ErrVersionExists) {
		t.Errorf("different bytes: %v", err)
	}
	if p := e.packument(t, "pkg", false); len(p.Versions) != 1 {
		t.Errorf("versions %v", p.Versions)
	}
	entries, err := os.ReadDir(e.dir)
	if err != nil || len(entries) != 0 {
		t.Errorf("temp files left: %v %v", entries, err)
	}
}

func TestBuildMetadataConflict(t *testing.T) {
	e := newStoreEnv(t, fsDriver(t))
	e.mustPublish(t, "pkg", npmBody(t, withVersion("1.0.0+a")))
	if _, err := e.publish(t, "pkg", npmBody(t, withVersion("1.0.0+b"))); !errors.Is(err, ErrVersionExists) {
		t.Errorf("1.0.0+b after 1.0.0+a: %v", err)
	}
	if p := e.packument(t, "pkg", false); len(p.Versions) != 1 || p.Versions["1.0.0+a"] == nil {
		t.Errorf("versions %v", p.Versions)
	}
}

// failTagsOnce fails the first write of a dist-tags document.
type failTagsOnce struct {
	storage.Driver
	mu     sync.Mutex
	failed bool
}

func (f *failTagsOnce) PutIfMatch(ctx context.Context, key string, r io.Reader, etag string) (storage.Info, error) {
	f.mu.Lock()
	fail := !f.failed && strings.HasSuffix(key, "/dist-tags.json")
	f.failed = f.failed || fail
	f.mu.Unlock()
	if fail {
		return storage.Info{}, errors.New("injected failure")
	}
	return f.Driver.PutIfMatch(ctx, key, r, etag)
}

func TestResumeAfterTagFailure(t *testing.T) {
	e := newStoreEnv(t, &failTagsOnce{Driver: fsDriver(t)})
	body := npmBody(t, withTag("beta", "1.0.0"))
	if _, err := e.publish(t, "pkg", body); err == nil {
		t.Fatal("publish with a failing dist-tags write succeeded")
	}
	// The retry sends the latest tag; the tag recorded in the sidecar wins.
	retry := bytes.Replace(body, []byte(`"dist-tags":{"beta"`), []byte(`"dist-tags":{"latest"`), 1)
	e.mustPublish(t, "pkg", retry)
	if tags := e.tags(t, "pkg"); tags["latest"] != "1.0.0" || tags["beta"] != "1.0.0" || len(tags) != 2 {
		t.Errorf("dist-tags %v", tags)
	}
	if _, _, err := e.d.Get(context.Background(), pkgKey("pkg", "dist-tags.json")); err != nil {
		t.Errorf("dist-tags.json: %v", err)
	}
}

func TestLatestRules(t *testing.T) {
	e := newStoreEnv(t, fsDriver(t))
	e.mustPublish(t, "@s/a", npmBody(t, withName("@s/a"), withVersion("2.0.0")))
	notice := e.mustPublish(t, "@s/a", npmBody(t, withName("@s/a"), withVersion("1.5.0")))
	if notice != "latest stayed at 2.0.0" {
		t.Errorf("notice %q", notice)
	}
	if tags := e.tags(t, "@s/a"); tags["latest"] != "2.0.0" || len(tags) != 1 {
		t.Errorf("after 1.5.0: %v", tags)
	}

	e.mustPublish(t, "@s/b", npmBody(t, withName("@s/b"), withTag("beta", "1.0.0")))
	if tags := e.tags(t, "@s/b"); tags["latest"] != "1.0.0" || tags["beta"] != "1.0.0" || len(tags) != 2 {
		t.Errorf("first version under beta: %v", tags)
	}

	e.mustPublish(t, "@s/a", npmBody(t, withName("@s/a"), withVersion("3.0.0-rc.1")))
	if tags := e.tags(t, "@s/a"); tags["latest"] != "3.0.0-rc.1" {
		t.Errorf("after 3.0.0-rc.1: %v", tags)
	}
	if err := e.d.Delete(context.Background(), pkgKey("@s/a", "dist-tags.json")); err != nil {
		t.Fatal(err)
	}
	if tags := e.tags(t, "@s/a"); tags["latest"] != "2.0.0" || len(tags) != 1 {
		t.Errorf("fallback: %v", tags)
	}
}

func TestConcurrentPublishSameVersion(t *testing.T) {
	const n = 8
	t.Run("same bytes", func(t *testing.T) {
		e := newStoreEnv(t, fsDriver(t))
		body := npmBody(t)
		errs := make([]error, n)
		var wg sync.WaitGroup
		for i := range n {
			wg.Go(func() { _, errs[i] = e.publish(t, "pkg", body) })
		}
		wg.Wait()
		for i, err := range errs {
			if err != nil {
				t.Errorf("publish %d: %v", i, err)
			}
		}
		if p := e.packument(t, "pkg", false); len(p.Versions) != 1 || p.DistTags["latest"] != "1.0.0" {
			t.Errorf("versions %v dist-tags %v", p.Versions, p.DistTags)
		}
	})
	t.Run("different bytes", func(t *testing.T) {
		e := newStoreEnv(t, fsDriver(t))
		bodies := make([][]byte, n)
		for i := range n {
			bodies[i] = npmBody(t, withFile("index.js", fmt.Sprintf("module.exports = %d\n", i)))
		}
		errs := make([]error, n)
		var wg sync.WaitGroup
		for i := range n {
			wg.Go(func() { _, errs[i] = e.publish(t, "pkg", bodies[i]) })
		}
		wg.Wait()
		ok := 0
		for i, err := range errs {
			switch {
			case err == nil:
				ok++
			case !errors.Is(err, ErrVersionExists):
				t.Errorf("publish %d: %v", i, err)
			}
		}
		if ok != 1 {
			t.Errorf("%d publishes succeeded, want 1", ok)
		}
	})
}

func TestConcurrentPublishTwoVersions(t *testing.T) {
	drivers(t, func(t *testing.T, d func(t *testing.T) storage.Driver) {
		b1, b2 := npmBody(t, withVersion("1.0.0")), npmBody(t, withVersion("1.1.0"))
		for i := range 50 {
			e := newStoreEnv(t, d(t))
			var wg sync.WaitGroup
			var err1, err2 error
			wg.Go(func() { _, err1 = e.publish(t, "pkg", b1) })
			wg.Go(func() { _, err2 = e.publish(t, "pkg", b2) })
			wg.Wait()
			if err1 != nil || err2 != nil {
				t.Fatalf("run %d: %v, %v", i, err1, err2)
			}
			p := e.packument(t, "pkg", false)
			if len(p.Versions) != 2 || p.DistTags["latest"] != "1.1.0" {
				t.Fatalf("run %d: versions %d dist-tags %v", i, len(p.Versions), p.DistTags)
			}
		}
	})
}

func TestDistTagMoves(t *testing.T) {
	e := newStoreEnv(t, fsDriver(t))
	ctx := context.Background()
	n := mustName(t, "pkg")
	e.mustPublish(t, "pkg", npmBody(t, withVersion("1.0.0")))
	e.mustPublish(t, "pkg", npmBody(t, withVersion("1.1.0")))
	e.packument(t, "pkg", false) // cached

	if err := e.src.SetTag(ctx, publisher, n, "beta", "1.0.0"); err != nil {
		t.Fatal(err)
	}
	if err := e.src.SetTag(ctx, publisher, n, "beta", "1.1.0"); err != nil {
		t.Fatal(err)
	}
	var moves []records.Audit
	for _, a := range e.audits(t) {
		if a.Action == "dist-tag" && a.Tag == "beta" {
			moves = append(moves, a)
		}
	}
	if len(moves) != 2 || moves[0].Tag != "beta" || moves[0].Version != "1.0.0" || moves[0].Previous != "" ||
		moves[1].Version != "1.1.0" || moves[1].Previous != "1.0.0" || moves[1].Uploader.Login != publisher.Login {
		t.Errorf("dist-tag audits %+v", moves)
	}
	if p := e.packument(t, "pkg", false); p.DistTags["beta"] != "1.1.0" {
		t.Errorf("packument dist-tags %v", p.DistTags)
	}
	if obj, err := e.src.Version(ctx, n, "beta"); err != nil || !bytes.Contains(obj, []byte(`"version":"1.1.0"`)) {
		t.Errorf("Version(beta): %v %s", err, obj)
	}

	for _, tc := range []struct {
		what   string
		err    error
		status int
	}{
		{"absent version", e.src.SetTag(ctx, publisher, n, "beta", "9.9.9"), 400},
		{"invalid tag", e.src.SetTag(ctx, publisher, n, "1.x", "1.0.0"), 400},
		{"remove latest", e.src.RemoveTag(ctx, publisher, n, "latest"), 400},
	} {
		if s := requestStatus(tc.err); s != tc.status {
			t.Errorf("%s: %v, want %d", tc.what, tc.err, tc.status)
		}
	}
	if err := e.src.RemoveTag(ctx, publisher, n, "nope"); !errors.Is(err, resolve.ErrNotFound) {
		t.Errorf("remove absent tag: %v", err)
	}
	if err := e.src.RemoveTag(ctx, publisher, n, "beta"); err != nil {
		t.Errorf("remove beta: %v", err)
	}
	if tags := e.tags(t, "pkg"); len(tags) != 1 {
		t.Errorf("after remove: %v", tags)
	}

	for i := range 99 {
		if err := e.src.SetTag(ctx, publisher, n, fmt.Sprintf("t%d", i), "1.0.0"); err != nil {
			t.Fatalf("tag %d: %v", i, err)
		}
	}
	if err := e.src.SetTag(ctx, publisher, n, "t99", "1.0.0"); requestStatus(err) != 400 {
		t.Errorf("101st tag: %v", err)
	}
	if err := e.src.SetTag(ctx, publisher, n, "t0", "1.1.0"); err != nil {
		t.Errorf("moving an existing tag at the limit: %v", err)
	}
	if _, err := e.publish(t, "pkg", npmBody(t, withVersion("1.2.0"), withTag("next", "1.2.0"))); requestStatus(err) != 400 {
		t.Errorf("publish adding a 101st tag: %v", err)
	}
}

func TestIndexRebuild(t *testing.T) {
	e := newStoreEnv(t, fsDriver(t))
	ctx := context.Background()
	n := mustName(t, "pkg")
	body := npmBody(t, withVersion("1.0.0"))
	e.mustPublish(t, "pkg", body)
	e.mustPublish(t, "pkg", npmBody(t, withVersion("1.1.0")))
	if err := e.src.SetTag(ctx, publisher, n, "beta", "1.0.0"); err != nil {
		t.Fatal(err)
	}
	e.packument(t, "pkg", false)

	if err := e.d.Delete(ctx, pkgKey("pkg", "index.json")); err != nil {
		t.Fatal(err)
	}
	p := e.packument(t, "pkg", false)
	if len(p.Versions) != 2 || p.DistTags["beta"] != "1.0.0" || p.DistTags["latest"] != "1.1.0" {
		t.Errorf("after losing the index: versions %d dist-tags %v", len(p.Versions), p.DistTags)
	}
	if got, err := readArtifact(e.src.Tarball(ctx, n, "pkg-1.0.0.tgz")); err != nil || !bytes.Equal(got, attachedTarball(t, body)) {
		t.Errorf("Tarball after losing the index: %v", err)
	}
	for _, h := range e.src.Health(ctx) {
		if !h.OK {
			t.Errorf("health with intact dist-tags: %+v", h)
		}
	}

	if _, err := e.d.Put(ctx, pkgKey("pkg", "dist-tags.json"), strings.NewReader("{garbage")); err != nil {
		t.Fatal(err)
	}
	if tags := e.tags(t, "pkg"); tags["latest"] != "1.1.0" || len(tags) != 1 {
		t.Errorf("fallback: %v", tags)
	}
	var bad int
	for _, h := range e.src.Health(ctx) {
		if !h.OK {
			bad++
			if !h.Scoped || len(h.Packages) != 1 || h.Packages[0] != "pkg" {
				t.Errorf("health row %+v", h)
			}
		}
	}
	if bad != 1 {
		t.Errorf("%d failing health rows, want 1", bad)
	}
	if rc, _, err := e.d.Get(ctx, pkgKey("pkg", "dist-tags.json")); err != nil {
		t.Fatal(err)
	} else if b, _ := io.ReadAll(rc); rc.Close() == nil && string(b) != "{garbage" {
		t.Errorf("dist-tags.json was rewritten by a read: %s", b)
	}
}

func TestConcurrentPublishSamePrecedence(t *testing.T) {
	drivers(t, func(t *testing.T, d func(t *testing.T) storage.Driver) {
		ba, bb := npmBody(t, withVersion("1.0.0+a")), npmBody(t, withVersion("1.0.0+b"))
		b2 := npmBody(t, withVersion("2.0.0"))
		ctx := context.Background()
		for i := range 50 {
			e := newStoreEnv(t, d(t))
			var wg sync.WaitGroup
			var errA, errB error
			wg.Go(func() { _, errA = e.publish(t, "pkg", ba) })
			wg.Go(func() { _, errB = e.publish(t, "pkg", bb) })
			wg.Wait()
			if (errA == nil) == (errB == nil) || !errors.Is(errA, ErrVersionExists) && !errors.Is(errB, ErrVersionExists) {
				t.Fatalf("run %d: %v, %v; want one success and one ErrVersionExists", i, errA, errB)
			}
			winner := "1.0.0+a"
			if errA != nil {
				winner = "1.0.0+b"
			}
			if err := e.d.Delete(ctx, pkgKey("pkg", "index.json")); err != nil {
				t.Fatal(err)
			}
			e.mustPublish(t, "pkg", b2)
			p := e.packument(t, "pkg", false)
			if len(p.Versions) != 2 || p.Versions[winner] == nil || p.Versions["2.0.0"] == nil {
				t.Fatalf("run %d: winner %s, versions %d", i, winner, len(p.Versions))
			}
			var published []string
			for _, a := range e.audits(t) {
				if a.Action == "publish" {
					published = append(published, a.Version)
				}
			}
			if len(published) != 2 {
				t.Fatalf("run %d: publish audits %v, want the winner and 2.0.0", i, published)
			}
		}
	})
}

func TestRepublishKeepsMovedTag(t *testing.T) {
	e := newStoreEnv(t, fsDriver(t))
	body := npmBody(t, withVersion("1.0.0"), withTag("beta", "1.0.0"))
	e.mustPublish(t, "pkg", body)
	e.mustPublish(t, "pkg", npmBody(t, withVersion("1.1.0")))
	if err := e.src.SetTag(context.Background(), publisher, mustName(t, "pkg"), "beta", "1.1.0"); err != nil {
		t.Fatal(err)
	}
	e.mustPublish(t, "pkg", body)
	if tags := e.tags(t, "pkg"); tags["beta"] != "1.1.0" || tags["latest"] != "1.1.0" {
		t.Errorf("after republishing 1.0.0: %v", tags)
	}
}

func TestPublishTagAudits(t *testing.T) {
	e := newStoreEnv(t, fsDriver(t))
	e.mustPublish(t, "pkg", npmBody(t, withVersion("1.0.0"), withTag("beta", "1.0.0")))
	e.mustPublish(t, "pkg", npmBody(t, withVersion("1.1.0")))
	got := map[string]records.Audit{}
	var n int
	for _, a := range e.audits(t) {
		if a.Action == "dist-tag" {
			n++
			got[a.Tag+"@"+a.Version] = a
		}
	}
	want := map[string]string{"latest@1.0.0": "", "beta@1.0.0": "", "latest@1.1.0": "1.0.0"}
	if n != len(want) {
		t.Errorf("%d dist-tag audits, want %d: %v", n, len(want), got)
	}
	for k, prev := range want {
		if a, ok := got[k]; !ok || a.Previous != prev || a.Uploader.Login != publisher.Login {
			t.Errorf("audit %s: %+v, want Previous %q", k, a, prev)
		}
	}
}

// failAudits fails every audit record write.
type failAudits struct{ storage.Driver }

func (f failAudits) PutIfAbsent(ctx context.Context, key string, r io.Reader) (storage.Info, error) {
	if strings.HasPrefix(key, "audit/") {
		return storage.Info{}, errors.New("injected audit failure")
	}
	return f.Driver.PutIfAbsent(ctx, key, r)
}

// loseTagRace fails the first If-Match write of a dist-tags document, as
// when another writer got there first.
type loseTagRace struct {
	storage.Driver
	lost atomic.Bool
}

func (l *loseTagRace) PutIfMatch(ctx context.Context, key string, r io.Reader, etag string) (storage.Info, error) {
	if strings.HasSuffix(key, "/dist-tags.json") && l.lost.CompareAndSwap(false, true) {
		return storage.Info{}, storage.ErrPrecondition
	}
	return l.Driver.PutIfMatch(ctx, key, r, etag)
}

// TestTagAuditAttempts: the dist-tag records of an attempt that lost its
// write stay pending; only the attempt that stuck has a dist-tag-commit.
func TestTagAuditAttempts(t *testing.T) {
	e := newStoreEnv(t, fsDriver(t))
	n := mustName(t, "pkg")
	e.mustPublish(t, "pkg", npmBody(t, withVersion("1.0.0")))
	race := &loseTagRace{Driver: e.d}
	e.src.d = race
	if err := e.src.SetTag(context.Background(), publisher, n, "beta", "1.0.0"); err != nil {
		t.Fatal(err)
	}
	if !race.lost.Load() {
		t.Fatal("no write was lost")
	}
	committed := map[string]bool{}
	var moves []records.Audit
	for _, a := range e.audits(t) {
		switch {
		case a.Action == "dist-tag-commit":
			committed[a.Attempt] = true
		case a.Action == "dist-tag" && a.Tag == "beta":
			moves = append(moves, a)
		}
	}
	if len(moves) != 2 || moves[0].Attempt == moves[1].Attempt {
		t.Fatalf("beta records %+v, want one per attempt", moves)
	}
	var applied int
	for _, m := range moves {
		if committed[m.Attempt] {
			applied++
		}
	}
	if applied != 1 {
		t.Errorf("%d committed beta records, want 1 (commits %v)", applied, committed)
	}
}

func TestSetTagAuditFailure(t *testing.T) {
	e := newStoreEnv(t, fsDriver(t))
	n := mustName(t, "pkg")
	e.mustPublish(t, "pkg", npmBody(t, withVersion("1.0.0")))
	e.mustPublish(t, "pkg", npmBody(t, withVersion("1.1.0")))
	e.src.rec = records.New(failAudits{e.recD})
	if err := e.src.SetTag(context.Background(), publisher, n, "beta", "1.0.0"); err == nil {
		t.Fatal("SetTag succeeded without its audit record")
	}
	if err := e.src.RemoveTag(context.Background(), publisher, n, "beta"); !errors.Is(err, resolve.ErrNotFound) {
		t.Errorf("RemoveTag after the failed SetTag: %v", err)
	}
	if tags := e.tags(t, "pkg"); len(tags) != 1 || tags["latest"] != "1.1.0" {
		t.Errorf("dist-tags %v", tags)
	}
}

func TestPackumentOverCap(t *testing.T) {
	e := newStoreEnv(t, fsDriver(t))
	ctx := context.Background()
	n := mustName(t, "pkg")
	e.mustPublish(t, "pkg", npmBody(t, withVersion("1.0.0")))
	e.src.maxDoc = 64
	for _, corgi := range []bool{false, true} {
		_, err := e.src.Packument(ctx, n, corgi)
		if err == nil || errors.Is(err, resolve.ErrNotFound) || resolve.HTTPStatus(err) != 500 {
			t.Errorf("corgi=%v over the cap: %v (status %d)", corgi, err, resolve.HTTPStatus(err))
		}
	}
	if _, err := e.src.Tarball(ctx, n, "pkg-1.0.0.tgz"); err == nil || errors.Is(err, resolve.ErrNotFound) {
		t.Errorf("Tarball over the cap: %v", err)
	}
	e.src.mu.Lock()
	cached := len(e.src.docs)
	e.src.mu.Unlock()
	if cached != 0 {
		t.Errorf("%d documents cached over the cap", cached)
	}
	var rows []string
	for _, h := range e.src.Health(ctx) {
		if !h.OK {
			if !h.Scoped || len(h.Packages) != 1 || h.Packages[0] != "pkg" || !strings.Contains(h.Detail, "64 bytes") {
				t.Errorf("health row %+v", h)
			}
			rows = append(rows, h.Detail)
		}
	}
	if len(rows) != 1 {
		t.Errorf("failing health rows %q, want 1", rows)
	}

	e.src.maxDoc = maxStorageDocBytes
	e.packument(t, "pkg", false)
	for _, h := range e.src.Health(ctx) {
		if !h.OK {
			t.Errorf("health after a render under the cap: %+v", h)
		}
	}
}

func TestConcurrentReadsRenderOnce(t *testing.T) {
	drivers(t, func(t *testing.T, d func(t *testing.T) storage.Driver) {
		e := newStoreEnv(t, d(t))
		e.mustPublish(t, "pkg", npmBody(t, withVersion("1.0.0")))
		e.packument(t, "pkg", false)
		e.mustPublish(t, "pkg", npmBody(t, withVersion("1.1.0")))
		var renders atomic.Int32
		release := make(chan struct{})
		e.src.onRender = func() {
			renders.Add(1)
			<-release
		}
		const readers = 16
		var wg sync.WaitGroup
		var started sync.WaitGroup
		started.Add(readers)
		errs := make([]error, readers)
		for i := range readers {
			wg.Go(func() {
				started.Done()
				_, errs[i] = e.src.Packument(context.Background(), mustName(t, "pkg"), i%2 == 0)
			})
		}
		started.Wait()
		time.Sleep(100 * time.Millisecond) // let every reader reach the render
		close(release)
		wg.Wait()
		for i, err := range errs {
			if err != nil {
				t.Errorf("reader %d: %v", i, err)
			}
		}
		if got := renders.Load(); got != 1 {
			t.Errorf("%d renders for %d concurrent readers, want 1", got, readers)
		}
		if p := e.packument(t, "pkg", false); len(p.Versions) != 2 {
			t.Errorf("versions %d after the shared render", len(p.Versions))
		}
	})
}

func TestMixedCaseMisses(t *testing.T) {
	drivers(t, func(t *testing.T, d func(t *testing.T) storage.Driver) {
		e := newStoreEnv(t, d(t))
		ctx := context.Background()
		e.mustPublish(t, "@s/x", npmBody(t, withName("@s/x")))
		e.packument(t, "@s/x", false)
		n := mustName(t, "@S/x")
		if _, err := e.src.Packument(ctx, n, false); !errors.Is(err, resolve.ErrNotFound) {
			t.Errorf("Packument(@S/x): %v", err)
		}
		if _, err := e.src.Packument(ctx, n, true); !errors.Is(err, resolve.ErrNotFound) {
			t.Errorf("corgi Packument(@S/x): %v", err)
		}
		if _, err := e.src.Version(ctx, n, "1.0.0"); !errors.Is(err, resolve.ErrNotFound) {
			t.Errorf("Version(@S/x): %v", err)
		}
		if _, err := e.src.DistTags(ctx, n); !errors.Is(err, resolve.ErrNotFound) {
			t.Errorf("DistTags(@S/x): %v", err)
		}
		if _, err := e.src.Tarball(ctx, n, "x-1.0.0.tgz"); !errors.Is(err, resolve.ErrNotFound) {
			t.Errorf("Tarball(@S/x): %v", err)
		}
		if err := e.src.SetTag(ctx, publisher, n, "beta", "1.0.0"); !errors.Is(err, resolve.ErrNotFound) {
			t.Errorf("SetTag(@S/x): %v", err)
		}
		if err := e.src.RemoveTag(ctx, publisher, n, "beta"); !errors.Is(err, resolve.ErrNotFound) {
			t.Errorf("RemoveTag(@S/x): %v", err)
		}
		if tags := e.tags(t, "@s/x"); len(tags) != 1 || tags["latest"] != "1.0.0" {
			t.Errorf("dist-tags of @s/x: %v", tags)
		}
	})
}

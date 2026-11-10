package storage

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/radiergummi/tspackages/internal/config"
)

func testS3Config(t *testing.T) config.StoreConfig {
	endpoint := os.Getenv("TSP_TEST_S3_ENDPOINT")
	if endpoint == "" {
		t.Skip("TSP_TEST_S3_ENDPOINT not set")
	}
	getenv := func(k, def string) string {
		if v := os.Getenv(k); v != "" {
			return v
		}
		return def
	}
	return config.StoreConfig{
		Driver:          "s3",
		Endpoint:        endpoint,
		Bucket:          fmt.Sprintf("tsp-test-%d", time.Now().UnixNano()),
		Prefix:          "pfx",
		AccessKeyID:     getenv("TSP_TEST_S3_ACCESS_KEY", "minioadmin"),
		SecretAccessKey: getenv("TSP_TEST_S3_SECRET_KEY", "minioadmin"),
	}
}

func TestS3(t *testing.T) {
	ctx := context.Background()
	cfg := testS3Config(t)
	d, err := NewS3(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.(*s3Driver).client.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: &cfg.Bucket}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		c := d.(*s3Driver).client
		pager := s3.NewListObjectsV2Paginator(c, &s3.ListObjectsV2Input{Bucket: &cfg.Bucket})
		for pager.HasMorePages() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				t.Logf("cleanup list: %v", err)
				return
			}
			for _, o := range page.Contents {
				c.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: &cfg.Bucket, Key: o.Key})
			}
		}
		if _, err := c.DeleteBucket(ctx, &s3.DeleteBucketInput{Bucket: &cfg.Bucket}); err != nil {
			t.Logf("cleanup bucket: %v", err)
		}
	})
	runDriverSuite(t, d)
}

func TestS3MissingBucket(t *testing.T) {
	ctx := context.Background()
	cfg := testS3Config(t)
	cfg.Bucket = strings.Replace(cfg.Bucket, "tsp-test", "tsp-absent", 1)
	d, err := NewS3(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := d.Get(ctx, "k"); err == nil || errors.Is(err, ErrNotFound) {
		t.Errorf("Get: %v", err)
	}
	if _, err := d.Stat(ctx, "k"); err == nil || errors.Is(err, ErrNotFound) {
		t.Errorf("Stat: %v", err)
	}
	if _, err := d.PutIfMatch(ctx, "k", strings.NewReader("x"), "abc"); err == nil || errors.Is(err, ErrPrecondition) {
		t.Errorf("PutIfMatch: %v", err)
	}
}

// fakeS3 answers PUTs with the scripted statuses in order (200 once they run
// out) and HEADs with head.
type fakeS3 struct {
	mu   sync.Mutex
	puts []int
	head int
	seen []string // "PUT If-None-Match If-Match" per PUT
}

func (f *fakeS3) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	switch r.Method {
	case http.MethodHead:
		w.WriteHeader(f.head)
	case http.MethodPut:
		f.seen = append(f.seen, r.Header.Get("If-None-Match")+"|"+r.Header.Get("If-Match"))
		code := http.StatusOK
		if len(f.puts) > 0 {
			code, f.puts = f.puts[0], f.puts[1:]
		}
		if code == http.StatusOK {
			w.Header().Set("ETag", `"e1"`)
			return
		}
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(code)
		fmt.Fprintf(w, `<Error><Code>Code%d</Code><Message>m</Message></Error>`, code)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func fakeDriver(t *testing.T, f *fakeS3) Driver {
	t.Helper()
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	d, err := NewS3(context.Background(), config.StoreConfig{Driver: "s3", Bucket: "b", Endpoint: srv.URL, AccessKeyID: "k", SecretAccessKey: "s"})
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// AWS answers 409 ConditionalRequestConflict when conditional writes race.
// It is retried, and a conflict that persists maps to the error a caller of
// each conditional write expects.
func TestS3ConditionalConflicts(t *testing.T) {
	ctx := context.Background()
	body := func() io.Reader { return strings.NewReader("x") }
	const conflict = http.StatusConflict
	always := func() []int { return []int{conflict, conflict, conflict, conflict, conflict} }

	f := &fakeS3{puts: []int{conflict, conflict}}
	if info, err := fakeDriver(t, f).Put(ctx, "k", body()); err != nil || info.ETag != "e1" || len(f.seen) != 3 {
		t.Fatalf("Put after two conflicts: %+v %v, %d attempts", info, err, len(f.seen))
	}

	f = &fakeS3{puts: always(), head: http.StatusOK}
	if _, err := fakeDriver(t, f).PutIfAbsent(ctx, "k", body()); !errors.Is(err, ErrExists) || len(f.seen) != 5 {
		t.Fatalf("PutIfAbsent, conflicts and the key exists: %v, %d attempts", err, len(f.seen))
	}
	f = &fakeS3{puts: always(), head: http.StatusNotFound}
	if _, err := fakeDriver(t, f).PutIfAbsent(ctx, "k", body()); err == nil || errors.Is(err, ErrExists) {
		t.Fatalf("PutIfAbsent, conflicts and no key: %v", err)
	}

	f = &fakeS3{puts: always()}
	if _, err := fakeDriver(t, f).PutIfMatch(ctx, "k", body(), "e0"); !errors.Is(err, ErrPrecondition) {
		t.Fatalf("PutIfMatch, conflicts: %v", err)
	}
	if f.seen[0] != `|"e0"` {
		t.Fatalf("PutIfMatch sent %q", f.seen[0])
	}
	f = &fakeS3{puts: []int{http.StatusPreconditionFailed}}
	if _, err := fakeDriver(t, f).PutIfMatch(ctx, "k", body(), "e0"); !errors.Is(err, ErrPrecondition) || len(f.seen) != 1 {
		t.Fatalf("PutIfMatch, 412: %v, %d attempts", err, len(f.seen))
	}

	f = &fakeS3{puts: []int{conflict}}
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := fakeDriver(t, f).Put(cctx, "k", body()); err == nil {
		t.Fatal("Put with a cancelled context succeeded")
	}
}

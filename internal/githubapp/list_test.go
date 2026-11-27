package githubapp

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/radiergummi/tspackages/internal/upstream"
)

func TestRepositoriesPaginates(t *testing.T) {
	clk := newClock()
	var f *fakeAPI
	f = newFakeAPI(t, clk, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/installation/repositories" {
			t.Errorf("path = %s", r.URL.Path)
		}
		if r.Header.Get("Accept") != "application/vnd.github+json" || r.Header.Get("X-Github-Api-Version") != "2022-11-28" {
			t.Errorf("headers = %v", r.Header)
		}
		if r.URL.Query().Get("page") == "2" {
			_, _ = w.Write([]byte(`{"total_count":2,"repositories":[{"id":2,"full_name":"o/b"}]}`))
			return
		}
		w.Header().Set("Link", `<`+f.URL+`/installation/repositories?per_page=100&page=2>; rel="next", <`+f.URL+`/x>; rel="last"`)
		_, _ = w.Write([]byte(`{"total_count":2,"repositories":[{"id":1,"full_name":"o/a"}]}`))
	})
	repos, err := f.app(t, clk).Repositories(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(repos) != 2 || repos[0].FullName != "o/a" || repos[1].ID != 2 {
		t.Fatalf("repos = %+v", repos)
	}
}

func TestRepositoriesRejectsForeignNextLink(t *testing.T) {
	clk := newClock()
	f := newFakeAPI(t, clk, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Link", `<https://evil.example/x>; rel="next"`)
		_, _ = w.Write([]byte(`{"repositories":[]}`))
	})
	if _, err := f.app(t, clk).Repositories(t.Context()); err == nil {
		t.Fatal("want error")
	}
}

func TestReleasesConditional(t *testing.T) {
	clk := newClock()
	var calls atomic.Int32
	var gotINM atomic.Value
	f := newFakeAPI(t, clk, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/repos/o/r/releases" || r.URL.Query().Get("per_page") != "100" {
			t.Errorf("url = %s", r.URL)
		}
		if calls.Add(1) == 1 {
			w.Header().Set("ETag", `W/"abc"`)
			_, _ = w.Write([]byte(`[{"id":9,"tag_name":"v1.0.0","draft":true,"prerelease":true,"created_at":"2026-01-02T03:04:05Z",
"assets":[{"id":5,"name":"a-1.0.0.tar.gz","state":"uploaded","digest":"sha256:` + strings.Repeat("a", 64) + `","size":12,"created_at":"2026-01-02T03:04:05Z","updated_at":"2026-01-02T03:04:06Z"},
{"id":6,"name":"old.whl","state":"uploaded","digest":null,"size":1,"created_at":"2026-01-02T03:04:05Z","updated_at":"2026-01-02T03:04:06Z"}]}]`))
			return
		}
		gotINM.Store(r.Header.Get("If-None-Match"))
		w.WriteHeader(http.StatusNotModified)
	})
	a := f.app(t, clk)
	r1, err := a.Releases(t.Context(), Repo{ID: 1, FullName: "o/r"})
	if err != nil {
		t.Fatal(err)
	}
	if len(r1) != 1 || r1[0].Tag != "v1.0.0" || !r1[0].Draft || !r1[0].Prerelease || len(r1[0].Assets) != 2 {
		t.Fatalf("r1 = %+v", r1)
	}
	if as := r1[0].Assets; as[0].Digest != "sha256:"+strings.Repeat("a", 64) || as[1].Digest != "" || as[0].Size != 12 || as[0].State != "uploaded" || as[0].UpdatedAt.IsZero() {
		t.Fatalf("assets = %+v", as)
	}
	r2, err := a.Releases(t.Context(), Repo{ID: 1, FullName: "o/r"})
	if err != nil {
		t.Fatal(err)
	}
	if gotINM.Load() != `W/"abc"` || len(r2) != 1 || r2[0].ID != 9 {
		t.Fatalf("inm = %v, r2 = %+v", gotINM.Load(), r2)
	}
}

func TestRateLimited(t *testing.T) {
	clk := newClock()
	reset := clk.now().Add(30 * time.Minute)
	for _, code := range []int{http.StatusForbidden, http.StatusTooManyRequests} {
		f := newFakeAPI(t, clk, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Ratelimit-Remaining", "0")
			w.Header().Set("X-Ratelimit-Reset", strconv.FormatInt(reset.Unix(), 10))
			w.WriteHeader(code)
		})
		a := f.app(t, clk)
		_, err := a.Releases(t.Context(), Repo{FullName: "o/r"})
		rl, ok := errors.AsType[*RateLimitError](err)
		if !ok || !rl.Reset.Equal(reset) || !errors.Is(err, ErrRateLimited) {
			t.Fatalf("%d: err = %v", code, err)
		}
		if rem, rs := a.RateLimit(); rem != 0 || !rs.Equal(reset) {
			t.Errorf("%d: RateLimit = %d, %v", code, rem, rs)
		}
	}
}

func TestPlain403IsNotRateLimited(t *testing.T) {
	clk := newClock()
	f := newFakeAPI(t, clk, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Ratelimit-Remaining", "10")
		w.WriteHeader(http.StatusForbidden)
	})
	_, err := f.app(t, clk).Releases(t.Context(), Repo{FullName: "o/r"})
	if err == nil || errors.Is(err, ErrRateLimited) {
		t.Fatalf("err = %v", err)
	}
}

func TestOpenAssetNoAuthAtDownloadHost(t *testing.T) {
	clk := newClock()
	cdn := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			t.Errorf("Authorization reached the download host: %q", r.Header.Get("Authorization"))
		}
		_, _ = w.Write([]byte("asset-bytes"))
	}))
	defer cdn.Close()
	f := newFakeAPI(t, clk, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/repos/o/r/releases/assets/5" || r.Header.Get("Accept") != "application/octet-stream" ||
			!strings.HasPrefix(r.Header.Get("Authorization"), "Bearer tok-") {
			t.Errorf("request = %s %v", r.URL, r.Header)
		}
		http.Redirect(w, r, cdn.URL+"/blob?sig=secret", http.StatusFound)
	})
	cu, _ := url.Parse(cdn.URL)
	au, _ := url.Parse(f.URL)
	c := upstream.New(upstream.Options{FetchHosts: []string{au.Hostname(), cu.Hostname()}, AllowPrivateForTesting: true})
	a := New(c, f.URL, 123, 7, testKey, clk.now)
	body, size, err := a.OpenAsset(t.Context(), Repo{FullName: "o/r"}, 5, 100)
	if err != nil {
		t.Fatal(err)
	}
	defer body.Close()
	b, _ := io.ReadAll(body)
	if string(b) != "asset-bytes" || size != int64(len(b)) {
		t.Fatalf("body = %q, size = %d", b, size)
	}
}

func TestAPIURLWithBasePath(t *testing.T) {
	clk := newClock()
	var got atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"token":"t","expires_at":"2099-01-01T00:00:00Z"}`))
			return
		}
		got.Store(r.URL.Path)
		_, _ = w.Write([]byte(`[]`))
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	c := upstream.New(upstream.Options{FetchHosts: []string{u.Hostname()}, AllowPrivateForTesting: true})
	a := New(c, srv.URL+"/api/v3/", 1, 7, testKey, clk.now)
	if _, err := a.Releases(t.Context(), Repo{FullName: "o/r"}); err != nil {
		t.Fatal(err)
	}
	if got.Load() != "/api/v3/repos/o/r/releases" {
		t.Fatalf("path = %v", got.Load())
	}
}

func TestOnResponseSeesEveryStatus(t *testing.T) {
	clk := newClock()
	f := newFakeAPI(t, clk, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/installation/repositories" {
			_, _ = w.Write([]byte(`{"repositories":[]}`))
			return
		}
		http.NotFound(w, r)
	})
	a := f.app(t, clk)
	var mu sync.Mutex
	var got []int
	a.OnResponse(func(status int) {
		mu.Lock()
		got = append(got, status)
		mu.Unlock()
	})
	if _, err := a.Repositories(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, _, err := a.OpenAsset(t.Context(), Repo{FullName: "o/r"}, 5, 100); err == nil {
		t.Fatal("OpenAsset of a missing asset succeeded")
	}
	mu.Lock()
	defer mu.Unlock()
	if !slices.Equal(got, []int{http.StatusCreated, http.StatusOK, http.StatusNotFound}) {
		t.Fatalf("statuses = %v", got)
	}
}

package config

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/radiergummi/tspackages/internal/gitmirror"
)

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadExample(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "ghp_test")
	t.Setenv("DEPLOY_KEY", "key")
	t.Setenv("KNOWN_HOSTS", "github.com ssh-ed25519 AAAA")

	c, err := Load("testdata/full.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if c.Tailscale.Hostname != "registry" {
		t.Errorf("hostname = %q", c.Tailscale.Hostname)
	}
	if c.Tailscale.Capability != "github.com/radiergummi/tspackages" {
		t.Errorf("capability = %q", c.Tailscale.Capability)
	}
	if c.Storage.Cache.MaxSize != 50<<30 {
		t.Errorf("cache max_size = %d", c.Storage.Cache.MaxSize)
	}
	if c.Limits.MaxUploadBytes != 100<<20 || c.Limits.MaxDecompressedBytes != 500<<20 ||
		c.Limits.MaxArchiveEntries != 20000 || c.Limits.RequestsPerSecond != 50 ||
		c.Limits.Burst != 100 || c.Limits.UpstreamFetchesPerSecond != 10 || c.Limits.MaxArtifactBytes != 8<<30 {
		t.Errorf("limit defaults = %+v", c.Limits)
	}
	srcs := c.Ecosystems["composer"].Sources
	if len(srcs) != 3 {
		t.Fatalf("sources = %d", len(srcs))
	}
	pk := srcs[2]
	if pk.Name != "packagist" || pk.MetadataTTL != 5*time.Minute || pk.PollInterval != time.Minute {
		t.Errorf("packagist = %+v", pk)
	}
	if got := pk.DownloadCredentials["api.github.com"].Bearer; got != "ghp_test" {
		t.Errorf("bearer = %q", got)
	}
	if srcs[0].KnownHosts != "github.com ssh-ed25519 AAAA" {
		t.Errorf("known_hosts = %q", srcs[0].KnownHosts)
	}
}

func TestLoadFileSecret(t *testing.T) {
	secret := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(secret, []byte("s3cret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(writeConfig(t, strings.Replace(base, "SECRET", "${file:"+secret+"}", 1)))
	if err != nil {
		t.Fatal(err)
	}
	if got := c.Storage.Stores["main"].SecretAccessKey; got != "s3cret" {
		t.Errorf("secret = %q", got)
	}
}

func TestByteSize(t *testing.T) {
	for in, want := range map[string]ByteSize{
		"50GiB": 50 << 30, "100MiB": 100 << 20, "512KiB": 512 << 10, "1234": 1234,
	} {
		c, err := Load(writeConfig(t, strings.Replace(base, "SECRET", "x", 1)+"limits: {max_upload_bytes: "+in+"}\n"))
		if err != nil {
			t.Fatalf("%s: %v", in, err)
		}
		if c.Limits.MaxUploadBytes != want {
			t.Errorf("%s = %d, want %d", in, c.Limits.MaxUploadBytes, want)
		}
	}
	_, err := Load(writeConfig(t, strings.Replace(base, "SECRET", "x", 1)+"limits: {max_upload_bytes: 5XB}\n"))
	if err == nil || !strings.Contains(err.Error(), "invalid byte size") {
		t.Errorf("err = %v", err)
	}
}

// base is a valid config; SECRET is a placeholder for a string field.
const base = `
tailscale:
  state_dir: /ts
storage:
  work_dir: /work
  cache: {driver: fs, path: /cache}
  state: {driver: fs, path: /state}
  stores:
    main: {driver: s3, bucket: b, prefix: hosted/, access_key_id: k, secret_access_key: "SECRET"}
ecosystems:
  composer:
    sources:
      - {name: hosted, type: storage, store: main, claims: ["acme/*"]}
`

func TestValidateErrors(t *testing.T) {
	ecoc := func(sources string) string {
		return strings.Split(base, "ecosystems:")[0] + "ecosystems:\n  composer:\n    sources:\n" + sources
	}
	tests := []struct {
		name, yaml, want string
	}{
		{"unknown key", "stroage: {}\n" + base, "field stroage not found"},
		{"unsupported ecosystem", base + "  oci:\n    sources: []\n", `ecosystem "oci" is not supported yet`},
		{"two unclaimed", ecoc(`      - {name: a, type: registry, url: "https://a", fetch_hosts: [a]}
      - {name: b, type: registry, url: "https://b", fetch_hosts: [b]}
`), "at most one unclaimed source"},
		{"storage without claims", ecoc("      - {name: hosted, type: storage, store: main}\n"), `storage source "hosted" must have claims`},
		{"unknown store", ecoc(`      - {name: hosted, type: storage, store: missing, claims: ["a/*"]}
`), `unknown store "missing"`},
		{"ssh without known_hosts", ecoc(`      - {name: g, type: git, claims: ["a/*"], remotes: ["ssh://git@github.com/a/b.git"]}
`), "known_hosts is required for SSH remotes"},
		{"scp without known_hosts", ecoc(`      - {name: g, type: git, claims: ["a/*"], remotes: ["git@github.com:a/b.git"]}
`), "known_hosts is required for SSH remotes"},
		{"https remote with credentials", ecoc(`      - {name: g, type: git, claims: ["a/*"], remotes: ["https://tok3n@github.com/a/b.git"]}
`), "remote must not contain credentials; use token"},
		{"file remote", ecoc(`      - {name: g, type: git, claims: ["a/*"], remotes: ["file:///x"]}
`), "unsupported remote scheme"},
		{"registry without fetch_hosts", ecoc(`      - {name: r, type: registry, url: "https://a"}
`), "fetch_hosts is required"},
		{"credential host not allowed", ecoc(`      - name: r
        type: registry
        url: https://a
        fetch_hosts: [a]
        download_credentials: {evil.example: {bearer: x}}
`), "not in fetch_hosts"},
		{"duplicate name", ecoc(`      - {name: hosted, type: storage, store: main, claims: ["a/*"]}
      - {name: hosted, type: storage, store: main, claims: ["b/*"]}
`), "duplicate source name"},
		{"cache and state overlap", strings.Replace(base, "state: {driver: fs, path: /state}", "state: {driver: fs, path: /cache/}", 1), "must not share a location"},
		{"hosted store overlaps cache", strings.Replace(base, "main: {driver: s3, bucket: b, prefix: hosted/,", "main: {driver: fs, path: /cache,", 1), "must not share a location"},
		{"uppercase s3 prefix", strings.Replace(base, "prefix: hosted/", "prefix: Hosted/", 1), `storage.stores.main: prefix "Hosted/" must be lowercase`},
		{"unset env", strings.Replace(base, "SECRET", "${env:UNSET}", 1), "environment variable UNSET is not set"},
		{"missing work_dir", strings.Replace(base, "  work_dir: /work\n", "", 1), "storage.work_dir is required"},
		{"relative work_dir", strings.Replace(base, "work_dir: /work", "work_dir: work", 1), "storage.work_dir must be absolute"},
		{"work_dir equals cache", strings.Replace(base, "work_dir: /work", "work_dir: /cache", 1), "storage.work_dir and storage.cache must not share a location"},
		{"work_dir inside state", strings.Replace(base, "work_dir: /work", "work_dir: /state/work", 1), "storage.work_dir and storage.state must not share a location"},
		{"work_dir contains fs store", strings.Replace(strings.Replace(base, "work_dir: /work", "work_dir: /data", 1), "main: {driver: s3, bucket: b, prefix: hosted/,", "main: {driver: fs, path: /data/hosted,", 1), "storage.work_dir and storage.stores.main must not share a location"},
		{"work_dir overlaps state_dir", strings.Replace(base, "state_dir: /ts", "state_dir: /work/ts", 1), "storage.work_dir and tailscale.state_dir must not share a location"},
		{"state_dir inside fs store", strings.Replace(base, "state_dir: /ts", "state_dir: /cache/ts", 1), "storage.cache and tailscale.state_dir must not share a location"},
		{"fs store inside state_dir", strings.Replace(base, "state: {driver: fs, path: /state}", "state: {driver: fs, path: /ts/state}", 1), "storage.state and tailscale.state_dir must not share a location"},
		{"s3 key without secret", strings.Replace(base, `, secret_access_key: "SECRET"`, "", 1), "storage.stores.main: access_key_id and secret_access_key must be set together"},
		{"s3 secret without key", strings.Replace(base, "access_key_id: k, ", "", 1), "storage.stores.main: access_key_id and secret_access_key must be set together"},
		{"no state_dir", strings.Replace(base, "state_dir: /ts", "hostname: r", 1), "tailscale.state_dir is required"},
		{"registry url host not in fetch_hosts", ecoc(`      - {name: r, type: registry, url: "https://a", fetch_hosts: [b]}
`), `url host "a" is not in fetch_hosts`},
		{"credentials host also in download_credentials", ecoc(`      - name: r
        type: registry
        url: https://a
        fetch_hosts: [a]
        credentials: {bearer: x}
        download_credentials: {a: {bearer: y}}
`), `host "a" has both credentials and download_credentials`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := strings.Replace(tt.yaml, "SECRET", "x", 1)
			_, err := Load(writeConfig(t, body))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err = %v, want substring %q", err, tt.want)
			}
		})
	}
}

func TestStoreOverlap(t *testing.T) {
	storage := func(cache, state, hosted string) string {
		return "tailscale: {state_dir: /ts}\nstorage:\n  work_dir: /work\n  cache: " + cache + "\n  state: " + state + "\n  stores:\n    main: " + hosted + "\n" +
			"ecosystems:" + strings.SplitN(base, "ecosystems:", 2)[1]
	}
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	const hosted = "{driver: s3, bucket: other, prefix: hosted/}"
	tests := []struct {
		name, cache, state, hosted string
		wantErr                    string
	}{
		{"fs ancestor", "{driver: fs, path: /data}", "{driver: fs, path: /data/state}", hosted, "must not share a location"},
		{"fs descendant", "{driver: fs, path: /data/cache}", "{driver: fs, path: /data}", hosted, "must not share a location"},
		{"fs sibling with common name prefix", "{driver: fs, path: /data}", "{driver: fs, path: /data2}", hosted, ""},
		{"fs relative equals absolute", "{driver: fs, path: " + cwd + "/rel}", "{driver: fs, path: ./rel/}", hosted, "must not share a location"},
		{"fs root", "{driver: fs, path: /}", "{driver: fs, path: /state}", hosted, "must not share a location"},
		{"s3 empty prefix contains all", "{driver: s3, bucket: b}", "{driver: s3, bucket: b, prefix: state/}", hosted, "must not share a location"},
		{"s3 nested prefix", "{driver: s3, bucket: b, prefix: cache/}", "{driver: s3, bucket: b, prefix: cache/x/}", hosted, "must not share a location"},
		{"s3 prefix without slash boundary", "{driver: s3, bucket: b, prefix: cache}", "{driver: s3, bucket: b, prefix: cache2}", hosted, ""},
		{"s3 different endpoints", "{driver: s3, bucket: b, endpoint: 'https://a.example'}", "{driver: s3, bucket: b, endpoint: 'https://b.example'}", hosted, ""},
		{"s3 same endpoint normalised", "{driver: s3, bucket: b, endpoint: 'https://A.example/'}", "{driver: s3, bucket: b, endpoint: 'https://a.example'}", hosted, "must not share a location"},
		{"hosted store nested in state", "{driver: fs, path: /cache}", "{driver: s3, bucket: b, prefix: state/}", "{driver: s3, bucket: b, prefix: state/hosted/}", "must not share a location"},
		{"missing storage block gives no overlap error", "{}", "{}", hosted, "driver must be fs or s3"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := strings.Replace(storage(tt.cache, tt.state, tt.hosted), "SECRET", "x", 1)
			_, err := Load(writeConfig(t, body))
			switch {
			case tt.wantErr == "" && err != nil:
				t.Fatalf("unexpected error: %v", err)
			case tt.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErr)):
				t.Fatalf("err = %v, want %q", err, tt.wantErr)
			case tt.name == "missing storage block gives no overlap error" && strings.Contains(err.Error(), "share a location"):
				t.Fatalf("spurious overlap error: %v", err)
			}
		})
	}
}

func TestRemoteKinds(t *testing.T) {
	for _, r := range []string{"ext::sh -c 'touch /tmp/x'", "fd::3", "-oProxyCommand=a:b", "git@-evil.com:a/b.git", "host:", "/local/path", "-u@github.com:a/b.git"} {
		t.Run(r, func(t *testing.T) {
			body := strings.Replace(base, "SECRET", "x", 1) +
				"      - {name: g, type: git, known_hosts: k, claims: [\"a/*\"], remotes: [\"" + strings.ReplaceAll(r, `"`, `\"`) + "\"]}\n"
			_, err := Load(writeConfig(t, body))
			if err == nil || !strings.Contains(err.Error(), "unsupported remote scheme") {
				t.Fatalf("err = %v", err)
			}
		})
	}
	for _, r := range []string{"git@github.com:a/b.git", "github.com:a/b.git", "ssh://git@github.com/a/b.git", "https://github.com/a/b.git"} {
		if _, err := gitmirror.RemoteKind(r, false); err != nil {
			t.Errorf("%q rejected", r)
		}
	}
}

func TestNegativeNumbers(t *testing.T) {
	for _, field := range []string{"burst", "max_archive_entries"} {
		t.Run(field, func(t *testing.T) {
			body := strings.Replace(base, "SECRET", "x", 1) + "limits: {" + field + ": -1}\n"
			_, err := Load(writeConfig(t, body))
			if err == nil || !strings.Contains(err.Error(), "limits."+field+" must not be negative") {
				t.Fatalf("err = %v", err)
			}
		})
	}
	for _, field := range []string{"metadata_ttl", "poll_interval"} {
		t.Run(field, func(t *testing.T) {
			body := strings.Replace(base, "SECRET", "x", 1) +
				"      - {name: r, type: registry, url: 'https://a', fetch_hosts: [a], " + field + ": -1m}\n"
			_, err := Load(writeConfig(t, body))
			if err == nil || !strings.Contains(err.Error(), field+" must not be negative") {
				t.Fatalf("err = %v", err)
			}
		})
	}
	// ByteSize cannot be negative through YAML, so exercise Validate directly.
	c := &Config{
		Storage: Storage{Cache: StoreConfig{Driver: "fs", Path: "/a", MaxSize: -1}, State: StoreConfig{Driver: "fs", Path: "/b"}},
		Limits:  Limits{MaxUploadBytes: -1, MaxDecompressedBytes: -1},
	}
	err := Validate(c)
	for _, want := range []string{"storage.cache: max_size", "limits.max_upload_bytes", "limits.max_decompressed_bytes"} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("err = %v, want %q", err, want)
		}
	}
}

func TestExpansionThroughPointersAndSlices(t *testing.T) {
	t.Setenv("PW", "pw")
	t.Setenv("REMOTE", "git@github.com:a/b.git")
	t.Setenv("CLAIM", "acme/*")
	body := strings.Replace(base, "SECRET", "x", 1) + `      - name: g
        type: git
        known_hosts: k
        claims: ["${env:CLAIM}"]
        remotes: ["${env:REMOTE}"]
      - name: r
        type: registry
        url: https://a
        fetch_hosts: [a]
        credentials: {username: u, password: "${env:PW}"}
`
	c, err := Load(writeConfig(t, body))
	if err != nil {
		t.Fatal(err)
	}
	srcs := c.Ecosystems["composer"].Sources
	if srcs[1].Claims[0] != "acme/*" || srcs[1].Remotes[0] != "git@github.com:a/b.git" {
		t.Errorf("slices not expanded: %+v", srcs[1])
	}
	if srcs[2].Credentials == nil || srcs[2].Credentials.Password != "pw" {
		t.Errorf("credentials not expanded: %+v", srcs[2].Credentials)
	}
}

func TestProblemsAreAggregatedInOrder(t *testing.T) {
	body := strings.Replace(base, "SECRET", "x", 1) + `      - {name: a, type: registry, url: "https://a"}
      - {name: a, type: git, claims: ["x/*"], remotes: ["file:///x"]}
  npm: {sources: []}
  oci: {sources: []}
`
	_, err := Load(writeConfig(t, body))
	if err == nil {
		t.Fatal("want error")
	}
	msg := err.Error()
	for _, want := range []string{"fetch_hosts is required", "duplicate source name", "unsupported remote scheme", `"npm" is not supported`, `"oci" is not supported`} {
		if !strings.Contains(msg, want) {
			t.Errorf("missing %q in:\n%s", want, msg)
		}
	}
	if strings.Index(msg, `"npm"`) > strings.Index(msg, `"oci"`) {
		t.Errorf("ecosystem errors not sorted:\n%s", msg)
	}
}

func TestCacheMaxSizeDefault(t *testing.T) {
	c, err := Load(writeConfig(t, strings.Replace(base, "SECRET", "x", 1)))
	if err != nil {
		t.Fatal(err)
	}
	if c.Storage.Cache.MaxSize != 10<<30 {
		t.Errorf("cache max_size = %d, want 10GiB", c.Storage.Cache.MaxSize)
	}
}

func TestEnvRefs(t *testing.T) {
	t.Setenv("TSP_SECRET", "s")
	t.Setenv("TSP_PW", "p")
	body := strings.Replace(base, "SECRET", "${env:TSP_SECRET}", 1) + `      - name: r
        type: registry
        url: https://a
        fetch_hosts: [a]
        credentials: {username: u, password: "${env:TSP_PW}${env:TSP_SECRET}"}
`
	c, err := Load(writeConfig(t, body))
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(c.EnvRefs(), ","); got != "TSP_PW,TSP_SECRET" {
		t.Errorf("EnvRefs = %q, want TSP_PW,TSP_SECRET", got)
	}
}

func TestBaseIsValid(t *testing.T) {
	if _, err := Load(writeConfig(t, strings.Replace(base, "SECRET", "x", 1))); err != nil {
		t.Fatal(err)
	}
}

func TestExampleConfigValidates(t *testing.T) {
	for k, v := range map[string]string{"DEPLOY_KEY": "key", "KNOWN_HOSTS": "github.com ssh-ed25519 AAAA", "GITHUB_TOKEN": "t"} {
		t.Setenv(k, v)
	}
	if _, err := Load("../../examples/config.yaml"); err != nil {
		t.Fatal(err)
	}
}

func TestClaimValidation(t *testing.T) {
	src := func(claim string) string {
		return strings.Replace(base, "SECRET", "x", 1) +
			"      - {name: r, type: registry, url: 'https://a', fetch_hosts: [a], claims: ['" + claim + "']}\n"
	}
	for _, bad := range []string{"matchory", "matchory*", "matchory/[", "Matchory/*", "a/b/c", "/a", "a/", "a/b?", "a/[bc]", `a\/b`, "a/b]", "", "**/x y"} {
		t.Run("bad "+bad, func(t *testing.T) {
			_, err := Load(writeConfig(t, src(bad)))
			if err == nil || !strings.Contains(err.Error(), "invalid claim") {
				t.Fatalf("err = %v", err)
			}
		})
	}
	for _, good := range []string{"*", "matchory/*", "matchory-*/*", "a.b_c/d-e", "*/*", "acme/pkg"} {
		t.Run("good "+good, func(t *testing.T) {
			if _, err := Load(writeConfig(t, src(good))); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestStorageClaimShadowedByEarlierSource(t *testing.T) {
	ecoc := func(sources string) string {
		return strings.Replace(strings.Split(base, "ecosystems:")[0], "SECRET", "x", 1) + "ecosystems:\n  composer:\n    sources:\n" + sources
	}
	_, err := Load(writeConfig(t, ecoc(`      - {name: g, type: git, claims: ["acme/*"], remotes: ["https://h/a.git"]}
      - {name: hosted, type: storage, store: main, claims: ["other/*", "acme/*"]}
`)))
	if err == nil || !strings.Contains(err.Error(), `source "hosted": claim "acme/*" overlaps claim "acme/*" of earlier source "g"`) {
		t.Fatalf("err = %v", err)
	}
	// Overlap is by pattern, not by string: every one of these leaves some
	// name the storage source claims to an earlier source.
	for _, c := range []struct{ earlier, storage string }{
		{"acme/*", "acme/x"},
		{"*", "acme/x"},
		{"*/x", "acme/*"},
		{"acme/x*", "acme/*y"},
		{"a*b/c", "*ab/c"},
	} {
		_, err := Load(writeConfig(t, ecoc(`      - {name: g, type: git, claims: ["`+c.earlier+`"], remotes: ["https://h/a.git"]}
      - {name: hosted, type: storage, store: main, claims: ["`+c.storage+`"]}
`)))
		if err == nil || !strings.Contains(err.Error(), "overlaps claim") {
			t.Errorf("%s then %s: err = %v", c.earlier, c.storage, err)
		}
	}
	// Later sources may overlap a storage source, and disjoint patterns pass.
	if _, err := Load(writeConfig(t, ecoc(`      - {name: hosted, type: storage, store: main, claims: ["acme/*"]}
      - {name: g, type: git, claims: ["acme/*", "acme/x*", "acmex/*"], remotes: ["https://h/a.git"]}
      - {name: h2, type: storage, store: main, claims: ["acme-*/x", "other/a*b"]}
      - {name: h3, type: storage, store: main, claims: ["other/a*c"]}
`))); err != nil {
		t.Fatal(err)
	}
}

func TestClaimsOverlap(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want bool
	}{
		{"*", "a/b", true},
		{"a/b", "a/b", true},
		{"a/*", "*/b", true},
		{"a*/b", "*a/b", true},
		{"ab*", "*ba", true}, // "aba"
		{"a*c/x", "ab*/x", true},
		{"a/b", "a/c", false},
		{"a*b/x", "a*c/x", false},
		{"ab*/x", "ac*/x", false},
		{"a/*", "b/*", false},
		{"*x/y", "*z/y", false},
	} {
		if got := claimsOverlap("composer", c.a, c.b); got != c.want {
			t.Errorf("claimsOverlap(%q, %q) = %v, want %v", c.a, c.b, got, c.want)
		}
		if got := claimsOverlap("composer", c.b, c.a); got != c.want {
			t.Errorf("claimsOverlap(%q, %q) = %v, want %v", c.b, c.a, got, c.want)
		}
	}
}

func TestRatesMustBePositiveAndFinite(t *testing.T) {
	for _, v := range []string{".nan", ".inf", "-.inf"} {
		for _, field := range []string{"requests_per_second", "upstream_fetches_per_second"} {
			body := strings.Replace(base, "SECRET", "x", 1) + "limits: {" + field + ": " + v + "}\n"
			_, err := Load(writeConfig(t, body))
			if err == nil || !strings.Contains(err.Error(), "limits."+field+" must be a positive number") {
				t.Errorf("%s=%s: err = %v", field, v, err)
			}
		}
	}
	// Without defaults applied, a zero rate is rejected, not unlimited.
	c, err := Load(writeConfig(t, strings.Replace(base, "SECRET", "x", 1)))
	if err != nil {
		t.Fatal(err)
	}
	c.Limits.RequestsPerSecond, c.Limits.UpstreamFetchesPerSecond = 0, 0
	err = Validate(c)
	for _, want := range []string{"limits.requests_per_second must be a positive number", "limits.upstream_fetches_per_second must be a positive number"} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("err = %v, want %q", err, want)
		}
	}
}

func TestMaxArtifactBytesNegative(t *testing.T) {
	c := &Config{Limits: Limits{MaxArtifactBytes: -1}}
	if err := Validate(c); err == nil || !strings.Contains(err.Error(), "limits.max_artifact_bytes must not be negative") {
		t.Fatalf("err = %v", err)
	}
}

func TestSourceNames(t *testing.T) {
	src := func(name string) string {
		return strings.Replace(base, "SECRET", "x", 1) +
			"      - {name: '" + name + "', type: registry, url: 'https://a', fetch_hosts: [a]}\n"
	}
	for _, bad := range []string{"../x", "a/b", ".hidden", "-x", "_x", "Upper", "a b", "a#b"} {
		if _, err := Load(writeConfig(t, src(bad))); err == nil || !strings.Contains(err.Error(), "invalid source name") {
			t.Errorf("%q: err = %v", bad, err)
		}
	}
	for _, good := range []string{"packagist", "a.b_c-d", "0x"} {
		if _, err := Load(writeConfig(t, src(good))); err != nil {
			t.Errorf("%q: %v", good, err)
		}
	}
}

func TestValidateWithTestingOptions(t *testing.T) {
	c, err := Load(writeConfig(t, strings.Replace(base, "SECRET", "x", 1)))
	if err != nil {
		t.Fatal(err)
	}
	eco := c.Ecosystems["composer"]
	eco.Sources = append(eco.Sources,
		Source{Name: "r", Type: "registry", URL: "http://127.0.0.1:8080", FetchHosts: []string{"127.0.0.1"}},
		Source{Name: "g", Type: "git", Claims: []string{"g/*"}, Remotes: []string{"/srv/repo", "file:///srv/other"}},
	)
	c.Ecosystems["composer"] = eco
	err = Validate(c)
	for _, want := range []string{`url "http://127.0.0.1:8080" must use https`, `unsupported remote scheme in "/srv/repo"`, `unsupported remote scheme in "file:///srv/other"`} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("Validate: err = %v, want %q", err, want)
		}
	}
	if err := ValidateWith(c, ValidateOptions{AllowHTTPUpstreams: true, AllowFileRemotes: true}); err != nil {
		t.Fatalf("ValidateWith: %v", err)
	}
	// The options do not loosen anything else.
	eco.Sources[1].URL = "ftp://x"
	if err := ValidateWith(c, ValidateOptions{AllowHTTPUpstreams: true, AllowFileRemotes: true}); err == nil || !strings.Contains(err.Error(), "must use https") {
		t.Fatalf("ftp accepted: %v", err)
	}
}

func TestCredentialsHostDuplicateNormalised(t *testing.T) {
	for _, tc := range []struct{ url, dl string }{
		{"https://A.example", "a.example"},
		{"https://a.example:443", "a.example"},
		{"https://a.example:443", "A.Example"},
	} {
		body := strings.Replace(base, "SECRET", "x", 1) + `      - name: r
        type: registry
        url: ` + tc.url + `
        fetch_hosts: [a.example, A.Example, "a.example:443"]
        credentials: {bearer: x}
        download_credentials: {"` + tc.dl + `": {bearer: y}}
`
		_, err := Load(writeConfig(t, body))
		if err == nil || !strings.Contains(err.Error(), "has both credentials and download_credentials") {
			t.Errorf("%s / %s: err = %v", tc.url, tc.dl, err)
		}
	}
}

func TestExpandSkipsUnexportedFields(t *testing.T) {
	t.Setenv("TSP_X", "expanded")
	v := struct {
		A string
		b string
	}{A: "${env:TSP_X}", b: "${env:TSP_X}"}
	refs := map[string]bool{}
	if err := expand(reflect.ValueOf(&v).Elem(), refs); err != nil {
		t.Fatal(err)
	}
	if v.A != "expanded" || v.b != "${env:TSP_X}" {
		t.Fatalf("%+v", v)
	}
}

// pypiConfig is base with only a pypi ecosystem holding sources.
func pypiConfig(sources string) string {
	return strings.Replace(strings.Split(base, "ecosystems:")[0], "SECRET", "x", 1) + "ecosystems:\n  pypi:\n    sources:\n" + sources
}

func TestPyPIClaims(t *testing.T) {
	src := func(claim string) string {
		return pypiConfig("      - {name: r, type: registry, url: 'https://pypi.org/simple/', fetch_hosts: [pypi.org], claims: ['" + claim + "']}\n")
	}
	for _, good := range []string{"*", "matchory-*", "foo", "*-utils", "a1-b2"} {
		if _, err := Load(writeConfig(t, src(good))); err != nil {
			t.Errorf("%q: %v", good, err)
		}
	}
	for _, bad := range []string{"Matchory-*", "matchory_*", "a.b", "vendor/name", "**", "", "a b", "a[bc]"} {
		_, err := Load(writeConfig(t, src(bad)))
		if err == nil || !strings.Contains(err.Error(), "invalid claim") || !strings.Contains(err.Error(), bad) {
			t.Errorf("%q: err = %v", bad, err)
		}
	}
}

func TestPyPIStorageClaimOverlap(t *testing.T) {
	_, err := Load(writeConfig(t, pypiConfig(`      - {name: g, type: git, claims: ["matchory-*"], remotes: ["https://h/a.git"]}
      - {name: hosted, type: storage, store: main, claims: ["matchory-core"]}
`)))
	if err == nil || !strings.Contains(err.Error(), "overlaps claim") {
		t.Fatalf("err = %v", err)
	}
	if _, err := Load(writeConfig(t, pypiConfig(`      - {name: hosted, type: storage, store: main, claims: ["matchory-*"]}
      - {name: g, type: git, claims: ["matchory-*", "other"], remotes: ["https://h/a.git"]}
      - {name: pypi, type: registry, url: "https://pypi.org/simple/", fetch_hosts: [pypi.org, files.pythonhosted.org]}
`))); err != nil {
		t.Fatal(err)
	}
}

func TestPyPITagsMapping(t *testing.T) {
	ok := pypiConfig(`      - name: g
        type: git
        claims: ["acme-*"]
        remotes: ["https://h/mono.git"]
        tags:
          "https://h/mono.git":
            "core@*": [packages/core]
            "v*": ["*"]
`)
	c, err := Load(writeConfig(t, ok))
	if err != nil {
		t.Fatal(err)
	}
	if got := c.Ecosystems["pypi"].Sources[0].Tags["https://h/mono.git"]["core@*"]; len(got) != 1 || got[0] != "packages/core" {
		t.Fatalf("tags = %v", c.Ecosystems["pypi"].Sources[0].Tags)
	}
	for name, body := range map[string]string{
		"unlisted remote": strings.Replace(ok, `"https://h/mono.git":`, `"https://h/other.git":`, 1),
		"dotdot path":     strings.Replace(ok, "[packages/core]", "[../core]", 1),
		"absolute path":   strings.Replace(ok, "[packages/core]", "[/core]", 1),
		"bad pattern":     strings.Replace(ok, `"core@*"`, `"core@["`, 1),
		"star with paths": strings.Replace(ok, `["*"]`, `["*", packages/core]`, 1),
		"on composer":     strings.Replace(strings.Replace(ok, "pypi:", "composer:", 1), `["acme-*"]`, `["acme/*"]`, 1),
	} {
		if _, err := Load(writeConfig(t, body)); err == nil || !strings.Contains(err.Error(), "tags") {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}

func TestPyPIRegistryURLMustBeSimpleIndex(t *testing.T) {
	_, err := Load(writeConfig(t, pypiConfig("      - {name: r, type: registry, url: 'https://pypi.org/', fetch_hosts: [pypi.org]}\n")))
	if err == nil || !strings.Contains(err.Error(), "/simple/") {
		t.Fatalf("err = %v", err)
	}
}

func TestPyPIBranchesRejected(t *testing.T) {
	_, err := Load(writeConfig(t, pypiConfig(`      - {name: g, type: git, claims: ["a-*"], remotes: ["https://h/a.git"], branches: [main]}
`)))
	if err == nil || !strings.Contains(err.Error(), "branches") {
		t.Fatalf("err = %v", err)
	}
}

func TestUnsupportedEcosystem(t *testing.T) {
	body := strings.Replace(pypiConfig("      - {name: r, type: registry, url: 'https://x/simple/', fetch_hosts: [x]}\n"), "pypi:", "npm:", 1)
	if _, err := Load(writeConfig(t, body)); err == nil || !strings.Contains(err.Error(), `ecosystem "npm" is not supported yet`) {
		t.Fatalf("err = %v", err)
	}
}

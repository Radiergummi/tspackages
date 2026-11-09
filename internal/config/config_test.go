package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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
		c.Limits.Burst != 100 || c.Limits.UpstreamFetchesPerSecond != 10 {
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
storage:
  cache: {driver: fs, path: /cache}
  state: {driver: fs, path: /state}
  stores:
    main: {driver: s3, bucket: b, prefix: hosted/, secret_access_key: "SECRET"}
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
		{"unsupported ecosystem", base + "  pypi:\n    sources: []\n", `ecosystem "pypi" is not supported yet`},
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
		{"unset env", strings.Replace(base, "SECRET", "${env:UNSET}", 1), "environment variable UNSET is not set"},
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

func TestBaseIsValid(t *testing.T) {
	if _, err := Load(writeConfig(t, strings.Replace(base, "SECRET", "x", 1))); err != nil {
		t.Fatal(err)
	}
}

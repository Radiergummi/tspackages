package config

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"
)

func rsaKeyPEM(t *testing.T, pkcs8 bool) string {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	if !pkcs8 {
		return string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)}))
	}
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

func TestGitHubSource(t *testing.T) {
	key := rsaKeyPEM(t, false)
	good := func() Source {
		return Source{Name: "x", Type: "github", Claims: []string{"acme-*"}, AppID: 1, InstallationID: 2, PrivateKey: key}
	}
	pypi := func(sources ...Source) *Config {
		return &Config{Ecosystems: map[string]Ecosystem{"pypi": {Sources: sources}}}
	}
	// validate runs the source checks only; the rest of the config is not
	// under test.
	validate := func(eco string, c *Config) error {
		return errors.Join(validateSources(eco, c.Ecosystems[eco].Sources, nil, ValidateOptions{})...)
	}
	for _, k := range []string{key, rsaKeyPEM(t, true)} {
		s := good()
		s.PrivateKey = k
		c := pypi(s)
		ApplyDefaults(c)
		if err := validate("pypi", c); err != nil {
			t.Fatalf("valid source: %v", err)
		}
		if got := c.Ecosystems["pypi"].Sources[0]; got.URL != "https://api.github.com/" || got.PollInterval != 5*time.Minute {
			t.Fatalf("defaults: url %q poll %v", got.URL, got.PollInterval)
		}
	}

	cases := []struct {
		name string
		mod  func(*Source)
		want string
	}{
		{"no claims", func(s *Source) { s.Claims = nil }, `github source "x" must have claims`},
		{"no app_id", func(s *Source) { s.AppID = 0 }, "app_id is required"},
		{"no installation_id", func(s *Source) { s.InstallationID = 0 }, "installation_id is required"},
		{"bad key", func(s *Source) { s.PrivateKey = "nope" }, "private_key is not a PEM RSA private key"},
		{"remotes", func(s *Source) { s.Remotes = []string{"https://h/a.git"} }, "remotes is only supported on git sources"},
		{"credentials", func(s *Source) { s.Credentials = &Credential{} }, "credentials are not supported on github sources"},
		{"http url", func(s *Source) { s.URL = "http://ghe.example/api/v3/" }, "must use https"},
		{"fetch_hosts on github.com", func(s *Source) { s.FetchHosts = []string{"x"} }, "fetch_hosts is only for GitHub Enterprise Server"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := good()
			tc.mod(&s)
			c := pypi(s)
			ApplyDefaults(c)
			if err := validate("pypi", c); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
		})
	}

	t.Run("not for npm", func(t *testing.T) {
		c := &Config{Ecosystems: map[string]Ecosystem{"npm": {Sources: []Source{good()}}}}
		ApplyDefaults(c)
		if err := validate("npm", c); err == nil || !strings.Contains(err.Error(), `type "github" is not supported for npm`) {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("overlap with an earlier source", func(t *testing.T) {
		reg := Source{Name: "pypi", Type: "registry", URL: "https://pypi.org/simple/", FetchHosts: []string{"pypi.org"}, Claims: []string{"acme-*"}}
		c := pypi(reg, good())
		ApplyDefaults(c)
		if err := validate("pypi", c); err == nil || !strings.Contains(err.Error(), "overlaps claim") {
			t.Fatalf("err = %v", err)
		}
	})
}

func TestGitHubFetchHosts(t *testing.T) {
	fetch, tailnet := GitHubFetchHosts(Source{Type: "github", URL: "https://api.github.com/"})
	if want := []string{"api.github.com", "release-assets.githubusercontent.com", "objects.githubusercontent.com"}; !slices.Equal(fetch, want) || len(tailnet) != 0 {
		t.Fatalf("github.com: fetch %v tailnet %v", fetch, tailnet)
	}
	fetch, tailnet = GitHubFetchHosts(Source{Type: "github", URL: "https://ghe.corp.example/api/v3/", FetchHosts: []string{"assets.corp.example"}})
	want := []string{"ghe.corp.example", "assets.corp.example"}
	if !slices.Equal(fetch, want) || !slices.Equal(tailnet, want) {
		t.Fatalf("GHES: fetch %v tailnet %v", fetch, tailnet)
	}
}

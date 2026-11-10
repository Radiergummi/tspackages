// Package testutil holds helpers shared by tests. Only _test.go files import it.
package testutil

import (
	"archive/zip"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/tailcfg"
	"tailscale.com/tailcfg/peercap"
)

// Git runs git in dir with a fixed identity, no user or system config,
// unsigned commits and tags, and main as the initial branch. It returns the
// trimmed combined output and fails the test on error.
func Git(t testing.TB, dir string, args ...string) string {
	t.Helper()
	full := append([]string{"-c", "commit.gpgsign=false", "-c", "tag.gpgsign=false", "-c", "init.defaultBranch=main"}, args...)
	cmd := exec.CommandContext(t.Context(), "git", full...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=T", "GIT_AUTHOR_EMAIL=t@example.com",
		"GIT_COMMITTER_NAME=T", "GIT_COMMITTER_EMAIL=t@example.com",
		"GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

// ZipOf returns a zip archive holding files (name to content).
func ZipOf(t testing.TB, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, content := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(w, content); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// Who is a fake identity.Whoiser: every caller is the tagged node
// ci.ts.net (stable ID "nid", tag:ci) holding Rules under capability Cap.
type Who struct {
	Cap   peercap.Cap
	Rules []string
}

// NewWho returns a Who granting rules (JSON capability values) under capName.
func NewWho(capName string, rules ...string) Who {
	return Who{Cap: peercap.Cap(capName), Rules: rules}
}

func (w Who) WhoIs(context.Context, string) (*apitype.WhoIsResponse, error) {
	var vals []tailcfg.RawMessage
	for _, r := range w.Rules {
		vals = append(vals, tailcfg.RawMessage(r))
	}
	return &apitype.WhoIsResponse{
		Node:   &tailcfg.Node{Name: "ci.ts.net.", StableID: "nid", Tags: []string{"tag:ci"}},
		CapMap: tailcfg.PeerCapMap{w.Cap: vals},
	}, nil
}

// S3Env returns the S3-compatible test service from TSP_TEST_S3_ENDPOINT, with
// credentials from TSP_TEST_S3_ACCESS_KEY and TSP_TEST_S3_SECRET_KEY
// (minioadmin by default), and a fresh bucket name. It skips the test when
// the endpoint is unset.
func S3Env(t testing.TB) (endpoint, accessKey, secretKey, bucket string) {
	t.Helper()
	endpoint = os.Getenv("TSP_TEST_S3_ENDPOINT")
	if endpoint == "" {
		t.Skip("TSP_TEST_S3_ENDPOINT not set")
	}
	accessKey, secretKey = "minioadmin", "minioadmin"
	if v := os.Getenv("TSP_TEST_S3_ACCESS_KEY"); v != "" {
		accessKey = v
	}
	if v := os.Getenv("TSP_TEST_S3_SECRET_KEY"); v != "" {
		secretKey = v
	}
	return endpoint, accessKey, secretKey, fmt.Sprintf("tsp-test-%d", time.Now().UnixNano())
}

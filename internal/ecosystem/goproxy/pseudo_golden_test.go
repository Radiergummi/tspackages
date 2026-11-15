package goproxy

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/radiergummi/tspackages/internal/storage"
	"github.com/radiergummi/tspackages/internal/testutil"
)

// TestPseudoVersionsMatchGoList compares GitSource.Info with what the go
// command resolves from the repository directly.
func TestPseudoVersionsMatchGoList(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not on PATH")
	}
	root := t.TempDir()
	dir := filepath.Join(root, "acme", "m")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	commit := func(date string, files map[string]string) string {
		writeFiles(t, dir, files)
		goldenGit(t, dir, date, "add", "-A")
		goldenGit(t, dir, date, "commit", "--quiet", "-m", date)
		return goldenGit(t, dir, date, "rev-parse", "HEAD")
	}
	goldenGit(t, dir, "", "init", "--quiet")
	commit("2026-01-02T03:04:05Z", map[string]string{
		"go.mod":    "module " + goldenPath + "\n\ngo 1.23\n",
		"v2/go.mod": "module " + goldenPath + "/v2\n\ngo 1.23\n",
	})
	goldenGit(t, dir, "", "tag", "v1.2.0")
	afterRelease := commit("2026-02-03T04:05:06Z", map[string]string{"a.go": "package m\n"})
	commit("2026-03-04T05:06:07Z", map[string]string{"b.go": "package m\n"})
	goldenGit(t, dir, "", "tag", "v1.3.0-rc.1")
	afterPrerelease := commit("2026-04-05T06:07:08Z", map[string]string{"c.go": "package m\n"})
	commit("2026-05-06T07:08:09Z", map[string]string{"d.go": "package m\n"})

	state, err := storage.NewFS(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	e := &gitEnv{t: t, repo: dir, remote: "file://" + dir, state: state, mirrorBase: t.TempDir()}
	g := e.source([]Module{{Path: goldenPath}})

	for _, c := range []struct{ path, rev string }{
		{goldenPath, "main"},
		{goldenPath, afterRelease[:12]},
		{goldenPath, afterRelease},
		{goldenPath, afterPrerelease},
		{goldenPath + "/v2", "main"},
		{goldenPath + "/v2", afterRelease[:12]},
	} {
		t.Run(c.path+"@"+c.rev, func(t *testing.T) {
			version, at := testutil.GoListModule(t, root, c.path+"@"+c.rev)
			info, err := g.Info(t.Context(), c.path, c.rev)
			if err != nil {
				t.Fatalf("Info: %v", err)
			}
			if info.Version != version || !info.Time.Equal(at) {
				t.Fatalf("Info = %s at %s; go list says %s at %s", info.Version, info.Time, version, at)
			}
			// The minted pseudo-version is also accepted when requested directly.
			if _, err := g.Info(t.Context(), c.path, version); err != nil {
				t.Fatalf("Info(%s): %v", version, err)
			}
		})
	}
}

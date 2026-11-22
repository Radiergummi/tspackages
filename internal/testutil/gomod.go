package testutil

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// goCmd runs the go command with args in a clean environment where
// https://git.test/<p> is the git repository repoRoot/<p>: no inherited
// variables but PATH, a fresh HOME, module cache and GOPATH, no proxy and no
// checksum database. extraEnv is appended. It skips the test when go or git
// is missing, and returns stdout; failure fails the test.
func goCmd(t *testing.T, repoRoot string, extraEnv []string, args ...string) []byte {
	t.Helper()
	for _, bin := range []string{"go", "git"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("%s not on PATH", bin)
		}
	}
	tmp := t.TempDir()
	gitconfig := filepath.Join(tmp, "gitconfig")
	conf := "[url \"file://" + repoRoot + "/\"]\n\tinsteadOf = https://git.test/\n[protocol \"file\"]\n\tallow = always\n"
	if err := os.WriteFile(gitconfig, []byte(conf), 0o600); err != nil {
		t.Fatal(err)
	}
	home := filepath.Join(tmp, "home")
	if err := os.Mkdir(home, 0o700); err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(t.Context(), "go", args...)
	cmd.Dir = tmp
	cmd.Env = append([]string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + home,
		"GIT_CONFIG_GLOBAL=" + gitconfig,
		"GIT_CONFIG_NOSYSTEM=1",
		"GOPROXY=direct",
		"GOSUMDB=off",
		"GOFLAGS=-modcacherw",
		"GOTOOLCHAIN=local",
		"GOMODCACHE=" + filepath.Join(tmp, "modcache"),
		"GOPATH=" + filepath.Join(tmp, "gopath"),
	}, extraEnv...)
	out, err := cmd.Output()
	if err != nil {
		var stderr []byte
		if ee, ok := errors.AsType[*exec.ExitError](err); ok {
			stderr = ee.Stderr
		}
		t.Fatalf("go %v: %v\n%s%s", args, err, out, stderr)
	}
	return out
}

// GoModDownload runs `go mod download -json module@version` against the
// repositories under repoRoot (see goCmd) and returns the go.sum hashes of
// the module zip and its go.mod.
func GoModDownload(t *testing.T, repoRoot, module, version string, extraEnv ...string) (sum, goModSum string) {
	t.Helper()
	out := goCmd(t, repoRoot, extraEnv, "mod", "download", "-json", module+"@"+version)
	var res struct {
		Version  string `json:"Version"`
		Sum      string `json:"Sum"`
		GoModSum string `json:"GoModSum"`
		Error    string `json:"Error"`
	}
	if err := json.Unmarshal(out, &res); err != nil {
		t.Fatalf("go mod download output %q: %v", out, err)
	}
	if res.Error != "" || res.Version != version || res.Sum == "" || res.GoModSum == "" {
		t.Fatalf("go mod download %s@%s: %s", module, version, out)
	}
	return res.Sum, res.GoModSum
}

// GoListModule runs `go list -m -json query` against the repositories under
// repoRoot (see goCmd) and returns the version and time it resolves to.
func GoListModule(t *testing.T, repoRoot, query string, extraEnv ...string) (version string, at time.Time) {
	t.Helper()
	out := goCmd(t, repoRoot, extraEnv, "list", "-m", "-json", query)
	var res struct {
		Version string    `json:"Version"`
		Time    time.Time `json:"Time"`
		Error   *struct {
			Err string `json:"Err"`
		} `json:"Error"`
	}
	if err := json.Unmarshal(out, &res); err != nil {
		t.Fatalf("go list output %q: %v", out, err)
	}
	if res.Error != nil || res.Version == "" {
		t.Fatalf("go list -m %s: %s", query, out)
	}
	return res.Version, res.Time
}

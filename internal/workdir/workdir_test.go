package workdir

import (
	"bytes"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLock(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "work")
	var logs bytes.Buffer
	log := slog.New(slog.NewTextHandler(&logs, nil))
	release, err := Lock(t.Context(), dir, time.Second, log)
	if err != nil {
		t.Fatal(err)
	}
	if st, err := os.Lstat(dir); err != nil || st.Mode().Perm() != 0o700 {
		t.Errorf("work_dir mode %v, %v", st.Mode(), err)
	}
	start := time.Now()
	if _, err := Lock(t.Context(), dir, 200*time.Millisecond, log); err == nil || !strings.Contains(err.Error(), "another instance") {
		t.Fatalf("second lock: %v", err)
	}
	if time.Since(start) < 200*time.Millisecond {
		t.Error("did not wait before giving up")
	}
	if !strings.Contains(logs.String(), "waiting") {
		t.Errorf("no wait log line: %s", logs.String())
	}
	// Released: a waiter gets it.
	go func() { time.Sleep(100 * time.Millisecond); release() }()
	r2, err := Lock(t.Context(), dir, 2*time.Second, log)
	if err != nil {
		t.Fatal(err)
	}
	r2()
}

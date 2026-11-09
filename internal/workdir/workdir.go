// Package workdir prepares and locks private directories such as work_dir
// and the tsnet state dir.
package workdir

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// EnsurePrivateDir creates dir with mode 0700 if it is missing, then checks
// that it is a real directory (not a symlink) owned by the current user with
// mode 0700.
func EnsurePrivateDir(dir string) error {
	if _, err := os.Lstat(dir); errors.Is(err, fs.ErrNotExist) {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("create %s: %w", dir, err)
		}
	}
	st, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !st.IsDir() {
		return fmt.Errorf("%s must be a directory, not a symlink or file", dir)
	}
	if sys, ok := st.Sys().(*syscall.Stat_t); !ok || int(sys.Uid) != os.Getuid() {
		return fmt.Errorf("%s must be owned by uid %d", dir, os.Getuid())
	}
	if st.Mode().Perm() != 0o700 {
		return fmt.Errorf("%s has mode %04o, want 0700", dir, st.Mode().Perm())
	}
	return nil
}

// Lock takes an exclusive flock on <dir>/.lock so only one instance
// uses a work_dir. If another holds it, it logs once and waits up to wait
// before failing. dir is created (mode 0700) if missing. The returned
// function releases the lock; the process exiting releases it too.
func Lock(ctx context.Context, dir string, wait time.Duration, log *slog.Logger) (func(), error) {
	if err := EnsurePrivateDir(dir); err != nil {
		return nil, err
	}
	p := filepath.Join(dir, ".lock")
	f, err := os.OpenFile(p, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(wait)
	for logged := false; ; {
		err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			return func() { f.Close() }, nil
		}
		if !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EINTR) {
			f.Close()
			return nil, fmt.Errorf("lock %s: %w", p, err)
		}
		if time.Now().After(deadline) {
			f.Close()
			return nil, fmt.Errorf("%s is locked by another instance (waited %s)", p, wait)
		}
		if !logged {
			log.Warn("work_dir is locked by another instance; waiting", "path", p, "timeout", wait)
			logged = true
		}
		select {
		case <-ctx.Done():
			f.Close()
			return nil, ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
}

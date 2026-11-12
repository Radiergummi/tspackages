package goproxy

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/mod/module"

	"github.com/radiergummi/tspackages/internal/gitmirror"
	"github.com/radiergummi/tspackages/internal/resolve"
)

// archEntry is an entry of a fake git archive, named without "prefix/".
type archEntry struct {
	name, body string
	mode       fs.FileMode // 0 means a regular file
}

// fakeArchive returns an Archive func writing entries as git archive would,
// under "prefix/".
func fakeArchive(t *testing.T, entries ...archEntry) func(context.Context, io.Writer) error {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, e := range entries {
		h := &zip.FileHeader{Name: "prefix/" + e.name, Method: zip.Store}
		mode := e.mode
		if mode == 0 {
			mode = 0o644
		}
		h.SetMode(mode)
		w, err := zw.CreateHeader(h)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(w, e.body); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	data := buf.Bytes()
	return func(_ context.Context, w io.Writer) error {
		_, err := w.Write(data)
		return err
	}
}

func noLicense(context.Context) ([]byte, error) {
	return nil, fmt.Errorf("LICENSE: %w", resolve.ErrNotFound)
}

func buildInput(t *testing.T, modPath, subdir string, archive func(context.Context, io.Writer) error) BuildInput {
	return BuildInput{
		Version:  module.Version{Path: modPath, Version: "v1.0.0"},
		Subdir:   subdir,
		GoMod:    []byte("module " + modPath + "\n"),
		Archive:  archive,
		License:  noLicense,
		TmpDir:   t.TempDir(),
		MaxBytes: MaxArchiveBytes,
	}
}

// zipFiles returns the names and contents of the module zip at path.
func zipFiles(t *testing.T, path string) map[string]string {
	t.Helper()
	zr, err := zip.OpenReader(path)
	if err != nil {
		t.Fatal(err)
	}
	defer zr.Close()
	out := map[string]string{}
	for _, f := range zr.File {
		rc, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		b, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			t.Fatal(err)
		}
		out[f.Name] = string(b)
	}
	return out
}

func wantRefusal(t *testing.T, err error, prefix string) {
	t.Helper()
	var r *RefusalError
	if !errors.As(err, &r) || !strings.HasPrefix(r.Reason, prefix) {
		t.Fatalf("err = %v, want a RefusalError starting %q", err, prefix)
	}
}

func TestBuildZipArchiveCap(t *testing.T) {
	in := buildInput(t, "example.com/m", "", fakeArchive(t,
		archEntry{name: "go.mod", body: "module example.com/m\n"},
		archEntry{name: "big.txt", body: strings.Repeat("x", 2048)}))
	in.MaxBytes = 1024
	_, _, err := BuildZip(t.Context(), in)
	wantRefusal(t, err, "archive over 1024 bytes")
}

func TestBuildZipLicenseRules(t *testing.T) {
	const mp = "example.com/m/tools"
	gomod := archEntry{name: "tools/go.mod", body: "module " + mp + "\n"}
	rootLicense := func(context.Context) ([]byte, error) { return []byte("root licence\n"), nil }

	t.Run("subdir module gets the root LICENSE", func(t *testing.T) {
		in := buildInput(t, mp, "tools", fakeArchive(t, archEntry{name: "tools/", mode: fs.ModeDir | 0o755}, gomod))
		in.License = rootLicense
		path, _, err := BuildZip(t.Context(), in)
		if err != nil {
			t.Fatal(err)
		}
		got := zipFiles(t, path)
		if got[mp+"@v1.0.0/LICENSE"] != "root licence\n" || len(got) != 2 {
			t.Fatalf("zip = %v", got)
		}
	})
	t.Run("own LICENSE wins", func(t *testing.T) {
		in := buildInput(t, mp, "tools", fakeArchive(t, gomod, archEntry{name: "tools/LICENSE", body: "own\n"}))
		in.License = func(context.Context) ([]byte, error) { t.Fatal("License called"); return nil, nil }
		path, _, err := BuildZip(t.Context(), in)
		if err != nil {
			t.Fatal(err)
		}
		if got := zipFiles(t, path); got[mp+"@v1.0.0/LICENSE"] != "own\n" {
			t.Fatalf("zip = %v", got)
		}
	})
	t.Run("a LICENSE symlink suppresses it and is dropped", func(t *testing.T) {
		in := buildInput(t, mp, "tools", fakeArchive(t, gomod,
			archEntry{name: "tools/LICENSE", body: "../LICENSE", mode: fs.ModeSymlink | 0o777}))
		in.License = func(context.Context) ([]byte, error) { t.Fatal("License called"); return nil, nil }
		path, _, err := BuildZip(t.Context(), in)
		if err != nil {
			t.Fatal(err)
		}
		if got := zipFiles(t, path); len(got) != 1 {
			t.Fatalf("zip = %v, want go.mod only", got)
		}
	})
	t.Run("root LICENSE over 16 MiB is a refusal", func(t *testing.T) {
		in := buildInput(t, mp, "tools", fakeArchive(t, gomod))
		in.License = func(context.Context) ([]byte, error) {
			return nil, fmt.Errorf("LICENSE is 17 MiB: %w", gitmirror.ErrTooLarge)
		}
		_, _, err := BuildZip(t.Context(), in)
		wantRefusal(t, err, "LICENSE over 16 MiB")
	})
	t.Run("absent root LICENSE (missing or a directory)", func(t *testing.T) {
		in := buildInput(t, mp, "tools", fakeArchive(t, gomod))
		path, _, err := BuildZip(t.Context(), in)
		if err != nil {
			t.Fatal(err)
		}
		if got := zipFiles(t, path); len(got) != 1 {
			t.Fatalf("zip = %v, want go.mod only", got)
		}
	})
	t.Run("other License errors are returned as is", func(t *testing.T) {
		boom := errors.New("boom")
		in := buildInput(t, mp, "tools", fakeArchive(t, gomod))
		in.License = func(context.Context) ([]byte, error) { return nil, boom }
		_, _, err := BuildZip(t.Context(), in)
		if !errors.Is(err, boom) {
			t.Fatalf("err = %v, want boom", err)
		}
	})
}

func TestBuildZipCreateErrorsRefuse(t *testing.T) {
	in := buildInput(t, "example.com/m", "", fakeArchive(t,
		archEntry{name: "go.mod", body: "module example.com/m\n"},
		archEntry{name: "a.go", body: "package m\n"},
		archEntry{name: "A.go", body: "package m\n"}))
	_, _, err := BuildZip(t.Context(), in)
	wantRefusal(t, err, "zip: ")
}

func TestBuildZipIOErrorRetries(t *testing.T) {
	archive := fakeArchive(t,
		archEntry{name: "go.mod", body: "module example.com/m\n"},
		archEntry{name: "a.go", body: "package m\n"})
	t.Run("module zip writer", func(t *testing.T) {
		in := buildInput(t, "example.com/m", "", archive)
		in.wrapZipWriter = func(io.Writer) io.Writer { return failingWriter{} }
		_, _, err := BuildZip(t.Context(), in)
		var r *RefusalError
		if errors.As(err, &r) || !errors.Is(err, syscall.ENOSPC) {
			t.Fatalf("err = %v, want ENOSPC and no refusal", err)
		}
	})
	t.Run("archive writer", func(t *testing.T) {
		in := buildInput(t, "example.com/m", "", func(_ context.Context, w io.Writer) error {
			return syscall.ENOSPC // as ArchiveModuleZip returns a writer error
		})
		_, _, err := BuildZip(t.Context(), in)
		var r *RefusalError
		if errors.As(err, &r) || !errors.Is(err, syscall.ENOSPC) {
			t.Fatalf("err = %v, want ENOSPC and no refusal", err)
		}
	})
	t.Run("git archive failure", func(t *testing.T) {
		in := buildInput(t, "example.com/m", "", func(context.Context, io.Writer) error {
			return fmt.Errorf("%w: exit 128", gitmirror.ErrArchiveFailed)
		})
		_, _, err := BuildZip(t.Context(), in)
		var r *RefusalError
		if errors.As(err, &r) || !errors.Is(err, gitmirror.ErrArchiveFailed) {
			t.Fatalf("err = %v, want ErrArchiveFailed as is", err)
		}
	})
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, syscall.ENOSPC }

func TestBuildZipNoTempLeft(t *testing.T) {
	ok := fakeArchive(t, archEntry{name: "go.mod", body: "module example.com/m\n"})
	collide := fakeArchive(t, archEntry{name: "go.mod", body: "module example.com/m\n"},
		archEntry{name: "a.go"}, archEntry{name: "A.go"})
	for name, c := range map[string]struct {
		archive func(context.Context, io.Writer) error
		max     int64
		ok      bool
	}{
		"success": {ok, MaxArchiveBytes, true},
		"cap":     {ok, 10, false},
		"refusal": {collide, MaxArchiveBytes, false},
	} {
		t.Run(name, func(t *testing.T) {
			in := buildInput(t, "example.com/m", "", c.archive)
			in.MaxBytes = c.max
			path, res, err := BuildZip(t.Context(), in)
			if (err == nil) != c.ok {
				t.Fatalf("err = %v", err)
			}
			ents, rerr := os.ReadDir(in.TmpDir)
			if rerr != nil {
				t.Fatal(rerr)
			}
			if !c.ok {
				if len(ents) != 0 || path != "" {
					t.Fatalf("left %v, path %q", ents, path)
				}
				return
			}
			if len(ents) != 1 || in.TmpDir+"/"+ents[0].Name() != path {
				t.Fatalf("TmpDir holds %v, path %q", ents, path)
			}
			st, err := os.Stat(path)
			if err != nil || st.Size() != res.Size || len(res.SHA256) != 64 ||
				!strings.HasPrefix(res.ZipHash, "h1:") || !strings.HasPrefix(res.ModHash, "h1:") {
				t.Fatalf("res = %+v, stat %v %v", res, st, err)
			}
		})
	}
}

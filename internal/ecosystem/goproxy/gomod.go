package goproxy

import (
	"bytes"
	"errors"
	"fmt"
	"go/version"
	"path"
	"strings"

	"golang.org/x/mod/modfile"
	"golang.org/x/mod/module"
	"golang.org/x/mod/semver"

	"github.com/radiergummi/tspackages/internal/gitmirror"
	"github.com/radiergummi/tspackages/internal/resolve"
)

const (
	maxGo      = "go1.27.4" // the go line of tspackages' go.mod
	MaxGoMod   = 16 << 20   // codehost.MaxGoMod
	MaxLICENSE = 16 << 20   // codehost.MaxLICENSE
)

// Module is a modules entry of a git source: Path without a major suffix,
// its Remote, and Dir, the path's directory in the repository
// (coderepo.go:newCodeRepo's codeDir). It serves Path and every Path/vN.
type Module struct{ Path, Remote, Dir string }

// RefusalError is a build failure derived from the commit's content. It is
// final: the version is reported and not retried for the process's life.
type RefusalError struct{ Reason string }

func (e *RefusalError) Error() string { return e.Reason }

// TagVersion returns the version a tag names for a module with tag prefix
// prefix (dir+"/" or "") requested at pathMajor ("" or "/vN"), as
// codeRepo.Versions accepts it: the rest of the tag is a canonical semantic
// version, not a pseudo-version, of pathMajor's major version. Tags that
// codeRepo.Versions would list as +incompatible are not versions here.
func TagVersion(tag, prefix, pathMajor string) (string, bool) {
	if !strings.HasPrefix(tag, prefix) {
		return "", false
	}
	v := tag[len(prefix):]
	if v == "" || v != semver.Canonical(v) || module.IsPseudoVersion(v) || module.CheckPathMajor(v, pathMajor) != nil {
		return "", false
	}
	return v, true
}

// Found is where a module's go.mod was found at a commit.
type Found struct {
	Dir   string // the zip's directory, d or d/vN
	GoMod []byte
}

const reasonGoModTooLarge = "go.mod over 16 MiB"

// findModule finds modPath's go.mod at a commit as coderepo.go:codeRepo.findDir
// does, then applies the two stricter rules: a go.mod must exist (no
// LegacyGoMod, hence no +incompatible) and must declare modPath exactly, not
// only its major suffix. modPath is mod.Path or mod.Path+"/vN".
//
// read returns the file at the commit, wrapping resolve.ErrNotFound when it
// is absent and gitmirror.ErrTooLarge over MaxGoMod. A non-empty reason is a
// skip; a go.mod over MaxGoMod is a *RefusalError. With either, f.Dir is the
// directory concerned and f.GoMod is nil. Any other error is read's.
func findModule(read func(file string) ([]byte, error), mod Module, modPath string) (f Found, reason string, err error) {
	pathMajor, err := requestedMajor(mod.Path, modPath)
	if err != nil {
		return Found{}, "", err
	}
	d := mod.Dir

	gomod1, ok1, err := readGoMod(read, d)
	if err != nil {
		return Found{Dir: d}, "", err
	}
	mpath1 := modfile.ModulePath(gomod1)
	// findDir also accepts canReplaceMismatchedVersionDueToBug paths, which
	// are gopkg.in paths only; config rejects those as module entries.
	found1 := ok1 && isMajor(mpath1, pathMajor)

	// findDir looks at d/vN/go.mod only when the repository root isn't the
	// whole module path; a Module's Path has no major suffix, so for P/vN it
	// never is.
	if pathMajor != "" {
		dir2 := path.Join(d, pathMajor[1:])
		gomod2, ok2, err := readGoMod(read, dir2)
		if err != nil {
			return Found{Dir: dir2}, "", err
		}
		mpath2 := modfile.ModulePath(gomod2)
		found2 := ok2 && isMajor(mpath2, pathMajor)
		if found1 && found2 {
			shown := d
			if shown == "" {
				shown = "."
			}
			return Found{Dir: d}, fmt.Sprintf("go.mod found in both %s and %s/%s", shown, shown, pathMajor[1:]), nil
		}
		if found2 {
			return declares(dir2, gomod2, mpath2, modPath)
		}
		if ok2 {
			// findDir: "has non-.../vN module path".
			return declares(dir2, gomod2, mpath2, modPath)
		}
	}

	if found1 {
		return declares(d, gomod1, mpath1, modPath)
	}
	if ok1 {
		// findDir: "has post-vN module path". A v2+ tag on the unsuffixed
		// module is what cmd/go would serve as +incompatible if it had no
		// go.mod; tspackages never does.
		if pathMajor != "" && mpath1 == mod.Path {
			return Found{Dir: d}, "major version not in the module path", nil
		}
		return declares(d, gomod1, mpath1, modPath)
	}
	// findDir serves a root v0/v1 module without go.mod with LegacyGoMod;
	// tspackages doesn't.
	return Found{Dir: d}, "no go.mod", nil
}

// declares returns the go.mod found in dir when it declares modPath, else
// the skip reason "module declares its path as <mpath>", the go command's
// later error.
func declares(dir string, gomod []byte, mpath, modPath string) (Found, string, error) {
	if mpath == modPath {
		return Found{Dir: dir, GoMod: gomod}, "", nil
	}
	if mpath == "" {
		mpath = `""`
	}
	return Found{Dir: dir}, "module declares its path as " + mpath, nil
}

// requestedMajor returns modPath's major suffix ("" or "/vN") when modPath
// is base or base+"/vN" (N >= 2).
func requestedMajor(base, modPath string) (string, error) {
	if modPath == base {
		return "", nil
	}
	prefix, pathMajor, ok := module.SplitPathVersion(modPath)
	if !ok || prefix != base || !strings.HasPrefix(pathMajor, "/") {
		return "", fmt.Errorf("goproxy: %s is not a path of module %s", modPath, base)
	}
	return pathMajor, nil
}

// readGoMod reads dir/go.mod: ok is false when it is absent, and a file
// over MaxGoMod is a *RefusalError.
func readGoMod(read func(string) ([]byte, error), dir string) (data []byte, ok bool, err error) {
	data, err = read(path.Join(dir, "go.mod"))
	switch {
	case err == nil:
		return data, true, nil
	case errors.Is(err, resolve.ErrNotFound):
		return nil, false, nil
	case errors.Is(err, gitmirror.ErrTooLarge):
		return nil, false, &RefusalError{Reason: reasonGoModTooLarge}
	default:
		return nil, false, err
	}
}

// isMajor is coderepo.go:isMajor: whether module path mpath is compatible
// with the requested pathMajor ("", "/vN" or gopkg.in's ".vN").
func isMajor(mpath, pathMajor string) bool {
	if mpath == "" {
		return false
	}
	_, mpathMajor, ok := module.SplitPathVersion(mpath)
	if !ok {
		return false
	}
	if pathMajor == "" {
		switch module.PathMajorPrefix(mpathMajor) {
		case "", "v0", "v1":
			return true
		default:
			return false
		}
	}
	if mpathMajor == "" {
		return false
	}
	return pathMajor[1:] == mpathMajor[1:]
}

// checkGoDirective returns a refusal reason for a go.mod that ParseLax
// rejects or whose go directive is unparseable or newer than maxGo, the
// toolchain whose rules the zip follows (coderepo.go:codeRepo.Zip refuses a
// too-new module with gover.TooNewError). A missing go line is fine.
func checkGoDirective(gomod []byte) string {
	f, err := modfile.ParseLax("go.mod", gomod, nil)
	if err != nil {
		if v, ok := badGoLine(gomod, err); ok {
			return "unparseable go directive " + v
		}
		return "unparseable go.mod: " + err.Error()
	}
	if f.Go == nil {
		return ""
	}
	v := f.Go.Version
	if !version.IsValid("go" + v) {
		return "unparseable go directive " + v
	}
	if version.Compare("go"+v, maxGo) > 0 {
		return "go " + v + " is newer than " + maxGo + "; upgrade tspackages"
	}
	return ""
}

// badGoLine returns the argument of a "go" line that ParseLax rejected and
// that isn't a valid Go version.
func badGoLine(gomod []byte, err error) (string, bool) {
	var errs modfile.ErrorList
	if !errors.As(err, &errs) {
		return "", false
	}
	lines := bytes.Split(gomod, []byte("\n"))
	for _, e := range errs {
		if e.Pos.Line < 1 || e.Pos.Line > len(lines) {
			continue
		}
		line, _, _ := bytes.Cut(lines[e.Pos.Line-1], []byte("//"))
		fields := strings.Fields(string(line))
		if len(fields) == 2 && fields[0] == "go" && !version.IsValid("go"+fields[1]) {
			return fields[1], true
		}
	}
	return "", false
}

// retracted returns the retraction intervals of gomod, read with ParseLax as
// coderepo.go:codeRepo.retractedVersions does; nil on any error.
func retracted(gomod []byte) []modfile.VersionInterval {
	f, err := modfile.ParseLax("go.mod", gomod, nil)
	if err != nil || len(f.Retract) == 0 {
		return nil
	}
	out := make([]modfile.VersionInterval, 0, len(f.Retract))
	for _, r := range f.Retract {
		out = append(out, r.VersionInterval)
	}
	return out
}

package pypi

import (
	"bytes"
	"errors"
	"fmt"
	"path"
	"slices"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/radiergummi/tspackages/internal/gitmirror"
	"github.com/radiergummi/tspackages/internal/resolve"
)

// Skip reasons, shown on the status page.
const (
	skipNoProject    = "no [project] table"
	skipDynamic      = "version is dynamic; publish it through a storage source"
	skipBadVersion   = "invalid version"
	skipNotPackage   = "not a package (tool.uv.package = false or no [build-system])"
	skipBadName      = "name missing or invalid"
	skipOutsideFile  = "readme or license file is outside the package directory, so the sdist cannot build"
	skipMissingFile  = "readme or license file does not exist"
	skipNotRegular   = "readme or license file is not a regular file (a symlink?), so the sdist cannot hold it"
	skipLargeFile    = "readme or license file is larger than 1 MiB"
	skipBadPath      = "path starts with \"-\" or holds a newline, carriage return or NUL, which tspackages does not pass to git"
	skipBadPyproject = "pyproject.toml does not parse"
)

// Package is a Python project found in a repository at one commit, read from
// its pyproject.toml without running anything.
type Package struct {
	Dir     string  // "" for the repository root
	Name    string  // normalised
	Version Version // valid when Skip is ""
	Project map[string]any
	Readme  string   // repository path of the readme file, "" if none
	Exclude []string // workspace member directories, for a workspace root
	Skip    string   // why the package cannot be served; "" = servable
}

// errNotRegular is what a DiscoverPackages read returns for a path that is
// not a regular file (a symlink); such a file is refused, not read.
var errNotRegular = errors.New("not a regular file")

// errBadPath is what a DiscoverPackages read returns for a path that is not
// passed to git because of its characters; the package is refused.
var errBadPath = errors.New("path starts with \"-\" or holds a newline, carriage return or NUL")

// errBadPyproject marks a pyproject.toml that does not parse.
var errBadPyproject = errors.New("pyproject.toml does not parse")

// maxPyprojects caps the pyproject.toml files discovery reads at a commit
// (the root's and the workspace members'): each costs git runs, and a tree
// of a few objects can name thousands.
const maxPyprojects = 1000

var errTooManyPyprojects = fmt.Errorf("more than %d pyproject.toml files to read", maxPyprojects)

// DiscoverPackages finds the packages of a repository: the root
// pyproject.toml's project and, for a uv workspace, each member directory
// (from dirs, the directories holding a pyproject.toml) with a
// pyproject.toml that has a [project] table. read returns a file's content,
// an error wrapping resolve.ErrNotFound, errNotRegular, errBadPath or
// gitmirror.ErrTooLarge, or any other error, which fails the discovery
// (content problems are Package.Skip instead). More than maxPyprojects
// files to read is errTooManyPyprojects. A repository without a root
// pyproject.toml has none.
func DiscoverPackages(read func(path string) ([]byte, error), dirs []string) ([]Package, error) {
	rootDoc, err := readPyproject(read, "pyproject.toml")
	switch {
	case errors.Is(err, resolve.ErrNotFound):
		return nil, nil
	case errors.Is(err, errBadPyproject):
		return []Package{{Skip: skipBadPyproject}}, nil
	case err != nil:
		return nil, err
	}
	var members []string
	if ws, ok := table(rootDoc, "tool", "uv", "workspace"); ok {
		include, exclude := stringList(ws["members"]), stringList(ws["exclude"])
		for _, d := range dirs {
			if matchAny(include, d) && !matchAny(exclude, d) {
				members = append(members, d)
			}
		}
	}
	if len(members) >= maxPyprojects {
		return nil, errTooManyPyprojects
	}
	var memberPkgs []Package
	var memberDirs []string // directories that are members: they hold a pyproject.toml
	for _, d := range members {
		doc, err := readPyproject(read, d+"/pyproject.toml")
		switch {
		case errors.Is(err, resolve.ErrNotFound):
			continue // a matched directory that is not a project
		case errors.Is(err, errBadPyproject):
			memberDirs = append(memberDirs, d)
			memberPkgs = append(memberPkgs, Package{Dir: d, Skip: skipBadPyproject})
			continue
		case errors.Is(err, errBadPath):
			memberDirs = append(memberDirs, d)
			memberPkgs = append(memberPkgs, Package{Dir: d, Skip: skipBadPath})
			continue
		case err != nil:
			return nil, err
		}
		memberDirs = append(memberDirs, d)
		if _, ok := doc["project"]; ok {
			p, err := evaluate(read, d, doc)
			if err != nil {
				return nil, err
			}
			memberPkgs = append(memberPkgs, p)
		}
	}
	var pkgs []Package
	if _, ok := rootDoc["project"]; ok {
		root, err := evaluate(read, "", rootDoc)
		if err != nil {
			return nil, err
		}
		root.Exclude = memberDirs
		pkgs = append(pkgs, root)
	}
	return append(pkgs, memberPkgs...), nil
}

func readPyproject(read func(string) ([]byte, error), p string) (map[string]any, error) {
	b, err := read(p)
	if errors.Is(err, errNotRegular) || errors.Is(err, gitmirror.ErrTooLarge) {
		return nil, fmt.Errorf("%s: %w: %w", p, errBadPyproject, err)
	}
	if err != nil {
		return nil, err
	}
	var doc map[string]any
	if _, err := toml.NewDecoder(bytes.NewReader(b)).Decode(&doc); err != nil {
		return nil, fmt.Errorf("%s: %w: %w", p, errBadPyproject, err)
	}
	return doc, nil
}

// evaluate reads one package's [project] table and decides whether it can be
// served; an error is a file that could not be read.
func evaluate(read func(string) ([]byte, error), dir string, doc map[string]any) (Package, error) {
	p := evaluateProject(dir, doc)
	if p.Skip != "" {
		return p, nil
	}
	return p, checkFiles(read, &p)
}

// evaluateProject decides from the [project] table alone.
func evaluateProject(dir string, doc map[string]any) Package {
	p := Package{Dir: dir}
	proj, ok := doc["project"].(map[string]any)
	if !ok {
		p.Skip = skipNoProject
		return p
	}
	p.Project = proj
	rawName, _ := proj["name"].(string)
	name, err := Normalize(rawName)
	if err != nil {
		p.Skip = skipBadName
		return p
	}
	p.Name = name
	if uv, ok := table(doc, "tool", "uv"); ok {
		if pkg, ok := uv["package"].(bool); ok && !pkg {
			p.Skip = skipNotPackage
			return p
		}
	}
	if _, ok := doc["build-system"]; !ok {
		p.Skip = skipNotPackage
		return p
	}
	rawVersion, ok := proj["version"].(string)
	if !ok {
		if slices.Contains(stringList(proj["dynamic"]), "version") {
			p.Skip = skipDynamic
		} else {
			p.Skip = skipBadVersion
		}
		return p
	}
	if p.Version, err = ParseVersion(rawVersion); err != nil {
		p.Skip = skipBadVersion
	}
	return p
}

// checkFiles refuses a package whose readme or license file cannot go into
// the sdist, and records the readme's path otherwise.
func checkFiles(read func(string) ([]byte, error), p *Package) error {
	for _, f := range referencedFiles(p.Project) {
		repo, inside := inDir(p.Dir, f)
		if !inside {
			p.Skip = skipOutsideFile
			return nil
		}
		switch _, err := read(repo); {
		case errors.Is(err, resolve.ErrNotFound):
			p.Skip = skipMissingFile
			return nil
		case errors.Is(err, errNotRegular):
			p.Skip = skipNotRegular
			return nil
		case errors.Is(err, errBadPath):
			p.Skip = skipBadPath
			return nil
		case errors.Is(err, gitmirror.ErrTooLarge):
			p.Skip = skipLargeFile
			return nil
		case err != nil:
			return err
		}
	}
	if f := readmeFile(p.Project); f != "" {
		p.Readme, _ = inDir(p.Dir, f)
	}
	return nil
}

// referencedFiles are the files [project] names by path: the readme and an
// old-style license file.
func referencedFiles(proj map[string]any) []string {
	var out []string
	if f := readmeFile(proj); f != "" {
		out = append(out, f)
	}
	if lic, ok := proj["license"].(map[string]any); ok {
		if f, ok := lic["file"].(string); ok {
			out = append(out, f)
		}
	}
	return out
}

func readmeFile(proj map[string]any) string {
	switch r := proj["readme"].(type) {
	case string:
		return r
	case map[string]any:
		f, _ := r["file"].(string)
		return f
	}
	return ""
}

// inDir resolves a path written relative to dir and reports whether it stays
// inside dir.
func inDir(dir, rel string) (string, bool) {
	if path.IsAbs(rel) {
		return "", false
	}
	joined := path.Join(dir, rel)
	if dir == "" {
		return joined, joined != ".." && !strings.HasPrefix(joined, "../")
	}
	return joined, strings.HasPrefix(joined, dir+"/")
}

func table(doc map[string]any, keys ...string) (map[string]any, bool) {
	cur := doc
	for _, k := range keys {
		next, ok := cur[k].(map[string]any)
		if !ok {
			return nil, false
		}
		cur = next
	}
	return cur, true
}

func stringList(v any) []string {
	items, _ := v.([]any)
	var out []string
	for _, it := range items {
		if s, ok := it.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// matchAny matches a directory against workspace globs (path.Match per
// pattern; "**" is not supported and matches nothing).
func matchAny(globs []string, dir string) bool {
	for _, g := range globs {
		if strings.Contains(g, "**") {
			continue
		}
		if ok, err := path.Match(strings.TrimSuffix(g, "/"), dir); err == nil && ok {
			return true
		}
	}
	return false
}

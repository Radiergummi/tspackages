// Package maven serves Maven 2 repositories: artifact files, checksums and
// maven-metadata.xml, for Maven and Gradle clients.
package maven

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
)

// MaxPart is the longest group, artifact, version or file name in bytes: the
// storage key rule (storage.EscapeSegment must fit storage.MaxSegment).
const MaxPart = 156

const (
	// maxSegments is the most segments of a path, as requested and in its
	// canonical form (a dotted group segment counts once per part).
	maxSegments   = 64
	maxClassifier = 64
	maxExtension  = 32
	metadataFile  = "maven-metadata.xml"
	snapshotSfx   = "-SNAPSHOT"
)

var (
	groupSegRE   = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
	artifactRE   = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)
	extensionRE  = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)
	classifierRE = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
	timestampRE  = regexp.MustCompile(`^\d{8}\.\d{6}-\d+`)
	checksums    = []string{"sha1", "md5", "sha256", "sha512"}
)

// Coords are a Maven coordinate in its exact case.
type Coords struct{ Group, Artifact, Version string }

// Key is the lowercased "groupId:artifactId" that claims and capability rules
// match against.
func (c Coords) Key() string { return strings.ToLower(c.Group + ":" + c.Artifact) }

// Kind says what a request path addresses.
type Kind int

const (
	KindFile             Kind = iota // an artifact file
	KindArtifactMetadata             // <group>/<artifact>/maven-metadata.xml
	KindVersionMetadata              // <group>/<artifact>/<version>-SNAPSHOT/maven-metadata.xml
)

// Path is a parsed repository path.
type Path struct {
	Kind     Kind
	Coords   Coords // artifact-level reading; Version is empty for KindArtifactMetadata
	File     string // the file name without a checksum suffix
	Checksum string // "", "sha1", "md5", "sha256" or "sha512"
}

// Snapshot reports whether p's version ends in "-SNAPSHOT".
func (p Path) Snapshot() bool { return IsSnapshot(p.Coords.Version) }

// Group is the group-level reading of a KindArtifactMetadata path:
// Coords.Group + "." + Coords.Artifact.
func (p Path) Group() string { return p.Coords.Group + "." + p.Coords.Artifact }

// Immutable reports whether p is a file that never changes: a release file,
// or a timestamped SNAPSHOT file. Metadata is never immutable.
func (p Path) Immutable() bool {
	return p.Kind == KindFile && (!p.Snapshot() || !strings.HasPrefix(p.File, p.Coords.Artifact+"-"+p.Coords.Version))
}

// ParsePath parses a URL-decoded repository path (what follows "/maven/").
// Any error means the path names nothing: the caller answers 404.
func ParsePath(p string) (Path, error) {
	tooMany := fmt.Errorf("more than %d path segments", maxSegments)
	if strings.Count(p, "/") >= maxSegments {
		return Path{}, tooMany
	}
	out, err := parsePath(p)
	if err == nil && strings.Count(out.String(), "/") >= maxSegments {
		return Path{}, tooMany
	}
	return out, err
}

func parsePath(p string) (Path, error) {
	segs := strings.Split(p, "/")
	var out Path
	last := segs[len(segs)-1]
	for _, c := range checksums {
		if name, ok := strings.CutSuffix(last, "."+c); ok {
			out.Checksum, last = c, name
			break
		}
	}
	segs[len(segs)-1] = last
	for _, s := range segs {
		if s == "" || s[0] == '.' || len(s) > MaxPart {
			return Path{}, fmt.Errorf("invalid path segment %q", s)
		}
	}
	out.File = last
	n := len(segs)
	if last == metadataFile {
		if n < 3 {
			return Path{}, errors.New("metadata path too short")
		}
		if n >= 4 && strings.HasSuffix(segs[n-2], snapshotSfx) {
			out.Kind = KindVersionMetadata
			out.Coords = Coords{strings.Join(segs[:n-3], "."), segs[n-3], segs[n-2]}
		} else {
			out.Kind = KindArtifactMetadata
			out.Coords = Coords{strings.Join(segs[:n-2], "."), segs[n-2], ""}
		}
		return out, validate(out.Coords)
	}
	if n < 4 {
		return Path{}, errors.New("file path needs group, artifact, version and file")
	}
	out.Coords = Coords{strings.Join(segs[:n-3], "."), segs[n-3], segs[n-2]}
	if err := validate(out.Coords); err != nil {
		return Path{}, err
	}
	if err := validateFile(out.Coords, last); err != nil {
		return Path{}, err
	}
	return out, nil
}

// validate checks the coordinate rules; an empty Version is skipped.
func validate(c Coords) error {
	if len(c.Group) > MaxPart {
		return errors.New("group too long")
	}
	for s := range strings.SplitSeq(c.Group, ".") {
		if !groupSegRE.MatchString(s) {
			return fmt.Errorf("invalid groupId segment %q", s)
		}
	}
	if !artifactRE.MatchString(c.Artifact) {
		return fmt.Errorf("invalid artifactId %q", c.Artifact)
	}
	if c.Version == "" {
		return nil
	}
	for _, r := range c.Version {
		if r <= ' ' || r >= 0x7f || r == '/' || r == '\\' || r == ':' {
			return fmt.Errorf("invalid version %q", c.Version)
		}
	}
	return nil
}

// validateFile checks that name is "<artifact>-<version>[-<classifier>].<ext>",
// with a timestamped SNAPSHOT version in place of <version> when the
// directory version ends in "-SNAPSHOT".
func validateFile(c Coords, name string) error {
	prefix := c.Artifact + "-"
	rest, ok := strings.CutPrefix(name, prefix+c.Version)
	if !ok {
		base, snap := strings.CutSuffix(c.Version, snapshotSfx)
		if !snap {
			return fmt.Errorf("file %q does not start with %q", name, prefix+c.Version)
		}
		stamped, ok := strings.CutPrefix(name, prefix+base+"-")
		if !ok {
			return fmt.Errorf("file %q does not start with %q", name, prefix+c.Version)
		}
		m := timestampRE.FindString(stamped)
		if m == "" {
			return fmt.Errorf("file %q has no SNAPSHOT timestamp", name)
		}
		rest = stamped[len(m):]
	}
	if classifier, after, ok := strings.Cut(rest, "."); ok && strings.HasPrefix(classifier, "-") {
		classifier = classifier[1:]
		if !classifierRE.MatchString(classifier) || len(classifier) > maxClassifier {
			return fmt.Errorf("invalid classifier in %q", name)
		}
		rest = "." + after
	}
	ext, ok := strings.CutPrefix(rest, ".")
	if !ok || !extensionRE.MatchString(ext) || ext[0] == '.' || len(ext) > maxExtension {
		return fmt.Errorf("invalid extension in %q", name)
	}
	if last := ext[strings.LastIndexByte(ext, '.')+1:]; slices.Contains(checksums, last) {
		return fmt.Errorf("%q is a checksum of a checksum", name)
	}
	return nil
}

// String is the canonical repository path of p, the form ParsePath accepts.
func (p Path) String() string {
	dirs := strings.ReplaceAll(p.Coords.Group, ".", "/") + "/" + p.Coords.Artifact
	if p.Coords.Version != "" {
		dirs += "/" + p.Coords.Version
	}
	s := dirs + "/" + p.File
	if p.Checksum != "" {
		s += "." + p.Checksum
	}
	return s
}

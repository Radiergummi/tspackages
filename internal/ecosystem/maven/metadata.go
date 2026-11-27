package maven

import (
	"bytes"
	"cmp"
	"encoding/xml"
	"maps"
	"slices"
	"strconv"
	"time"
)

// lastUpdatedFormat is the layout of lastUpdated and updated (UTC).
const lastUpdatedFormat = "20060102150405"

// VersionInfo is a version listed in artifact-level metadata: one whose POM
// is stored, POM being when its newest POM was.
type VersionInfo struct {
	Version string
	POM     time.Time
}

// SnapshotFile is a timestamped file of a SNAPSHOT version. Value is its
// timestamped version ("1.0-20261123.101010-3"), Updated when it was stored.
type SnapshotFile struct {
	Classifier, Extension, Value string
	Updated                      time.Time
}

// metaWriter writes indented metadata elements.
type metaWriter struct{ bytes.Buffer }

func (w *metaWriter) open(depth int, name string) {
	w.indent(depth)
	w.WriteString("<" + name + ">\n")
}

func (w *metaWriter) close(depth int, name string) {
	w.indent(depth)
	w.WriteString("</" + name + ">\n")
}

func (w *metaWriter) elem(depth int, name, text string) {
	w.indent(depth)
	w.WriteString("<" + name + ">")
	_ = xml.EscapeText(w, []byte(text)) // writes to a bytes.Buffer never fail
	w.WriteString("</" + name + ">\n")
}

func (w *metaWriter) indent(depth int) {
	for range depth {
		w.WriteString("  ")
	}
}

const xmlHeader = `<?xml version="1.0" encoding="UTF-8"?>` + "\n"

// RenderArtifactMetadata renders <group>/<artifact>/maven-metadata.xml:
// versions ascending by CompareVersions, latest the highest of them, release
// the highest non-SNAPSHOT (left out when there is none), lastUpdated the
// newest POM time. The output depends only on the set of versions.
func RenderArtifactMetadata(group, artifact string, versions []VersionInfo) []byte {
	vs := slices.SortedFunc(slices.Values(versions), func(a, b VersionInfo) int {
		return cmp.Or(CompareVersions(a.Version, b.Version), cmp.Compare(a.Version, b.Version))
	})
	var latest, release string
	var updated time.Time
	for _, v := range vs {
		latest = v.Version
		if !IsSnapshot(v.Version) {
			release = v.Version
		}
		if v.POM.After(updated) {
			updated = v.POM
		}
	}
	w := &metaWriter{}
	w.WriteString(xmlHeader)
	w.open(0, "metadata")
	w.elem(1, "groupId", group)
	w.elem(1, "artifactId", artifact)
	w.open(1, "versioning")
	if latest != "" {
		w.elem(2, "latest", latest)
	}
	if release != "" {
		w.elem(2, "release", release)
	}
	w.open(2, "versions")
	for _, v := range vs {
		w.elem(3, "version", v.Version)
	}
	w.close(2, "versions")
	w.elem(2, "lastUpdated", updated.UTC().Format(lastUpdatedFormat))
	w.close(1, "versioning")
	w.close(0, "metadata")
	return w.Bytes()
}

// newerSnapshot orders timestamped files by build number, then timestamp,
// then Updated.
func newerSnapshot(a, b SnapshotFile) int {
	ta, _ := ParseTimestamped(a.Value)
	tb, _ := ParseTimestamped(b.Value)
	return cmp.Or(cmp.Compare(ta.Build, tb.Build), cmp.Compare(ta.Timestamp, tb.Timestamp), a.Updated.Compare(b.Updated))
}

// RenderVersionMetadata renders <group>/<artifact>/<version>/maven-metadata.xml
// for a SNAPSHOT version from its timestamped files: snapshot holds the
// timestamp and build number of the newest POM (left out before there is
// one), snapshotVersions the newest file per classifier and extension,
// ordered by classifier then extension, and lastUpdated the newest of
// their updated times.
func RenderVersionMetadata(group, artifact, version string, files []SnapshotFile) []byte {
	type ce struct{ classifier, extension string }
	newest := map[ce]SnapshotFile{}
	for _, f := range files {
		k := ce{f.Classifier, f.Extension}
		if cur, ok := newest[k]; !ok || newerSnapshot(f, cur) > 0 {
			newest[k] = f
		}
	}
	entries := slices.SortedFunc(maps.Values(newest), func(a, b SnapshotFile) int {
		return cmp.Or(cmp.Compare(a.Classifier, b.Classifier), cmp.Compare(a.Extension, b.Extension))
	})
	var updated time.Time
	for _, f := range entries {
		if f.Updated.After(updated) {
			updated = f.Updated
		}
	}
	w := &metaWriter{}
	w.WriteString(xmlHeader)
	w.WriteString(`<metadata modelVersion="1.1.0">` + "\n")
	w.elem(1, "groupId", group)
	w.elem(1, "artifactId", artifact)
	w.elem(1, "version", version)
	w.open(1, "versioning")
	if pom, ok := newest[ce{"", "pom"}]; ok {
		ts, _ := ParseTimestamped(pom.Value)
		w.open(2, "snapshot")
		w.elem(3, "timestamp", ts.Timestamp)
		w.elem(3, "buildNumber", strconv.Itoa(ts.Build))
		w.close(2, "snapshot")
	}
	w.elem(2, "lastUpdated", updated.UTC().Format(lastUpdatedFormat))
	w.open(2, "snapshotVersions")
	for _, f := range entries {
		w.open(3, "snapshotVersion")
		if f.Classifier != "" {
			w.elem(4, "classifier", f.Classifier)
		}
		w.elem(4, "extension", f.Extension)
		w.elem(4, "value", f.Value)
		w.elem(4, "updated", f.Updated.UTC().Format(lastUpdatedFormat))
		w.close(3, "snapshotVersion")
	}
	w.close(2, "snapshotVersions")
	w.close(1, "versioning")
	w.close(0, "metadata")
	return w.Bytes()
}

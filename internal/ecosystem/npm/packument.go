package npm

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"slices"
	"strings"
)

// BaseToken stands for "https://<host>/npm/" in rendered documents. A raw
// 0x01 byte cannot occur in valid JSON (encoders escape it as \u0001), so
// upstream data cannot forge the token. Documents carrying it are not valid
// JSON until Expand has run.
const BaseToken = "\x01base\x01"

// MaxVersionBytes caps one rendered version object.
const MaxVersionBytes = 4 << 20

const maxTopBytes = 1 << 20

// fullTopFields are the top-level fields of a source document that the full
// packument keeps. dist-tags, versions and time are written by DocWriter.
var fullTopFields = []string{"_id", "name", "description", "maintainers", "author", "repository", "homepage", "bugs", "license", "keywords"}

// droppedVersionFields are npm-internal leftovers removed from every version.
var droppedVersionFields = []string{"_resolved", "_from", "_shasum", "_where", "_args", "_inBundle", "_phantomChildren", "_requested", "_requiredBy", "_spec", "_location"}

// corgiVersionFields are kept in abbreviated version objects: arborist's
// pkgMetaKeys plus name, version, directories and dist.
var corgiVersionFields = []string{
	"name", "version", "directories", "dist",
	"dependencies", "peerDependencies", "peerDependenciesMeta", "optionalDependencies",
	"bundleDependencies", "acceptDependencies", "funding", "engines", "os", "cpu", "libc",
	"license", "_hasShrinkwrap", "hasInstallScript", "bin", "deprecated", "workspaces",
}

// distFields are the keys a rendered dist may have.
var distFields = []string{"tarball", "integrity", "shasum", "fileCount", "unpackedSize", "signatures", "npm-signature", "attestations"}

// Dist is the dist object of a rendered version; zero fields are omitted.
type Dist struct {
	Tarball, Integrity, Shasum string
	FileCount, UnpackedSize    int64
	Signatures, NPMSignature   json.RawMessage
	// AttestationsURL and AttestationsProvenance render as "attestations";
	// it is written only when AttestationsURL is set.
	AttestationsURL        string
	AttestationsProvenance json.RawMessage
}

// encString encodes s as a JSON string, leaving a leading BaseToken raw.
func encString(s string) []byte {
	rest, hasToken := strings.CutPrefix(s, BaseToken)
	b, _ := json.Marshal(rest)
	if !hasToken {
		return b
	}
	return append([]byte{'"'}, append([]byte(BaseToken), b[1:]...)...)
}

func compact(raw json.RawMessage) (json.RawMessage, error) {
	var b bytes.Buffer
	if err := json.Compact(&b, raw); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func (d Dist) fields() (map[string][]byte, error) {
	m := map[string][]byte{}
	if d.Tarball != "" {
		m["tarball"] = encString(d.Tarball)
	}
	if d.Integrity != "" {
		m["integrity"], _ = json.Marshal(d.Integrity)
	}
	if d.Shasum != "" {
		m["shasum"], _ = json.Marshal(d.Shasum)
	}
	if d.FileCount != 0 {
		m["fileCount"], _ = json.Marshal(d.FileCount)
	}
	if d.UnpackedSize != 0 {
		m["unpackedSize"], _ = json.Marshal(d.UnpackedSize)
	}
	for k, raw := range map[string]json.RawMessage{"signatures": d.Signatures, "npm-signature": d.NPMSignature} {
		if len(raw) == 0 {
			continue
		}
		c, err := compact(raw)
		if err != nil {
			return nil, fmt.Errorf("dist %s: %w", k, err)
		}
		m[k] = c
	}
	if d.AttestationsURL != "" {
		a := append([]byte(`{"url":`), encString(d.AttestationsURL)...)
		if len(d.AttestationsProvenance) > 0 {
			c, err := compact(d.AttestationsProvenance)
			if err != nil {
				return nil, fmt.Errorf("dist attestations: %w", err)
			}
			a = append(append(a, `,"provenance":`...), c...)
		}
		m["attestations"] = append(a, '}')
	}
	for k := range m {
		if !slices.Contains(distFields, k) {
			delete(m, k)
		}
	}
	return m, nil
}

// writeSorted writes fields as a JSON object with sorted keys.
func writeSorted(fields map[string][]byte) []byte {
	var b bytes.Buffer
	b.WriteByte('{')
	for i, k := range slices.Sorted(maps.Keys(fields)) {
		if i > 0 {
			b.WriteByte(',')
		}
		b.Write(encString(k))
		b.WriteByte(':')
		b.Write(fields[k])
	}
	b.WriteByte('}')
	return b.Bytes()
}

// RenderVersion renders one version object in full and abbreviated form. Keys
// are sorted so the bytes are stable across rebuilds. hasInstallScript is
// derived from scripts when the source lacks it, since npm only runs install
// scripts of lockfile entries that carry it.
func RenderVersion(obj map[string]json.RawMessage, d Dist) (full, corgi []byte, err error) {
	dist, err := d.fields()
	if err != nil {
		return nil, nil, err
	}
	fullF := map[string][]byte{"dist": writeSorted(dist)}
	corgiF := map[string][]byte{"dist": fullF["dist"]}
	for k, raw := range obj {
		if k == "dist" || slices.Contains(droppedVersionFields, k) {
			continue
		}
		c, err := compact(raw)
		if err != nil {
			return nil, nil, fmt.Errorf("version field %s: %w", k, err)
		}
		fullF[k] = c
		if slices.Contains(corgiVersionFields, k) {
			corgiF[k] = c
		}
	}
	if _, ok := fullF["hasInstallScript"]; !ok && hasInstallScripts(obj["scripts"]) {
		fullF["hasInstallScript"] = []byte("true")
		corgiF["hasInstallScript"] = []byte("true")
	}
	return writeSorted(fullF), writeSorted(corgiF), nil
}

func hasInstallScripts(raw json.RawMessage) bool {
	var scripts map[string]json.RawMessage
	if json.Unmarshal(raw, &scripts) != nil {
		return false
	}
	for _, k := range []string{"preinstall", "install", "postinstall"} {
		if _, ok := scripts[k]; ok {
			return true
		}
	}
	return false
}

// RenderDistTags renders the dist-tags route body.
func RenderDistTags(tags map[string]string) []byte {
	f := make(map[string][]byte, len(tags))
	for k, v := range tags {
		f[k], _ = json.Marshal(v)
	}
	return writeSorted(f)
}

// DocWriter streams a full and an abbreviated packument. Output order is
// {"versions":{...},<top fields>,"dist-tags":{...},"time":{...}}, so versions
// can stream before the tags are known.
type DocWriter struct {
	full, corgi io.Writer
	top         map[string]json.RawMessage
	topBytes    int
	started     bool
	err         error
	tokF, tokC  int
}

// NewDocWriter returns a writer rendering into full and corgi.
func NewDocWriter(full, corgi io.Writer) *DocWriter {
	return &DocWriter{full: full, corgi: corgi, top: map[string]json.RawMessage{}}
}

// Top buffers a top-level field of the source document; fields outside
// fullTopFields are ignored. More than 1 MiB of kept fields fails Close.
func (w *DocWriter) Top(key string, raw json.RawMessage) {
	if !slices.Contains(fullTopFields, key) {
		return
	}
	w.topBytes += len(raw)
	if w.topBytes > maxTopBytes && w.err == nil {
		w.err = errors.New("npm: top-level fields exceed 1 MiB")
	}
	w.top[key] = raw
}

func (w *DocWriter) write(isFull bool, b []byte) {
	if w.err != nil {
		return
	}
	out, tok := w.corgi, &w.tokC
	if isFull {
		out, tok = w.full, &w.tokF
	}
	*tok += bytes.Count(b, []byte(BaseToken))
	if _, err := out.Write(b); err != nil {
		w.err = err
	}
}

func (w *DocWriter) both(b []byte) {
	w.write(true, b)
	w.write(false, b)
}

// Version appends one rendered version to both documents.
func (w *DocWriter) Version(version string, full, corgi []byte) error {
	if len(full) > MaxVersionBytes || len(corgi) > MaxVersionBytes {
		return fmt.Errorf("npm: version %s exceeds %d bytes", version, MaxVersionBytes)
	}
	prefix := []byte(`{"versions":{`)
	if w.started {
		prefix = []byte(",")
	}
	w.started = true
	key := append(encString(version), ':')
	w.write(true, append(append(prefix, key...), full...))
	w.write(false, append(append(append([]byte(nil), prefix...), key...), corgi...))
	return w.err
}

// Close writes the buffered top fields, dist-tags and time.
func (w *DocWriter) Close(distTags map[string]string, times map[string]string) error {
	if w.err != nil {
		return w.err
	}
	if !w.started {
		w.both([]byte(`{"versions":{`))
	}
	w.both([]byte("}"))
	for _, k := range slices.Sorted(maps.Keys(w.top)) {
		c, err := compact(w.top[k])
		if err != nil {
			return fmt.Errorf("npm: top field %s: %w", k, err)
		}
		field := append(append(append([]byte(","), encString(k)...), ':'), c...)
		w.write(true, field)
		if k == "name" {
			w.write(false, field)
		}
	}
	if m, ok := times["modified"]; ok {
		w.write(false, append([]byte(`,"modified":`), encString(m)...))
	}
	tags := append([]byte(`,"dist-tags":`), RenderDistTags(distTags)...)
	w.both(tags)
	tf := make(map[string][]byte, len(times))
	for k, v := range times {
		tf[k] = encString(v)
	}
	w.both(append([]byte(`,"time":`), writeSorted(tf)...))
	w.both([]byte("}"))
	return w.err
}

// Tokens reports how many BaseTokens were written to each output.
func (w *DocWriter) Tokens() (full, corgi int) { return w.tokF, w.tokC }

// ExpandedSize is the length of a document of size bytes with tokens
// BaseTokens after Expand with base.
func ExpandedSize(size int64, tokens int, base string) int64 {
	return size + int64(tokens)*int64(len(base)-len(BaseToken))
}

type expander struct {
	w       io.Writer
	base    []byte
	pending []byte
}

// Expand replaces every BaseToken written through it with base. It holds at
// most len(BaseToken)-1 bytes between writes; Close writes them out (it does
// not close w).
func Expand(w io.Writer, base string) io.WriteCloser {
	return &expander{w: w, base: []byte(base)}
}

func (e *expander) Write(p []byte) (int, error) {
	data := append(slices.Clone(e.pending), p...)
	tok := []byte(BaseToken)
	for {
		i := bytes.Index(data, tok)
		if i < 0 {
			break
		}
		if _, err := e.w.Write(data[:i]); err != nil {
			return 0, err
		}
		if _, err := e.w.Write(e.base); err != nil {
			return 0, err
		}
		data = data[i+len(tok):]
	}
	keep := 0
	for k := min(len(tok)-1, len(data)); k > 0; k-- {
		if bytes.HasPrefix(tok, data[len(data)-k:]) {
			keep = k
			break
		}
	}
	if _, err := e.w.Write(data[:len(data)-keep]); err != nil {
		return 0, err
	}
	e.pending = append(e.pending[:0], data[len(data)-keep:]...)
	return len(p), nil
}

func (e *expander) Close() error {
	if len(e.pending) == 0 {
		return nil
	}
	_, err := e.w.Write(e.pending)
	e.pending = nil
	return err
}

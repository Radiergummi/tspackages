package apt

import (
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

const (
	// uploadReadTimeout bounds reading a PUT body.
	uploadReadTimeout = 10 * time.Minute
	// allowedMethods is the Allow header of every path under /apt/.
	allowedMethods = "GET, HEAD, PUT"
	immutableCache = "private, max-age=31536000, immutable"
	textType       = "text/plain; charset=utf-8"
)

// APT serves apt repositories under /apt/.
type APT struct {
	sources   []Source
	signer    *Signer
	maxUpload int64
	tmpDir    string
	log       *slog.Logger
	// createTemp creates a PUT spool: os.CreateTemp, replaced in tests.
	createTemp func(dir, pattern string) (*os.File, error)
}

var _ ecosystem.Ecosystem = (*APT)(nil)

// New returns the apt endpoint over sources. signer is nil when no source
// stores packages. Packages are capped at maxUpload bytes; PUT bodies are
// spooled in tmpDir, which must exist and be private.
func New(sources []Source, signer *Signer, maxUpload int64, tmpDir string, log *slog.Logger) *APT {
	if log == nil {
		log = slog.Default()
	}
	return &APT{sources: sources, signer: signer, maxUpload: maxUpload, tmpDir: tmpDir, log: log, createTemp: os.CreateTemp}
}

func (h *APT) Name() string { return ecoName }

// Mount registers /apt/{path...}.
func (h *APT) Mount(mux *http.ServeMux) {
	mux.HandleFunc("/apt/{path...}", h.serve)
}

func setSecurityHeaders(hd http.Header) {
	hd.Set("Cache-Control", "private, no-store")
	hd.Set("X-Content-Type-Options", "nosniff")
}

// problem answers an error with a plain-text body. An empty detail is the
// status text.
func problem(w http.ResponseWriter, status int, detail string) {
	if detail == "" {
		detail = strings.ToLower(http.StatusText(status))
	}
	w.Header().Set("Content-Type", textType)
	w.WriteHeader(status)
	_, _ = io.WriteString(w, detail+"\n") //nolint:gosec // text/plain with nosniff; never rendered as HTML
}

// entry collects what a request touched, for its log line and metrics.
type entry struct {
	pkg, source string
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

func (h *APT) serve(rw http.ResponseWriter, r *http.Request) {
	setSecurityHeaders(rw.Header())
	caller, ok := identity.FromContext(r.Context())
	if !ok {
		h.log.Warn("apt request without caller", "path", r.URL.Path, "status", http.StatusForbidden)
		metrics.ObserveRequest(ecoName, "none", http.StatusForbidden)
		problem(rw, http.StatusForbidden, "forbidden")
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
	if e.write {
		level = slog.LevelInfo
	}
	attrs := []any{"caller", caller.String(), "node", caller.NodeStableID, "package", e.pkg, "source", e.source, "method", r.Method, "path", r.URL.Path, "status", status}
	if e.write {
		attrs = append(attrs, "node_name", caller.NodeName)
	}
	h.log.Log(r.Context(), level, "apt request", attrs...)
	if e.aborted {
		// Headers are out: break the connection so the client sees a failed
		// transfer, not a short file.
		panic(http.ErrAbortHandler)
	}
}

func (h *APT) route(w http.ResponseWriter, r *http.Request, caller identity.Caller, e *entry) {
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodPut:
	default:
		w.Header().Set("Allow", allowedMethods)
		problem(w, http.StatusMethodNotAllowed, "this repository accepts GET, HEAD and PUT")
		return
	}
	put := r.Method == http.MethodPut
	p, err := ParsePath(strings.TrimPrefix(r.URL.Path, "/apt/"), put)
	if err != nil {
		problem(w, http.StatusNotFound, "")
		return
	}
	if put {
		h.upload(w, r, caller, e, p)
		return
	}
	acc := h.access(caller)
	if !acc.Any {
		problem(w, http.StatusForbidden, "forbidden: no apt read rule")
		return
	}
	if p.Kind == KindKey {
		h.key(w, r)
		return
	}
	if p.Kind == KindPreferences {
		h.preferences(w, r)
		return
	}
	src := h.source(p.Source)
	if src == nil {
		problem(w, http.StatusNotFound, "")
		return
	}
	e.source = src.Name()
	ctx := r.Context()
	var b Blob
	ctype, cache := textType, "no-cache"
	switch p.Kind {
	case KindRelease:
		b, err = src.Release(ctx, acc, p.Suite, p.Rel)
		if p.Rel == "Release.gpg" {
			ctype = "application/pgp-signature"
		}
	case KindDist:
		b, err = src.Dist(ctx, acc, p.Suite, p.Rel)
		if strings.HasSuffix(p.Rel, ".gz") {
			ctype = "application/gzip"
		}
	case KindByHash:
		b, err = src.ByHash(ctx, acc, p.Suite, p.Rel, p.Hash)
		ctype = "application/octet-stream"
	case KindPool:
		e.pkg = p.Deb.Name
		b, err = src.Pool(ctx, acc, p)
		ctype = "application/vnd.debian.binary-package"
	case KindKey, KindPreferences, KindUpload:
		// Answered above.
	}
	if err != nil {
		h.fail(w, r, err)
		return
	}
	if b.Immutable && (p.Kind == KindByHash || p.Kind == KindPool) {
		cache = immutableCache
	}
	h.serveBlob(w, r, e, b, ctype, cache)
}

// source returns the source called name, or nil.
func (h *APT) source(name string) Source {
	for _, s := range h.sources {
		if s.Name() == name {
			return s
		}
	}
	return nil
}

// access computes what caller may read.
func (h *APT) access(caller identity.Caller) ReadAccess {
	anyRule := authz.Allowed(caller.Rules, ecoName, "any", authz.Read, func(p, _ string) bool { return ValidPattern(p) })
	if !anyRule {
		h.logMalformed(caller)
	}
	return ReadAccess{
		Any:    anyRule,
		Name:   func(name string) bool { return authz.Allowed(caller.Rules, ecoName, name, authz.Read, Match) },
		Viewer: caller.NodeStableID,
	}
}

func (h *APT) key(w http.ResponseWriter, r *http.Request) {
	if h.signer == nil {
		problem(w, http.StatusNotFound, "")
		return
	}
	serveBytes(w, r, h.signer.PublicKey(), "application/pgp-keys")
}

func (h *APT) preferences(w http.ResponseWriter, r *http.Request) {
	var storage []Uploader
	for _, s := range h.sources {
		if u, ok := s.(Uploader); ok {
			storage = append(storage, u)
		}
	}
	serveBytes(w, r, RenderPreferences(storage), textType)
}

// serveBytes answers a small document that may change.
func serveBytes(w http.ResponseWriter, r *http.Request, b []byte, ctype string) {
	hd := w.Header()
	hd.Set("Cache-Control", "no-cache")
	hd.Set("Content-Type", ctype)
	hd.Set("Content-Length", strconv.Itoa(len(b)))
	if r.Method == http.MethodHead {
		return
	}
	_, _ = w.Write(b) //nolint:gosec // plain text or a key with nosniff; never rendered as HTML
}

// serveBlob writes b: 304 when the validators say the client has it, headers
// only for HEAD, else the body copied to its end.
func (h *APT) serveBlob(w http.ResponseWriter, r *http.Request, e *entry, b Blob, ctype, cache string) {
	defer b.Body.Close()
	hd := w.Header()
	hd.Set("Cache-Control", cache)
	if b.ETag != "" {
		hd.Set("ETag", b.ETag)
	}
	if !b.Modified.IsZero() {
		hd.Set("Last-Modified", b.Modified.UTC().Format(http.TimeFormat))
	}
	if notModified(r, b) {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	hd.Set("Content-Type", ctype)
	if b.Size >= 0 {
		hd.Set("Content-Length", strconv.FormatInt(b.Size, 10))
	}
	if r.Method == http.MethodHead {
		return
	}
	// Copied to its end: a cache hit's digest check runs on the final Read,
	// and a failure must break the transfer.
	if _, err := io.Copy(w, b.Body); err != nil {
		h.log.Warn("apt copy failed", "path", r.URL.Path, "source", e.source, "error", err)
		e.aborted = true
	}
}

// notModified reports whether the request's validators match b:
// If-None-Match decides when present, else If-Modified-Since.
func notModified(r *http.Request, b Blob) bool {
	if inm := r.Header.Get("If-None-Match"); inm != "" {
		return b.ETag != "" && etagMatch(inm, b.ETag)
	}
	if ims := r.Header.Get("If-Modified-Since"); ims != "" && !b.Modified.IsZero() {
		if t, err := http.ParseTime(ims); err == nil {
			return !b.Modified.Truncate(time.Second).After(t)
		}
	}
	return false
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

// upload checks the PUT before reading its body (an Expect: 100-continue
// client never sends a refused one), spools it, checks its control file
// against the URL and hands it to the source.
func (h *APT) upload(w http.ResponseWriter, r *http.Request, caller identity.Caller, e *entry, p Path) {
	e.write = true
	e.pkg = p.Deb.Name
	if !authz.Allowed(caller.Rules, ecoName, p.Deb.Name, authz.Write, Match) {
		h.logMalformed(caller)
		problem(w, http.StatusForbidden, "forbidden: no apt:"+p.Deb.Name+" write rule")
		return
	}
	src := h.source(p.Source)
	if src == nil {
		problem(w, http.StatusNotFound, "")
		return
	}
	e.source = src.Name()
	up, ok := src.(Uploader)
	if !ok {
		w.Header().Set("Allow", "GET, HEAD")
		problem(w, http.StatusMethodNotAllowed, "source "+p.Source+" does not accept uploads")
		return
	}
	if !slices.ContainsFunc(up.Claims(), func(c string) bool { return Match(c, p.Deb.Name) }) {
		problem(w, http.StatusForbidden, p.Deb.Name+" is not claimed by source "+p.Source)
		return
	}
	file := p.Deb.FileName()
	tooLarge := fmt.Sprintf("%s exceeds %d bytes", file, h.maxUpload)
	if r.ContentLength > h.maxUpload {
		problem(w, http.StatusRequestEntityTooLarge, tooLarge)
		return
	}
	// The server has no ReadTimeout (downloads are large); bound the body here.
	if err := http.NewResponseController(w).SetReadDeadline(time.Now().Add(uploadReadTimeout)); err != nil && !errors.Is(err, http.ErrNotSupported) {
		h.log.Warn("apt upload: set read deadline", "error", err)
	}
	f, err := h.createTemp(h.tmpDir, "upload-*")
	if err != nil {
		h.log.Error("apt upload: spool", "error", err)
		problem(w, http.StatusInternalServerError, "")
		return
	}
	defer func() { f.Close(); os.Remove(f.Name()) }() //nolint:gosec // our own os.CreateTemp file
	body := &readErr{r: io.LimitReader(r.Body, h.maxUpload+1)}
	size, err := io.Copy(f, body)
	if err != nil && body.err == nil {
		h.log.Error("apt upload: spool", "error", err)
		problem(w, http.StatusInternalServerError, "")
		return
	}
	if err != nil {
		problem(w, http.StatusBadRequest, "could not read the request body")
		return
	}
	if size > h.maxUpload {
		problem(w, http.StatusRequestEntityTooLarge, tooLarge)
		return
	}
	ctl, err := Inspect(f, size)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	if d := ctl.Deb; d.Name != p.Deb.Name {
		problem(w, http.StatusBadRequest, fmt.Sprintf("Package is %q in the control file but %q in the file name", d.Name, p.Deb.Name))
		return
	} else if StripEpoch(d.Version) != p.Deb.Version {
		problem(w, http.StatusBadRequest, fmt.Sprintf("Version is %q in the control file but %q in the file name", StripEpoch(d.Version), p.Deb.Version))
		return
	} else if d.Arch != p.Deb.Arch {
		problem(w, http.StatusBadRequest, fmt.Sprintf("Architecture is %q in the control file but %q in the file name", d.Arch, p.Deb.Arch))
		return
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		h.log.Error("apt upload: rewind spool", "error", err)
		problem(w, http.StatusInternalServerError, "")
		return
	}
	if _, err := up.Upload(r.Context(), caller, p.Suite, p.Component, ctl, f, size); err != nil {
		if errors.Is(err, ErrExists) {
			err = &RequestError{Status: http.StatusConflict, Detail: file + " " + ErrExists.Error()}
		}
		h.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusCreated)
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

func (h *APT) logMalformed(caller identity.Caller) {
	if bad := malformedRules(caller.Rules); len(bad) > 0 {
		h.log.Warn("ignoring malformed capability rules", "caller", caller.NodeName, "rules", bad)
	}
}

// malformedRules returns the capability entries that can never grant
// anything for apt: entries without an ecosystem and apt entries with an
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

// fail answers err. Never 401: there are no credentials to ask for.
func (h *APT) fail(w http.ResponseWriter, r *http.Request, err error) {
	var status int
	var detail string
	switch re, isReq := errors.AsType[*RequestError](err); {
	case isReq:
		status, detail = re.Status, re.Detail
	case errors.Is(err, ErrExists):
		status, detail = http.StatusConflict, err.Error()
	default:
		status = resolve.HTTPStatus(err)
	}
	if status == http.StatusUnauthorized {
		status, detail = http.StatusBadGateway, ""
	}
	if status >= 500 {
		h.log.Error("apt request failed", "path", r.URL.Path, "status", status, "error", err)
		detail = ""
	}
	problem(w, status, detail)
}

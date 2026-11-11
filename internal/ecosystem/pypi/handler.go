package pypi

import (
	"context"
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

	"github.com/radiergummi/tspackages/internal/archive"
	"github.com/radiergummi/tspackages/internal/authz"
	"github.com/radiergummi/tspackages/internal/ecosystem"
	"github.com/radiergummi/tspackages/internal/identity"
	"github.com/radiergummi/tspackages/internal/metrics"
	"github.com/radiergummi/tspackages/internal/resolve"
)

// ecoName is the ecosystem name in config, capability rules and metrics.
const ecoName = "pypi"

const (
	// uploadReadTimeout bounds reading an upload's body.
	uploadReadTimeout = 10 * time.Minute
	// maxField caps a form field other than content and attestations.
	maxField = 64 << 10
	// maxAttestations caps the attestations field.
	maxAttestations = 1 << 20
)

// PyPI serves the simple API under /pypi/simple/, files under /pypi/files/
// and uploads at /pypi/legacy/.
type PyPI struct {
	sources   []Source
	maxUpload int64
	tmpDir    string
	log       *slog.Logger
}

var _ ecosystem.Ecosystem = (*PyPI)(nil)

// New returns the PyPI endpoint over sources. Uploads are capped at
// maxUpload bytes and spooled in tmpDir, which must exist and be private.
func New(sources []Source, maxUpload int64, tmpDir string, log *slog.Logger) *PyPI {
	if log == nil {
		log = slog.Default()
	}
	return &PyPI{sources: sources, maxUpload: maxUpload, tmpDir: tmpDir, log: log}
}

func (p *PyPI) Name() string { return ecoName }

// Mount registers the PyPI routes on mux.
func (p *PyPI) Mount(mux *http.ServeMux) {
	mux.HandleFunc("GET /pypi/simple/{$}", p.wrap(p.index))
	mux.HandleFunc("GET /pypi/simple/{name}/{$}", p.wrap(p.project))
	mux.HandleFunc("GET /pypi/simple/{name}", p.wrap(p.project))
	mux.HandleFunc("GET /pypi/files/{source}/{name}/{filename}", p.wrap(p.file))
	// HEAD would otherwise be served by the GET route and fetch the artifact.
	mux.HandleFunc("HEAD /pypi/files/{source}/{name}/{filename}", func(w http.ResponseWriter, _ *http.Request) {
		setSecurityHeaders(w.Header())
		w.Header().Set("Allow", "GET")
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
	})
	mux.HandleFunc("GET /pypi/integrity/{source}/{name}/{filename}/provenance", p.wrap(p.provenance))
	mux.HandleFunc("POST /pypi/legacy/{$}", p.wrap(p.upload))
	mux.HandleFunc("POST /pypi/legacy", p.wrap(p.upload))
}

func setSecurityHeaders(h http.Header) {
	h.Set("Cache-Control", "private, no-store")
	h.Set("X-Content-Type-Options", "nosniff")
}

// entry collects what a request touched, for its log line and metrics.
type entry struct {
	pkg, source string
	claimed     bool
	write       bool
	version     string // uploads only
	filename    string // uploads only
	aborted     bool   // the body failed after the headers were sent
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

func (p *PyPI) wrap(h func(http.ResponseWriter, *http.Request, identity.Caller, *entry)) http.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request) {
		setSecurityHeaders(rw.Header())
		caller, ok := identity.FromContext(r.Context())
		if !ok {
			p.log.Warn("pypi request without caller", "path", r.URL.Path, "status", http.StatusForbidden)
			metrics.ObserveRequest(ecoName, "none", http.StatusForbidden)
			http.Error(rw, "forbidden", http.StatusForbidden)
			return
		}
		w := &statusWriter{ResponseWriter: rw}
		e := &entry{}
		h(w, r, caller, e)
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
		attrs := []any{"caller", caller.String(), "node", caller.NodeStableID, "package", e.pkg, "source", e.source, "status", status}
		if e.write {
			attrs = append(attrs, "node_name", caller.NodeName, "version", e.version, "filename", e.filename)
		}
		p.log.Log(r.Context(), level, "pypi request", attrs...)
		if e.aborted {
			// Headers are out: break the connection so the client sees a
			// failed transfer, not a short file.
			panic(http.ErrAbortHandler)
		}
	}
}

func (p *PyPI) index(w http.ResponseWriter, r *http.Request, caller identity.Caller, _ *entry) {
	seen := map[string]bool{}
	var names []string
	for _, s := range p.sources {
		l, ok := s.(Lister)
		if !ok {
			continue
		}
		ns, err := l.Names(r.Context())
		if err != nil {
			p.log.Warn("pypi: listing projects failed", "source", s.Name(), "error", err)
			continue
		}
		for _, n := range ns {
			if !seen[n] && authz.Allowed(caller.Rules, ecoName, n, authz.Read, Match) {
				seen[n] = true
				names = append(names, n)
			}
		}
	}
	slices.Sort(names)
	w.Header().Set("Vary", "Accept")
	WriteIndex(w, names, WantJSON(r.Header.Get("Accept")))
}

func (p *PyPI) project(w http.ResponseWriter, r *http.Request, caller identity.Caller, e *entry) {
	raw := r.PathValue("name")
	name, err := Normalize(raw)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if raw != name || !strings.HasSuffix(r.URL.Path, "/") {
		http.Redirect(w, r, "/pypi/simple/"+name+"/", http.StatusMovedPermanently) //nolint:gosec // a local path; name is normalised to [a-z0-9-]
		return
	}
	cands, ok := p.authorize(w, caller, e, name, authz.Read)
	if !ok {
		return
	}
	proj, src, err := resolve.First(r.Context(), cands, func(ctx context.Context, s Source) (Project, error) {
		return s.Project(ctx, name)
	})
	if err != nil {
		p.fail(w, r, err)
		return
	}
	e.source = src.Name()
	base := baseURL(r) + "/pypi/"
	files := slices.Clone(proj.Files)
	for i := range files {
		files[i].URL = base + "files/" + src.Name() + "/" + name + "/" + files[i].Filename
		if files[i].HasProvenance {
			files[i].ProvenanceURL = base + "integrity/" + src.Name() + "/" + name + "/" + files[i].Filename + "/provenance"
		}
	}
	proj.Name, proj.Files = name, files
	w.Header().Set("Vary", "Accept")
	WriteProject(w, proj, WantJSON(r.Header.Get("Accept")))
}

func baseURL(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + r.Host
}

// servingSource returns the source named in the route if, and only if, it is
// the one the index resolves name to.
func (p *PyPI) servingSource(w http.ResponseWriter, r *http.Request, caller identity.Caller, e *entry) (Source, string, bool) {
	name, err := Normalize(r.PathValue("name"))
	if err != nil || name != r.PathValue("name") {
		http.NotFound(w, r)
		return nil, "", false
	}
	cands, ok := p.authorize(w, caller, e, name, authz.Read)
	if !ok {
		return nil, "", false
	}
	i := slices.IndexFunc(cands, func(s Source) bool { return s.Name() == r.PathValue("source") })
	if i < 0 {
		http.NotFound(w, r)
		return nil, "", false
	}
	// The index answers from the first candidate that knows the name, so an
	// earlier one must not know it either.
	_, _, err = resolve.First(r.Context(), cands[:i], func(ctx context.Context, s Source) (Project, error) {
		return s.Project(ctx, name)
	})
	if err == nil {
		http.NotFound(w, r)
		return nil, "", false
	}
	if _, failed := errors.AsType[*resolve.SourceError](err); failed {
		p.fail(w, r, err)
		return nil, "", false
	}
	e.source = cands[i].Name()
	return cands[i], name, true
}

func (p *PyPI) file(w http.ResponseWriter, r *http.Request, caller identity.Caller, e *entry) {
	src, name, ok := p.servingSource(w, r, caller, e)
	if !ok {
		return
	}
	filename := r.PathValue("filename")
	var art Artifact
	var err error
	if f, isMeta := strings.CutSuffix(filename, ".metadata"); isMeta {
		art, err = src.Metadata(r.Context(), name, f)
	} else {
		art, err = src.File(r.Context(), name, filename)
	}
	if err != nil {
		p.fail(w, r, resolve.Wrap(src.Name(), err))
		return
	}
	p.serve(w, r, e, art, filename)
}

func (p *PyPI) provenance(w http.ResponseWriter, r *http.Request, caller identity.Caller, e *entry) {
	src, name, ok := p.servingSource(w, r, caller, e)
	if !ok {
		return
	}
	art, err := src.Provenance(r.Context(), name, r.PathValue("filename"))
	if err != nil {
		p.fail(w, r, resolve.Wrap(src.Name(), err))
		return
	}
	w.Header().Set("Content-Type", "application/vnd.pypi.integrity.v1+json")
	p.serve(w, r, e, art, "")
}

// serve streams an artifact; a seekable body also answers range requests.
func (p *PyPI) serve(w http.ResponseWriter, r *http.Request, e *entry, art Artifact, filename string) {
	defer art.Body.Close()
	if w.Header().Get("Content-Type") == "" {
		w.Header().Set("Content-Type", "application/octet-stream")
	}
	// Ranges go through ServeContent. A whole file is copied to its end: a
	// cache hit's digest check runs on the final Read, which ServeContent's
	// size-bounded copy never makes, and a failure must break the transfer.
	if rs, ok := art.Body.(io.ReadSeeker); ok && r.Header.Get("Range") != "" {
		http.ServeContent(w, r, filename, time.Time{}, rs)
		return
	}
	if art.Size > 0 {
		w.Header().Set("Content-Length", strconv.FormatInt(art.Size, 10))
	}
	if _, err := io.Copy(w, art.Body); err != nil {
		p.log.Warn("pypi file copy failed", "package", e.pkg, "source", e.source, "error", err)
		e.aborted = true
	}
}

func (p *PyPI) upload(w http.ResponseWriter, r *http.Request, caller identity.Caller, e *entry) {
	e.write = true
	// The server has no ReadTimeout (downloads are large); bound the upload body here.
	if err := http.NewResponseController(w).SetReadDeadline(time.Now().Add(uploadReadTimeout)); err != nil && !errors.Is(err, http.ErrNotSupported) {
		p.log.Warn("pypi upload: set read deadline", "error", err)
	}
	form, err := p.readUpload(w, r)
	if form.content != nil {
		defer func() { form.content.Close(); os.Remove(form.content.Name()) }() //nolint:gosec // our own os.CreateTemp file
	}
	if err != nil {
		if _, ok := errors.AsType[*http.MaxBytesError](err); ok || errors.Is(err, errUploadTooLarge) {
			http.Error(w, fmt.Sprintf("upload exceeds %d bytes", p.maxUpload), http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	e.version, e.filename = form.fields["version"], form.filename
	if a := form.fields[":action"]; a != "file_upload" {
		http.Error(w, fmt.Sprintf("unsupported :action %q", a), http.StatusBadRequest)
		return
	}
	if form.content == nil {
		http.Error(w, "missing content", http.StatusBadRequest)
		return
	}
	name, err := Normalize(form.fields["name"])
	if err != nil {
		http.Error(w, "invalid project name", http.StatusBadRequest)
		return
	}
	cands, ok := p.authorize(w, caller, e, name, authz.Write)
	if !ok {
		return
	}
	var store Uploader
	if e.claimed {
		for _, s := range cands {
			if u, ok := s.(Uploader); ok {
				store = u
				break
			}
		}
	}
	if store == nil {
		http.Error(w, fmt.Sprintf("no storage source claims %q", name), http.StatusForbidden)
		return
	}
	// Reads resolve from the first claiming source; an upload anywhere else
	// would be stored but never served.
	if store != cands[0] {
		http.Error(w, fmt.Sprintf("%q is served by source %q", name, cands[0].Name()), http.StatusConflict)
		return
	}
	e.source = store.Name()
	if _, err := form.content.Seek(0, io.SeekStart); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	_, err = store.Upload(r.Context(), caller, Upload{
		Name: form.fields["name"], Version: form.fields["version"], Filename: form.filename,
		Content: form.content, Size: form.size, SHA256: form.fields["sha256_digest"], Attestations: []byte(form.fields["attestations"]),
	})
	if err != nil {
		status, body := uploadStatus(err)
		if status >= 500 {
			p.log.Error("pypi upload failed", "package", name, "source", store.Name(), "error", err)
		}
		http.Error(w, body, status)
		return
	}
	w.WriteHeader(http.StatusOK)
}

var errUploadTooLarge = errors.New("upload too large")

type uploadForm struct {
	fields   map[string]string
	content  *os.File
	filename string
	size     int64
}

// readUpload reads the multipart form, spooling the content part to a temp
// file. Fields are capped; the first value of each wins.
func (p *PyPI) readUpload(w http.ResponseWriter, r *http.Request) (uploadForm, error) {
	form := uploadForm{fields: map[string]string{}}
	r.Body = http.MaxBytesReader(w, r.Body, p.maxUpload+maxAttestations+(1<<20))
	mr, err := r.MultipartReader()
	if err != nil {
		return form, errors.New("expected a multipart/form-data upload")
	}
	for {
		part, err := mr.NextPart()
		if errors.Is(err, io.EOF) {
			return form, nil
		}
		if err != nil {
			return form, err
		}
		key := part.FormName()
		if key == "content" {
			if form.content != nil {
				return form, errors.New("more than one content part")
			}
			f, err := os.CreateTemp(p.tmpDir, "upload-*")
			if err != nil {
				return form, err
			}
			form.content, form.filename = f, part.FileName()
			n, err := io.Copy(f, io.LimitReader(part, p.maxUpload+1))
			if err != nil {
				return form, err
			}
			if n > p.maxUpload {
				return form, errUploadTooLarge
			}
			form.size = n
			continue
		}
		limit := int64(maxField)
		if key == "attestations" {
			limit = maxAttestations
		}
		b, err := io.ReadAll(io.LimitReader(part, limit+1))
		if err != nil {
			return form, err
		}
		if int64(len(b)) > limit {
			return form, fmt.Errorf("form field %q is too large", key)
		}
		if _, dup := form.fields[key]; !dup {
			form.fields[key] = string(b)
		}
	}
}

// uploadStatus maps an Upload error to a status and a client-safe body.
func uploadStatus(err error) (int, string) {
	switch {
	case errors.Is(err, ErrFileExists):
		return http.StatusBadRequest, err.Error()
	case errors.As(err, new(*archive.Error)), errors.As(err, new(*UploadError)):
		return http.StatusBadRequest, err.Error()
	default:
		return http.StatusInternalServerError, "internal error"
	}
}

// authorize records name in e, answers 403 unless the caller may perform
// action on it and returns the candidate sources for it.
func (p *PyPI) authorize(w http.ResponseWriter, caller identity.Caller, e *entry, name string, action authz.Action) ([]Source, bool) {
	e.pkg = name
	cands, claimed := resolve.Candidates(p.sources, name, Match)
	e.claimed = claimed
	if !authz.Allowed(caller.Rules, ecoName, name, action, Match) {
		if bad := malformedRules(caller.Rules); len(bad) > 0 {
			p.log.Warn("ignoring malformed capability rules", "caller", caller.NodeName, "rules", bad)
		}
		http.Error(w, "forbidden", http.StatusForbidden)
		return nil, false
	}
	return cands, true
}

// malformedRules returns the capability entries that can never grant
// anything for PyPI: entries without an ecosystem and PyPI entries with an
// invalid pattern. Entries for other ecosystems are not checked.
func malformedRules(rules []authz.Rule) []string {
	var bad []string
	for _, r := range rules {
		for _, e := range slices.Concat(r.Read, r.Write) {
			eco, pattern, ok := strings.Cut(e, ":")
			if e != "*" && (!ok || eco == "" || (eco == ecoName && !ValidPattern(strings.ToLower(pattern)))) {
				bad = append(bad, e)
			}
		}
	}
	return bad
}

// fail answers a resolution error with a short, client-safe body.
func (p *PyPI) fail(w http.ResponseWriter, r *http.Request, err error) {
	status := resolve.HTTPStatus(err)
	if status >= 500 {
		p.log.Error("pypi source failed", "path", r.URL.Path, "error", err)
	}
	http.Error(w, http.StatusText(status), status)
}

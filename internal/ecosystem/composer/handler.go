package composer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/radiergummi/tspackages/internal/archive"
	"github.com/radiergummi/tspackages/internal/authz"
	"github.com/radiergummi/tspackages/internal/ecosystem"
	"github.com/radiergummi/tspackages/internal/identity"
	"github.com/radiergummi/tspackages/internal/metrics"
	"github.com/radiergummi/tspackages/internal/resolve"
)

const ecoName = "composer"

// uploadReadTimeout bounds reading an upload's body.
const uploadReadTimeout = 10 * time.Minute

// Composer serves the Composer v2 repository protocol under /composer/.
type Composer struct {
	sources []Source
	limits  archive.Limits
	log     *slog.Logger
}

var _ ecosystem.Ecosystem = (*Composer)(nil)

// New returns the Composer endpoint over sources. Uploads are capped at
// l.MaxBytes.
func New(sources []Source, l archive.Limits, log *slog.Logger) *Composer {
	if log == nil {
		log = slog.Default()
	}
	return &Composer{sources: sources, limits: l, log: log}
}

func (c *Composer) Name() string { return ecoName }

// Mount registers the Composer routes on mux.
func (c *Composer) Mount(mux *http.ServeMux) {
	mux.HandleFunc("GET /composer/packages.json", c.wrap(c.packagesJSON))
	mux.HandleFunc("GET /composer/p2/{vendor}/{file}", c.wrap(c.p2))
	mux.HandleFunc("GET /composer/dist/{source}/{vendor}/{name}/{version}/{reference}", c.wrap(c.dist))
	// HEAD would otherwise be served by the GET route and fetch the artifact.
	mux.HandleFunc("HEAD /composer/dist/{source}/{vendor}/{name}/{version}/{reference}", func(w http.ResponseWriter, _ *http.Request) {
		setSecurityHeaders(w.Header())
		w.Header().Set("Allow", "GET")
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
	})
	mux.HandleFunc("PUT /composer/upload/{vendor}/{name}/{version}", c.wrap(c.upload))
}

// entry carries per-request log fields set by the handlers.
type entry struct {
	pkg, source string
	claimed     bool
	write       bool
	version     string // writes only
	sha256      string // writes only, once stored
	aborted     bool   // the body failed after the headers were sent
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

// code is the status sent so far; 200 if the handler wrote nothing.
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
	w.status = w.code()
	return w.ResponseWriter.Write(b)
}

func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// setSecurityHeaders sets the headers every Composer response carries.
func setSecurityHeaders(h http.Header) {
	h.Set("Cache-Control", "private, no-store")
	h.Set("Vary", "Host")
	h.Set("X-Content-Type-Options", "nosniff")
}

// wrap requires a Caller in the context and logs the request when it is done.
func (c *Composer) wrap(h func(http.ResponseWriter, *http.Request, identity.Caller, *entry)) http.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request) {
		setSecurityHeaders(rw.Header())
		caller, ok := identity.FromContext(r.Context())
		if !ok {
			c.log.Warn("composer request without caller", "path", r.URL.Path, "status", http.StatusForbidden)
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
		attrs := []any{
			"caller", caller.String(),
			"node", caller.NodeStableID,
			"package", e.pkg,
			"source", e.source,
			"status", status,
		}
		if e.write {
			attrs = append(attrs, "node_name", caller.NodeName, "version", e.version, "sha256", e.sha256)
		}
		c.log.Log(r.Context(), level, "composer request", attrs...)
		if e.aborted {
			// Headers are out: break the connection so the client sees a
			// failed transfer, not a short file.
			panic(http.ErrAbortHandler)
		}
	}
}

func (c *Composer) packagesJSON(w http.ResponseWriter, r *http.Request, caller identity.Caller, e *entry) {
	if !hasComposerRule(caller.Rules) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	body := map[string]any{
		"packages":     []any{},
		"metadata-url": "/composer/p2/%package%.json",
	}
	if patterns, ok := claimPatterns(c.sources); ok {
		body["available-package-patterns"] = patterns
	}
	writeJSON(w, http.StatusOK, body)
}

// claimPatterns returns the claims of every source, sorted and deduplicated.
// Composer may skip a repository for names matching none of these patterns.
// They are not filtered per caller: they describe routing, not access. Any
// unclaimed source (or a "*" claim) can answer any name, so then ok is false.
func claimPatterns(sources []Source) (patterns []string, ok bool) {
	for _, s := range sources {
		if len(s.Claims()) == 0 || slices.Contains(s.Claims(), "*") {
			return nil, false
		}
		patterns = append(patterns, s.Claims()...)
	}
	slices.Sort(patterns)
	return slices.Compact(patterns), true
}

func hasComposerRule(rules []authz.Rule) bool {
	for _, r := range rules {
		for _, e := range slices.Concat(r.Read, r.Write) {
			if e == "*" || strings.HasPrefix(e, ecoName+":") {
				return true
			}
		}
	}
	return false
}

func (c *Composer) p2(w http.ResponseWriter, r *http.Request, caller identity.Caller, e *entry) {
	file, ok := strings.CutSuffix(r.PathValue("file"), ".json")
	if !ok {
		http.NotFound(w, r)
		return
	}
	file, dev := strings.CutSuffix(file, "~dev")
	name, err := Normalize(r.PathValue("vendor") + "/" + file)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	cands, ok := c.authorize(w, caller, e, name, authz.Read)
	if !ok {
		return
	}
	vs, src, err := resolve.First(r.Context(), cands, func(ctx context.Context, s Source) ([]Version, error) {
		return s.Versions(ctx, name, dev)
	})
	if err != nil {
		c.fail(w, r, err)
		return
	}
	e.source = src.Name()
	out := []map[string]any{}
	for _, v := range vs {
		out = append(out, c.withDistURL(r, src.Name(), name, v))
	}
	writeJSON(w, http.StatusOK, map[string]any{"packages": map[string]any{name: out}})
}

func (c *Composer) dist(w http.ResponseWriter, r *http.Request, caller identity.Caller, e *entry) {
	name, err := Normalize(r.PathValue("vendor") + "/" + r.PathValue("name"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	cands, ok := c.authorize(w, caller, e, name, authz.Read)
	if !ok {
		return
	}
	i := slices.IndexFunc(cands, func(s Source) bool { return s.Name() == r.PathValue("source") })
	if i < 0 {
		http.NotFound(w, r)
		return
	}
	// p2 answers from the first candidate that knows the name, so an earlier
	// one must not know it either.
	version := r.PathValue("version")
	normalized, _ := NormalizeVersion(version)
	_, _, err = resolve.First(r.Context(), cands[:i], func(ctx context.Context, s Source) ([]Version, error) {
		return s.Versions(ctx, name, isDevVersion(normalized))
	})
	if err == nil {
		http.NotFound(w, r)
		return
	}
	if _, failed := errors.AsType[*resolve.SourceError](err); failed {
		c.fail(w, r, err)
		return
	}
	src := cands[i]
	e.source = src.Name()
	art, err := src.Dist(r.Context(), name, version, r.PathValue("reference"))
	if err != nil {
		c.fail(w, r, resolve.Wrap(src.Name(), err))
		return
	}
	defer art.Body.Close()
	w.Header().Set("Content-Type", "application/zip")
	if art.Size > 0 {
		w.Header().Set("Content-Length", fmt.Sprint(art.Size))
	}
	if _, err := io.Copy(w, art.Body); err != nil {
		c.log.Warn("composer dist copy failed", "package", name, "source", src.Name(), "error", err)
		e.aborted = true
	}
}

func (c *Composer) upload(w http.ResponseWriter, r *http.Request, caller identity.Caller, e *entry) {
	e.write = true
	e.version = r.PathValue("version")
	name, err := Normalize(r.PathValue("vendor") + "/" + r.PathValue("name"))
	if err != nil {
		http.Error(w, "invalid package name", http.StatusBadRequest)
		return
	}
	cands, ok := c.authorize(w, caller, e, name, authz.Write)
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
	// The server has no ReadTimeout (downloads are large); bound the upload body here.
	if err := http.NewResponseController(w).SetReadDeadline(time.Now().Add(uploadReadTimeout)); err != nil && !errors.Is(err, http.ErrNotSupported) {
		c.log.Warn("composer upload: set read deadline", "error", err)
	}
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, c.limits.MaxBytes))
	if err != nil {
		if _, ok := errors.AsType[*http.MaxBytesError](err); ok {
			http.Error(w, fmt.Sprintf("upload exceeds %d bytes", c.limits.MaxBytes), http.StatusRequestEntityTooLarge)
		} else {
			http.Error(w, "could not read request body", http.StatusBadRequest)
		}
		return
	}
	v, err := store.Upload(r.Context(), caller, name, r.PathValue("version"), data)
	if err != nil {
		status, body := uploadStatus(err)
		if status >= 500 {
			c.log.Error("composer upload failed", "package", name, "source", store.Name(), "error", err)
		}
		http.Error(w, body, status)
		return
	}
	e.sha256 = v.Reference
	writeJSON(w, http.StatusCreated, c.withDistURL(r, store.Name(), name, v))
}

// authorize records name in e, answers 403 unless the caller may perform
// action on it and returns the candidate sources for it.
func (c *Composer) authorize(w http.ResponseWriter, caller identity.Caller, e *entry, name string, action authz.Action) ([]Source, bool) {
	e.pkg = name
	cands, claimed := resolve.Candidates(c.sources, name, Match)
	e.claimed = claimed
	if !authz.Allowed(caller.Rules, ecoName, name, action, Match) {
		if bad := malformedRules(caller.Rules); len(bad) > 0 {
			c.log.Warn("ignoring malformed capability rules", "caller", caller.NodeName, "rules", bad)
		}
		http.Error(w, "forbidden", http.StatusForbidden)
		return nil, false
	}
	return cands, true
}

// uploadStatus maps an Upload error to a status and a client-safe body, as
// resolve.HTTPStatus does for reads.
func uploadStatus(err error) (int, string) {
	var ae *archive.Error
	var ue *UploadError
	switch {
	case errors.Is(err, ErrVersionExists):
		return http.StatusConflict, "version already exists"
	case errors.As(err, &ae), errors.As(err, &ue):
		return http.StatusBadRequest, err.Error()
	default:
		return http.StatusInternalServerError, "internal error"
	}
}

// fail answers a resolution error with a short, client-safe body.
func (c *Composer) fail(w http.ResponseWriter, r *http.Request, err error) {
	status := resolve.HTTPStatus(err)
	if status >= 500 {
		c.log.Error("composer source failed", "path", r.URL.Path, "error", err)
	}
	http.Error(w, http.StatusText(status), status)
}

// servedDistKeys is what a served dist keeps. Composer would also follow mirrors
// and transport-options, which could send clients to upstream hosts.
var servedDistKeys = []string{"type", "url", "reference", "shasum"}

// withDistURL returns a deep copy of v.Package whose dist.url points back at
// this server, without the keys that make Composer contact other hosts.
func (c *Composer) withDistURL(r *http.Request, source, name string, v Version) map[string]any {
	pkg, _ := deepCopy(v.Package).(map[string]any)
	if pkg == nil {
		pkg = map[string]any{}
	}
	delete(pkg, "source") // never reveal upstream VCS locations
	delete(pkg, "notification-url")
	delete(pkg, "transport-options")
	upstreamDist, _ := pkg["dist"].(map[string]any)
	if upstreamDist == nil || v.Reference == "" {
		delete(pkg, "dist") // no artifact we can address; do not invent a URL or leak upstream's
		return pkg
	}
	dist := make(map[string]any, len(servedDistKeys))
	for _, k := range servedDistKeys {
		if val, ok := upstreamDist[k]; ok {
			dist[k] = val
		}
	}
	pkg["dist"] = dist
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	dist["url"] = scheme + "://" + r.Host + "/composer/dist/" + url.PathEscape(source) + "/" + name + "/" +
		url.PathEscape(v.Version) + "/" + url.PathEscape(v.Reference)
	return pkg
}

func deepCopy(v any) any {
	switch x := v.(type) {
	case map[string]any:
		m := make(map[string]any, len(x))
		for k, e := range x {
			m[k] = deepCopy(e)
		}
		return m
	case []any:
		s := make([]any, len(x))
		for i, e := range x {
			s[i] = deepCopy(e)
		}
		return s
	default:
		return v
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

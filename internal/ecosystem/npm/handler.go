package npm

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
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
const ecoName = "npm"

const (
	// publishReadTimeout bounds reading a publish body.
	publishReadTimeout = 10 * time.Minute
	// maxTagBody caps the JSON string body of a dist-tag add.
	maxTagBody = 1 << 10
	// corgiType is the abbreviated packument's media type.
	corgiType = "application/vnd.npm.install-v1+json"
)

// allowedMethods is the Allow header of each route. Unpublish routes allow
// nothing.
var allowedMethods = map[RouteKind]string{
	RoutePackument:    "GET, HEAD, PUT",
	RouteVersion:      "GET, HEAD",
	RouteTarball:      "GET, HEAD",
	RouteDistTags:     "GET, HEAD",
	RouteDistTag:      "PUT, DELETE",
	RouteKeys:         "GET, HEAD",
	RouteAttestations: "GET, HEAD",
	RouteRev:          "",
}

// NPM serves the npm registry protocol under /npm/.
type NPM struct {
	sources   []Source
	maxUpload int64
	tmpDir    string
	log       *slog.Logger
}

var _ ecosystem.Ecosystem = (*NPM)(nil)

// New returns the npm endpoint over sources. Tarballs are capped at
// maxUpload bytes, so a publish body (base64 plus JSON) at
// ceil(maxUpload*4/3) + 2 MiB; bodies are spooled in tmpDir, which must
// exist and be private.
func New(sources []Source, maxUpload int64, tmpDir string, log *slog.Logger) *NPM {
	if log == nil {
		log = slog.Default()
	}
	return &NPM{sources: sources, maxUpload: maxUpload, tmpDir: tmpDir, log: log}
}

func (h *NPM) Name() string { return ecoName }

// Mount registers /npm/. Paths are parsed by ParsePath: a ServeMux pattern
// can't treat "@scope%2fname" and "@scope/name" as the same name.
func (h *NPM) Mount(mux *http.ServeMux) {
	mux.HandleFunc("/npm/{path...}", h.serve)
}

func setSecurityHeaders(hd http.Header) {
	hd.Set("Cache-Control", "private, no-store")
	hd.Set("X-Content-Type-Options", "nosniff")
}

// jsonError answers {"error":reason}, the shape npm appends to its messages.
func jsonError(w http.ResponseWriter, status int, reason string) {
	b, _ := json.Marshal(struct {
		Error string `json:"error"`
	}{reason})
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(b)
}

func methodNotAllowed(w http.ResponseWriter, allow, reason string) {
	w.Header().Set("Allow", allow)
	jsonError(w, http.StatusMethodNotAllowed, reason)
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

func (h *NPM) serve(rw http.ResponseWriter, r *http.Request) {
	setSecurityHeaders(rw.Header())
	caller, ok := identity.FromContext(r.Context())
	if !ok {
		h.log.Warn("npm request without caller", "path", r.URL.Path, "status", http.StatusForbidden)
		metrics.ObserveRequest(ecoName, "none", http.StatusForbidden)
		jsonError(rw, http.StatusForbidden, "forbidden")
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
	attrs := []any{"caller", caller.String(), "node", caller.NodeStableID, "package", e.pkg, "source", e.source, "method", r.Method, "status", status}
	if e.write {
		attrs = append(attrs, "node_name", caller.NodeName)
	}
	h.log.Log(r.Context(), level, "npm request", attrs...)
	if e.aborted {
		// Headers are out: break the connection so the client sees a failed
		// transfer, not a short document.
		panic(http.ErrAbortHandler)
	}
}

func (h *NPM) route(w http.ResponseWriter, r *http.Request, caller identity.Caller, e *entry) {
	rt, err := ParsePath(strings.TrimPrefix(r.URL.EscapedPath(), "/npm/"))
	if err != nil {
		jsonError(w, http.StatusNotFound, "not found")
		return
	}
	e.pkg = rt.Name.Norm
	allow := allowedMethods[rt.Kind]
	if !slices.Contains(strings.Split(allow, ", "), r.Method) {
		reason := "method not allowed"
		if rt.Kind == RouteRev || rt.Kind == RoutePackument && r.Method == http.MethodDelete {
			reason = "this registry does not support unpublish"
		}
		methodNotAllowed(w, allow, reason)
		return
	}
	switch rt.Kind {
	case RoutePackument:
		if r.Method == http.MethodPut {
			h.publish(w, r, caller, e, rt.Name)
		} else {
			h.packument(w, r, caller, e, rt.Name)
		}
	case RouteVersion:
		h.version(w, r, caller, e, rt.Name, rt.Version)
	case RouteTarball:
		h.tarball(w, r, caller, e, rt.Name, rt.File)
	case RouteDistTags:
		h.distTags(w, r, caller, e, rt.Name)
	case RouteDistTag:
		h.distTag(w, r, caller, e, rt.Name, rt.Tag)
	case RouteKeys:
		h.keys(w, r, caller, e)
	case RouteAttestations:
		h.attestations(w, r, caller, e, rt.Name, rt.Version)
	case RouteRev:
		// Never reached: RouteRev allows no method.
	}
}

func baseURL(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + r.Host
}

func (h *NPM) packument(w http.ResponseWriter, r *http.Request, caller identity.Caller, e *entry, n Name) {
	cands, ok := h.authorize(w, caller, e, n, authz.Read)
	if !ok {
		return
	}
	corgi := strings.Contains(strings.ToLower(strings.Join(r.Header.Values("Accept"), ",")), corgiType)
	doc, src, err := resolve.First(r.Context(), cands, func(ctx context.Context, s Source) (Doc, error) {
		return s.Packument(ctx, n, corgi)
	})
	if err != nil {
		h.fail(w, r, err)
		return
	}
	e.source = src.Name()
	ctype := "application/json"
	if corgi {
		ctype = corgiType
	}
	h.serveDoc(w, r, e, doc, ctype)
}

func (h *NPM) version(w http.ResponseWriter, r *http.Request, caller identity.Caller, e *entry, n Name, versionOrTag string) {
	cands, ok := h.authorize(w, caller, e, n, authz.Read)
	if !ok {
		return
	}
	b, src, err := resolve.First(r.Context(), cands, func(ctx context.Context, s Source) ([]byte, error) {
		return s.Version(ctx, n, versionOrTag)
	})
	if err != nil {
		h.fail(w, r, err)
		return
	}
	e.source = src.Name()
	sum := sha256.Sum256(b)
	h.serveDoc(w, r, e, Doc{
		Body: io.NopCloser(bytes.NewReader(b)), Size: int64(len(b)),
		SHA256: hex.EncodeToString(sum[:]), Tokens: bytes.Count(b, []byte(BaseToken)),
	}, "application/json")
}

// serveDoc answers a stored document with its BaseTokens expanded to this
// request's base URL. The ETag covers the stored bytes and the base, so it
// changes whenever the served bytes do.
func (h *NPM) serveDoc(w http.ResponseWriter, r *http.Request, e *entry, doc Doc, ctype string) {
	defer doc.Body.Close()
	base := baseURL(r) + "/npm/"
	sum := sha256.Sum256([]byte(doc.SHA256 + base))
	etag := `"` + hex.EncodeToString(sum[:]) + `"`
	hd := w.Header()
	hd.Set("ETag", etag)
	// no-cache: clients revalidate every time, so a fresh publish is never
	// hidden by heuristic freshness. No Last-Modified, for the same reason.
	hd.Set("Cache-Control", "no-cache")
	// Full and abbreviated documents share a URL.
	hd.Set("Vary", "Accept")
	if etagMatch(r.Header.Get("If-None-Match"), etag) {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	hd.Set("Content-Type", ctype)
	hd.Set("Content-Length", strconv.FormatInt(ExpandedSize(doc.Size, doc.Tokens, base), 10))
	if r.Method == http.MethodHead {
		return
	}
	ex := Expand(w, base)
	_, err := io.Copy(ex, doc.Body)
	if err == nil {
		err = ex.Close()
	}
	if err != nil {
		h.log.Warn("npm document copy failed", "package", e.pkg, "source", e.source, "error", err)
		e.aborted = true
	}
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

func (h *NPM) tarball(w http.ResponseWriter, r *http.Request, caller identity.Caller, e *entry, n Name, file string) {
	cands, ok := h.authorize(w, caller, e, n, authz.Read)
	if !ok {
		return
	}
	art, src, err := resolve.First(r.Context(), cands, func(ctx context.Context, s Source) (Artifact, error) {
		return s.Tarball(ctx, n, file)
	})
	if err != nil {
		h.fail(w, r, err)
		return
	}
	e.source = src.Name()
	h.serveArtifact(w, r, e, art, "application/octet-stream")
}

func (h *NPM) serveArtifact(w http.ResponseWriter, r *http.Request, e *entry, art Artifact, ctype string) {
	defer art.Body.Close()
	w.Header().Set("Content-Type", ctype)
	if art.Size > 0 {
		w.Header().Set("Content-Length", strconv.FormatInt(art.Size, 10))
	}
	if r.Method == http.MethodHead {
		return
	}
	// Copied to its end: a cache hit's digest check runs on the final Read,
	// and a failure must break the transfer.
	if _, err := io.Copy(w, art.Body); err != nil {
		h.log.Warn("npm file copy failed", "package", e.pkg, "source", e.source, "error", err)
		e.aborted = true
	}
}

func (h *NPM) distTags(w http.ResponseWriter, r *http.Request, caller identity.Caller, e *entry, n Name) {
	cands, ok := h.authorize(w, caller, e, n, authz.Read)
	if !ok {
		return
	}
	tags, src, err := resolve.First(r.Context(), cands, func(ctx context.Context, s Source) (map[string]string, error) {
		return s.DistTags(ctx, n)
	})
	if err != nil {
		h.fail(w, r, err)
		return
	}
	e.source = src.Name()
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(RenderDistTags(tags))
}

// distTag adds (PUT) or removes (DELETE) a dist-tag on the source the name
// resolves to first, which must be a Publisher.
func (h *NPM) distTag(w http.ResponseWriter, r *http.Request, caller identity.Caller, e *entry, n Name, tag string) {
	e.write = true
	cands, ok := h.authorize(w, caller, e, n, authz.Write)
	if !ok {
		return
	}
	if len(cands) == 0 {
		jsonError(w, http.StatusNotFound, "not found")
		return
	}
	pub, ok := cands[0].(Publisher)
	if !ok {
		methodNotAllowed(w, "", "dist-tags of "+n.Norm+" come from "+cands[0].Name())
		return
	}
	e.source = pub.Name()
	var err error
	if r.Method == http.MethodDelete {
		err = pub.RemoveTag(r.Context(), caller, n, tag)
	} else {
		b, rerr := io.ReadAll(io.LimitReader(r.Body, maxTagBody+1))
		if rerr != nil {
			jsonError(w, http.StatusBadRequest, "could not read the dist-tag body")
			return
		}
		if len(b) > maxTagBody {
			jsonError(w, http.StatusRequestEntityTooLarge, fmt.Sprintf("dist-tag body exceeds %d bytes", maxTagBody))
			return
		}
		var version string
		if json.Unmarshal(b, &version) != nil {
			jsonError(w, http.StatusBadRequest, "dist-tag body must be a JSON string")
			return
		}
		err = pub.SetTag(r.Context(), caller, n, tag, version)
	}
	if err != nil {
		h.fail(w, r, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = io.WriteString(w, `{"ok":true}`)
}

// publish spools the body and hands it to the first claiming source, which
// must be a Publisher: reads resolve from it, so a publish anywhere else
// would be stored but never served.
func (h *NPM) publish(w http.ResponseWriter, r *http.Request, caller identity.Caller, e *entry, n Name) {
	e.write = true
	if mt, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type")); mt != "application/json" {
		jsonError(w, http.StatusBadRequest, "publish body must be application/json")
		return
	}
	cands, ok := h.authorize(w, caller, e, n, authz.Write)
	if !ok {
		return
	}
	if !e.claimed || !slices.ContainsFunc(cands, func(s Source) bool { _, ok := s.(Publisher); return ok }) {
		jsonError(w, http.StatusForbidden, "no storage source claims "+n.Norm)
		return
	}
	pub, ok := cands[0].(Publisher)
	if !ok {
		jsonError(w, http.StatusConflict, n.Norm+" is served by source "+cands[0].Name())
		return
	}
	e.source = pub.Name()
	// The server has no ReadTimeout (downloads are large); bound the body here.
	if err := http.NewResponseController(w).SetReadDeadline(time.Now().Add(publishReadTimeout)); err != nil && !errors.Is(err, http.ErrNotSupported) {
		h.log.Warn("npm publish: set read deadline", "error", err)
	}
	f, err := os.CreateTemp(h.tmpDir, "publish-*")
	if err != nil {
		h.log.Error("npm publish: spool", "error", err)
		jsonError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	defer func() { f.Close(); os.Remove(f.Name()) }() //nolint:gosec // our own os.CreateTemp file
	limit := (h.maxUpload*4+2)/3 + 2<<20
	size, err := io.Copy(f, io.LimitReader(r.Body, limit+1))
	if err != nil {
		jsonError(w, http.StatusBadRequest, "could not read the publish body")
		return
	}
	if size > limit {
		jsonError(w, http.StatusRequestEntityTooLarge, fmt.Sprintf("publish body exceeds %d bytes", limit))
		return
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		h.log.Error("npm publish: rewind spool", "error", err)
		jsonError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	notice, err := pub.Publish(r.Context(), caller, n, f, size)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	if notice != "" {
		w.Header().Set("npm-notice", notice)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_, _ = io.WriteString(w, `{"ok":true}`)
}

// keys serves the unclaimed source's signing keys. They are public, but
// default deny still holds: any npm read rule will do.
func (h *NPM) keys(w http.ResponseWriter, r *http.Request, caller identity.Caller, e *entry) {
	if !hasNPMRead(caller.Rules) {
		h.logMalformed(caller)
		jsonError(w, http.StatusForbidden, "forbidden: no npm: read rule")
		return
	}
	i := slices.IndexFunc(h.sources, func(s Source) bool { return len(s.Claims()) == 0 })
	if i < 0 {
		jsonError(w, http.StatusNotFound, "not found")
		return
	}
	a, ok := h.sources[i].(Attester)
	if !ok {
		jsonError(w, http.StatusNotFound, "not found")
		return
	}
	e.source = h.sources[i].Name()
	art, err := a.Keys(r.Context())
	if err != nil {
		h.fail(w, r, resolve.Wrap(e.source, err))
		return
	}
	h.serveArtifact(w, r, e, art, "application/json")
}

func (h *NPM) attestations(w http.ResponseWriter, r *http.Request, caller identity.Caller, e *entry, n Name, version string) {
	cands, ok := h.authorize(w, caller, e, n, authz.Read)
	if !ok {
		return
	}
	// A source without attestations ends resolution: a later source's
	// bundle would describe another package of the same name.
	if i := slices.IndexFunc(cands, func(s Source) bool { _, ok := s.(Attester); return !ok }); i >= 0 {
		cands = cands[:i]
	}
	art, src, err := resolve.First(r.Context(), cands, func(ctx context.Context, s Source) (Artifact, error) {
		return s.(Attester).Attestations(ctx, n, version)
	})
	if err != nil {
		h.fail(w, r, err)
		return
	}
	e.source = src.Name()
	h.serveArtifact(w, r, e, art, "application/json")
}

// authorize records n in e, answers 403 unless the caller may perform action
// on it and returns its candidate sources.
func (h *NPM) authorize(w http.ResponseWriter, caller identity.Caller, e *entry, n Name, action authz.Action) ([]Source, bool) {
	cands, claimed := resolve.Candidates(h.sources, n.Norm, Match)
	e.claimed = claimed
	if !authz.Allowed(caller.Rules, ecoName, n.Norm, action, Match) {
		h.logMalformed(caller)
		jsonError(w, http.StatusForbidden, "forbidden: no npm:"+n.Norm+" "+string(action)+" rule")
		return nil, false
	}
	return cands, true
}

// hasNPMRead reports whether any rule grants read on something in npm: "*"
// or an "npm:" entry.
func hasNPMRead(rules []authz.Rule) bool {
	for _, r := range rules {
		for _, x := range r.Read {
			if x == "*" || strings.HasPrefix(x, ecoName+":") {
				return true
			}
		}
	}
	return false
}

func (h *NPM) logMalformed(caller identity.Caller) {
	if bad := malformedRules(caller.Rules); len(bad) > 0 {
		h.log.Warn("ignoring malformed capability rules", "caller", caller.NodeName, "rules", bad)
	}
}

// malformedRules returns the capability entries that can never grant
// anything for npm: entries without an ecosystem and npm entries with an
// invalid pattern (npm patterns are lowercase). Entries for other ecosystems
// are not checked.
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

// fail answers err with a status and a client-safe {"error":…} body. Never
// 401: npm turns one into an OTP or login prompt.
func (h *NPM) fail(w http.ResponseWriter, r *http.Request, err error) {
	var status int
	var reason string
	switch re, isReq := errors.AsType[*RequestError](err); {
	case isReq:
		status, reason = re.Status, re.Reason
	case errors.Is(err, ErrVersionExists):
		status, reason = http.StatusConflict, err.Error()
	case errors.Is(err, ErrNoTarball):
		w.Header().Set("Allow", "GET, HEAD")
		status, reason = http.StatusMethodNotAllowed, ErrNoTarball.Error()
	default:
		status = resolve.HTTPStatus(err)
	}
	if status == http.StatusUnauthorized {
		status, reason = http.StatusBadGateway, ""
	}
	if status >= 500 {
		h.log.Error("npm request failed", "path", r.URL.Path, "status", status, "error", err)
		reason = ""
	}
	if reason == "" {
		reason = strings.ToLower(http.StatusText(status))
	}
	jsonError(w, status, reason)
}

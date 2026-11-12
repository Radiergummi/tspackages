package goproxy

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode"

	"golang.org/x/mod/module"

	"github.com/radiergummi/tspackages/internal/authz"
	"github.com/radiergummi/tspackages/internal/ecosystem"
	"github.com/radiergummi/tspackages/internal/identity"
	"github.com/radiergummi/tspackages/internal/metrics"
	"github.com/radiergummi/tspackages/internal/resolve"
)

// ecoName is the ecosystem name in config, capability rules and metrics.
const ecoName = "go"

// GoProxy serves the GOPROXY protocol under /go/ and the checksum database
// under /go/sumdb/.
type GoProxy struct {
	sources []Source
	sumdb   SumDB
	log     *slog.Logger
}

var _ ecosystem.Ecosystem = (*GoProxy)(nil)

// New returns the Go endpoint over sources. A nil sumdb answers 404 for every
// sumdb path.
func New(sources []Source, sumdb SumDB, log *slog.Logger) *GoProxy {
	if log == nil {
		log = slog.Default()
	}
	return &GoProxy{sources: sources, sumdb: sumdb, log: log}
}

func (g *GoProxy) Name() string { return ecoName }

// Mount registers the Go routes on mux.
func (g *GoProxy) Mount(mux *http.ServeMux) {
	mux.HandleFunc("GET /go/{rest...}", g.serve)
	// HEAD would otherwise be served by the GET route and fetch the artifact.
	mux.HandleFunc("HEAD /go/{rest...}", func(w http.ResponseWriter, _ *http.Request) {
		setSecurityHeaders(w.Header())
		w.Header().Set("Allow", "GET")
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
	})
}

func setSecurityHeaders(h http.Header) {
	h.Set("Cache-Control", "private, no-store")
	h.Set("X-Content-Type-Options", "nosniff")
}

// textError answers with a single-line text/plain body.
func textError(w http.ResponseWriter, msg string, status int) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, msg+"\n")
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

// entry collects what a request touched, for its log line and metrics.
type entry struct {
	pkg, source string
	claimed     bool
	aborted     bool // the body failed after the headers were sent
}

// serve handles every GET under /go/. The route is parsed from the path
// net/http already percent-decoded once (PathValue), so "%40v" and "@v" name
// the same route; module escaping ("!") is the protocol's own and decoded by
// ParseRoute.
func (g *GoProxy) serve(rw http.ResponseWriter, r *http.Request) {
	setSecurityHeaders(rw.Header())
	caller, ok := identity.FromContext(r.Context())
	if !ok {
		g.log.Warn("go request without caller", "path", r.URL.Path, "status", http.StatusForbidden)
		metrics.ObserveRequest(ecoName, "none", http.StatusForbidden)
		textError(rw, "forbidden", http.StatusForbidden)
		return
	}
	w := &statusWriter{ResponseWriter: rw}
	e := &entry{}
	rest := r.PathValue("rest")
	if sub, ok := strings.CutPrefix(rest, "sumdb/"); ok {
		e.source = "sumdb"
		if g.sumdb == nil {
			textError(w, "not found", http.StatusNotFound)
		} else {
			g.sumdb.ServeSumDB(w, r, caller, sub)
		}
	} else {
		g.module(w, r, caller, e, rest)
	}
	status := w.code()
	src := e.source
	if src == "" {
		src = "none"
	}
	metrics.ObserveRequest(ecoName, src, status)
	level := slog.LevelDebug
	if e.claimed {
		level = slog.LevelInfo
	}
	g.log.Log(r.Context(), level, "go request",
		"caller", caller.String(), "node", caller.NodeStableID, "package", e.pkg, "source", e.source, "status", status)
	if e.aborted {
		// Headers are out: break the connection so the client sees a failed
		// transfer, not a short file.
		panic(http.ErrAbortHandler)
	}
}

func (g *GoProxy) module(w http.ResponseWriter, r *http.Request, caller identity.Caller, e *entry, rest string) {
	route, err := ParseRoute(rest)
	if err != nil {
		textError(w, "not found", http.StatusNotFound)
		return
	}
	// Reject versions before any rule check, lookup or fetch. A .info version
	// may be a query (branch, hash), so only the shape is checked there.
	switch route.Kind {
	case KindMod, KindZip:
		if module.Check(route.Path, route.Version) != nil || module.CanonicalVersion(route.Version) != route.Version {
			textError(w, "not found", http.StatusNotFound)
			return
		}
	case KindInfo:
		if route.Version == "" || strings.ContainsFunc(route.Version, func(c rune) bool { return unicode.IsSpace(c) || unicode.IsControl(c) }) {
			textError(w, "not found", http.StatusNotFound)
			return
		}
	case KindList, KindLatest:
	}
	lower := strings.ToLower(route.Path)
	e.pkg = lower
	cands, claimed := resolve.Candidates(g.sources, route.Path, Match)
	e.claimed = claimed
	if !authz.Allowed(caller.Rules, ecoName, lower, authz.Read, Match) {
		textError(w, "forbidden: no go:"+lower+" read rule", http.StatusForbidden)
		return
	}
	ctx := r.Context()
	p, v := route.Path, route.Version
	switch route.Kind {
	case KindList:
		vs, src, err := resolve.First(ctx, cands, func(ctx context.Context, s Source) ([]string, error) { return s.List(ctx, p) })
		if err != nil {
			g.fail(w, r, err)
			return
		}
		e.source = src.Name()
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		for _, x := range vs {
			_, _ = io.WriteString(w, x+"\n")
		}
	case KindInfo, KindLatest:
		info, src, err := resolve.First(ctx, cands, func(ctx context.Context, s Source) (Info, error) {
			if route.Kind == KindLatest {
				return s.Latest(ctx, p)
			}
			return s.Info(ctx, p, v)
		})
		if err != nil {
			g.fail(w, r, err)
			return
		}
		e.source = src.Name()
		info.Time = info.Time.UTC()
		body, err := json.Marshal(info)
		if err != nil {
			g.fail(w, r, err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	case KindMod, KindZip:
		art, src, err := resolve.First(ctx, cands, func(ctx context.Context, s Source) (Artifact, error) {
			if route.Kind == KindMod {
				return s.Mod(ctx, p, v)
			}
			return s.Zip(ctx, p, v)
		})
		if err != nil {
			g.fail(w, r, err)
			return
		}
		e.source = src.Name()
		ct := "text/plain; charset=utf-8"
		if route.Kind == KindZip {
			ct = "application/zip"
		}
		g.serveArtifact(w, r, e, art, ct)
	}
}

// serveArtifact streams art; a seekable body also answers range requests.
func (g *GoProxy) serveArtifact(w http.ResponseWriter, r *http.Request, e *entry, art Artifact, contentType string) {
	defer art.Body.Close()
	w.Header().Set("Content-Type", contentType)
	// Ranges go through ServeContent. A whole file is copied to its end: a
	// cache hit's digest check runs on the final Read, which ServeContent's
	// size-bounded copy never makes, and a failure must break the transfer.
	if rs, ok := art.Body.(io.ReadSeeker); ok && r.Header.Get("Range") != "" {
		http.ServeContent(w, r, "", time.Time{}, rs)
		return
	}
	if art.Size > 0 {
		w.Header().Set("Content-Length", strconv.FormatInt(art.Size, 10))
	}
	if _, err := io.Copy(w, art.Body); err != nil {
		g.log.Warn("go artifact copy failed", "package", e.pkg, "source", e.source, "error", err)
		e.aborted = true
	}
}

// fail answers a resolution error with a short, client-safe body.
func (g *GoProxy) fail(w http.ResponseWriter, r *http.Request, err error) {
	status := resolve.HTTPStatus(err)
	if status >= 500 {
		g.log.Error("go source failed", "path", r.URL.Path, "error", err)
	}
	textError(w, strings.ToLower(http.StatusText(status)), status)
}

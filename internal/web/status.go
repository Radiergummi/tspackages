// Package web serves the status page, health probes and metrics.
package web

import (
	"context"
	_ "embed"
	"html/template"
	"log/slog"
	"net/http"
	"slices"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/radiergummi/tspackages/internal/authz"
	"github.com/radiergummi/tspackages/internal/ecosystem"
	"github.com/radiergummi/tspackages/internal/ecosystem/composer"
	"github.com/radiergummi/tspackages/internal/identity"
	"github.com/radiergummi/tspackages/internal/metrics"
	"github.com/radiergummi/tspackages/internal/pins"
)

type (
	Health       = metrics.Health
	StatusSource = metrics.StatusSource
)

//go:embed status.html
var statusHTML string

var statusTmpl = template.Must(template.New("status").Parse(statusHTML))

// Web serves /, /healthz, /readyz and /metrics.
type Web struct {
	hostname  string
	eco       []ecosystem.Ecosystem
	sources   []StatusSource
	moved     func() []pins.MovedTag
	conflicts func() []composer.Conflict
	ready     func(ctx context.Context) error

	movedPkg     func(pins.MovedTag) string // package a moved tag's remote declares
	readyTimeout time.Duration
}

// New returns the status endpoints. hostname is the fallback host for client
// snippets when a request carries none. movedPkg names the package a moved
// tag's remote declares, so the status page shows the tag only to callers
// allowed to read that package; without it moved tags are hidden. A nil moved
// or conflicts reports none, a nil ready is always ready.
func New(hostname string, eco []ecosystem.Ecosystem, sources []StatusSource, moved func() []pins.MovedTag, movedPkg func(pins.MovedTag) string, conflicts func() []composer.Conflict, ready func(ctx context.Context) error) *Web {
	if moved == nil || movedPkg == nil {
		moved = func() []pins.MovedTag { return nil }
	}
	if conflicts == nil {
		conflicts = func() []composer.Conflict { return nil }
	}
	if ready == nil {
		ready = func(context.Context) error { return nil }
	}
	return &Web{hostname: hostname, eco: eco, sources: sources, moved: moved, movedPkg: movedPkg, conflicts: conflicts, ready: ready, readyTimeout: 5 * time.Second}
}

// Mount registers the routes on mux.
func (w *Web) Mount(mux *http.ServeMux) {
	mux.HandleFunc("GET /{$}", w.status)
	mux.HandleFunc("GET /healthz", w.requireCaller(func(rw http.ResponseWriter, _ *http.Request) {
		rw.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = rw.Write([]byte("ok"))
	}))
	mux.HandleFunc("GET /readyz", w.requireRule(w.readyz))
	metricsHandler := promhttp.HandlerFor(metrics.Registry(), promhttp.HandlerOpts{})
	mux.HandleFunc("GET /metrics", w.requireRule(metricsHandler.ServeHTTP))
}

// requireCaller admits any request with a tailnet identity.
func (w *Web) requireCaller(h http.HandlerFunc) http.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request) {
		if _, ok := identity.FromContext(r.Context()); !ok {
			http.Error(rw, "forbidden", http.StatusForbidden)
			return
		}
		h(rw, r)
	}
}

// requireRule admits only callers with at least one capability rule entry.
func (w *Web) requireRule(h http.HandlerFunc) http.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request) {
		if c, ok := identity.FromContext(r.Context()); !ok || !hasAnyRule(c.Rules) {
			http.Error(rw, "forbidden", http.StatusForbidden)
			return
		}
		h(rw, r)
	}
}

func (w *Web) readyz(rw http.ResponseWriter, r *http.Request) {
	rw.Header().Set("Content-Type", "text/plain; charset=utf-8")
	ctx, cancel := context.WithTimeout(r.Context(), w.readyTimeout)
	defer cancel()
	if err := w.ready(ctx); err != nil {
		category := "unavailable"
		switch {
		case r.Context().Err() != nil:
			category = "cancelled"
		case ctx.Err() != nil:
			category = "timeout"
		}
		slog.Warn("not ready", "category", category, "error", err)
		rw.WriteHeader(http.StatusServiceUnavailable)
		_, _ = rw.Write([]byte("not ready: " + category))
		return
	}
	_, _ = rw.Write([]byte("ok"))
}

type pageData struct {
	Host       string
	Ecosystems []string
	Health     []Health
	Moved      []pins.MovedTag
	Conflicts  []conflictView
	Composer   bool
}

func (w *Web) status(rw http.ResponseWriter, r *http.Request) {
	caller, ok := identity.FromContext(r.Context())
	if !ok || !hasAnyRule(caller.Rules) {
		http.Error(rw, "forbidden", http.StatusForbidden)
		return
	}
	host := r.Host
	if host == "" {
		host = w.hostname
	}
	d := pageData{Host: host}
	for _, e := range w.eco {
		d.Ecosystems = append(d.Ecosystems, e.Name())
		if e.Name() == "composer" {
			d.Composer = true
		}
	}
	slices.Sort(d.Ecosystems)
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	allowed := func(pkg string) bool {
		return authz.Allowed(caller.Rules, "composer", pkg, authz.Read, composer.Match)
	}
	for _, s := range w.sources {
		for _, h := range s.Health(ctx) {
			if !h.Scoped || (h.Package != "" && allowed(h.Package)) {
				d.Health = append(d.Health, h)
			}
		}
	}
	for _, m := range w.moved() {
		if allowed(w.movedPkg(m)) {
			m.Remote = metrics.RedactRemote(m.Remote)
			d.Moved = append(d.Moved, m)
		}
	}
	for _, c := range w.conflicts() {
		if !allowed(c.Package) {
			continue
		}
		v := conflictView{Package: c.Package}
		for _, r := range c.Remotes {
			v.Remotes = append(v.Remotes, metrics.RedactRemote(r))
		}
		d.Conflicts = append(d.Conflicts, v)
	}
	rw.Header().Set("Content-Type", "text/html; charset=utf-8")
	rw.Header().Set("Cache-Control", "private, no-store")
	rw.Header().Set("X-Content-Type-Options", "nosniff")
	rw.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'")
	if err := statusTmpl.Execute(rw, d); err != nil {
		http.Error(rw, "internal error", http.StatusInternalServerError)
	}
}

type conflictView struct {
	Package string
	Remotes []string
}

// hasAnyRule reports whether the rules hold at least one read or write entry.
func hasAnyRule(rules []authz.Rule) bool {
	return slices.ContainsFunc(rules, func(r authz.Rule) bool { return len(r.Read)+len(r.Write) > 0 })
}

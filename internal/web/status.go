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
	"github.com/radiergummi/tspackages/internal/ecosystem/pypi"
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
	changed   func() []composer.ChangedDist
	pypiConf  func() []pypi.Conflict
	pypiSkip  func() []pypi.Skipped
	ready     func(ctx context.Context) error

	movedPkg     func(pins.MovedTag) string // package a moved tag's remote declares
	readyTimeout time.Duration
}

// Options configures the status endpoints. Nil functions report nothing,
// and a nil Ready is always ready.
type Options struct {
	Hostname   string // fallback host for client snippets when a request carries none
	Ecosystems []ecosystem.Ecosystem
	Sources    []StatusSource
	Moved      func() []pins.MovedTag
	// MovedPkg names the package a moved tag's remote declares, so the status
	// page shows the tag only to callers allowed to read that package; without
	// it moved tags are hidden.
	MovedPkg  func(pins.MovedTag) string
	Conflicts func() []composer.Conflict
	Changed   func() []composer.ChangedDist // dists whose upstream bytes changed
	// PyPIConflicts and PyPISkipped report the pypi git sources' releases
	// that are not served as tagged, and packages that cannot be served.
	PyPIConflicts func() []pypi.Conflict
	PyPISkipped   func() []pypi.Skipped
	Ready         func(ctx context.Context) error
}

// New returns the status endpoints.
func New(o Options) *Web {
	w := &Web{hostname: o.Hostname, eco: o.Ecosystems, sources: o.Sources, moved: o.Moved, movedPkg: o.MovedPkg,
		conflicts: o.Conflicts, changed: o.Changed, pypiConf: o.PyPIConflicts, pypiSkip: o.PyPISkipped,
		ready: o.Ready, readyTimeout: 5 * time.Second}
	if w.moved == nil || w.movedPkg == nil {
		w.moved = func() []pins.MovedTag { return nil }
	}
	if w.conflicts == nil {
		w.conflicts = func() []composer.Conflict { return nil }
	}
	if w.changed == nil {
		w.changed = func() []composer.ChangedDist { return nil }
	}
	if w.ready == nil {
		w.ready = func(context.Context) error { return nil }
	}
	return w
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
	Changed    []composer.ChangedDist
	Composer   bool
	PyPI       bool
	PyPIConf   []pypi.Conflict
	PyPISkip   []pypi.Skipped
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
		switch e.Name() {
		case "composer":
			d.Composer = true
		case "pypi":
			d.PyPI = true
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
	pypiAllowed := func(pkg string) bool {
		return pkg != "" && authz.Allowed(caller.Rules, "pypi", pkg, authz.Read, pypi.Match)
	}
	if w.pypiConf != nil {
		for _, c := range w.pypiConf() {
			if pypiAllowed(c.Package) {
				d.PyPIConf = append(d.PyPIConf, c)
			}
		}
	}
	if w.pypiSkip != nil {
		for _, s := range w.pypiSkip() {
			if pypiAllowed(s.Package) {
				s.Remote = metrics.RedactRemote(s.Remote)
				d.PyPISkip = append(d.PyPISkip, s)
			}
		}
	}
	for _, c := range w.changed() {
		if allowed(c.Package) {
			d.Changed = append(d.Changed, c)
		}
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

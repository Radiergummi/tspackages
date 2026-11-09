// Package web serves the status page, health probes and metrics.
package web

import (
	"context"
	_ "embed"
	"html/template"
	"net/http"
	"sort"
	"time"

	"github.com/prometheus/client_golang/prometheus"
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

// Registry is the Prometheus registry served at /metrics.
func Registry() *prometheus.Registry { return metrics.Registry() }

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
}

// New returns the status endpoints. hostname is the fallback host for client
// snippets when a request carries none.
func New(hostname string, eco []ecosystem.Ecosystem, sources []StatusSource, moved func() []pins.MovedTag, conflicts func() []composer.Conflict, ready func(ctx context.Context) error) *Web {
	return &Web{hostname: hostname, eco: eco, sources: sources, moved: moved, conflicts: conflicts, ready: ready}
}

// SetRejected exposes the rate limiter's rejection count as
// tspackages_rate_limited_total.
func (w *Web) SetRejected(f func() uint64) { metrics.SetRejected(f) }

// Mount registers the routes on mux.
func (w *Web) Mount(mux *http.ServeMux) {
	mux.HandleFunc("GET /{$}", w.status)
	mux.HandleFunc("GET /healthz", w.requireCaller(func(rw http.ResponseWriter, _ *http.Request) {
		rw.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = rw.Write([]byte("ok"))
	}))
	mux.HandleFunc("GET /readyz", w.requireCaller(w.readyz))
	metricsHandler := promhttp.HandlerFor(metrics.Registry(), promhttp.HandlerOpts{})
	mux.HandleFunc("GET /metrics", w.requireCaller(metricsHandler.ServeHTTP))
}

func (w *Web) requireCaller(h http.HandlerFunc) http.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request) {
		if _, ok := identity.FromContext(r.Context()); !ok {
			http.Error(rw, "forbidden", http.StatusForbidden)
			return
		}
		h(rw, r)
	}
}

func (w *Web) readyz(rw http.ResponseWriter, r *http.Request) {
	rw.Header().Set("Content-Type", "text/plain; charset=utf-8")
	if w.ready != nil {
		if err := w.ready(r.Context()); err != nil {
			rw.WriteHeader(http.StatusServiceUnavailable)
			_, _ = rw.Write([]byte(err.Error()))
			return
		}
	}
	_, _ = rw.Write([]byte("ok"))
}

type pageData struct {
	Host       string
	Ecosystems []string
	Health     []Health
	Moved      []pins.MovedTag
	Conflicts  []composer.Conflict
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
	sort.Strings(d.Ecosystems)
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	for _, s := range w.sources {
		d.Health = append(d.Health, s.Health(ctx)...)
	}
	if w.moved != nil {
		d.Moved = w.moved()
	}
	if w.conflicts != nil {
		d.Conflicts = w.conflicts()
	}
	rw.Header().Set("Content-Type", "text/html; charset=utf-8")
	rw.Header().Set("Cache-Control", "private, no-store")
	rw.Header().Set("X-Content-Type-Options", "nosniff")
	rw.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'")
	if err := statusTmpl.Execute(rw, d); err != nil {
		http.Error(rw, "internal error", http.StatusInternalServerError)
	}
}

func hasAnyRule(rules []authz.Rule) bool { return len(rules) > 0 }

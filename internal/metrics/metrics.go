// Package metrics holds tspackages' Prometheus registry and the helpers the
// handlers and sources call to record observations.
//
// Label values come from configuration (ecosystem, source) or are
// fixed (the numeric status code); never pass client input.
package metrics

import (
	"context"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
)

// Health is the state of one status-page source entry.
type Health struct {
	Name   string
	OK     bool
	Detail string
	// Scoped rows describe one package's remote and are shown only to callers
	// allowed to read Package ("" while unknown: shown to nobody).
	Scoped  bool
	Package string
}

// StatusSource reports its health on the status page.
type StatusSource interface {
	Health(ctx context.Context) []Health
}

var (
	registry = prometheus.NewRegistry()

	requests = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "tspackages_requests_total",
		Help: "Requests handled, by ecosystem, source and HTTP status code.",
	}, []string{"ecosystem", "source", "code"})
	cacheHits = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "tspackages_cache_hits_total",
		Help: "Upstream-backed reads served from the cache.",
	}, []string{"ecosystem", "source"})
	upstreamDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "tspackages_upstream_request_duration_seconds",
		Help:    "Duration of upstream requests.",
		Buckets: prometheus.DefBuckets,
	}, []string{"source"})
	gitLastSync = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "tspackages_git_last_sync_timestamp_seconds",
		Help: "Unix time of the oldest last successful sync among a git source's remotes (0 while one never synced).",
	}, []string{"source"})

	buildInfo = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "tspackages_build_info",
		Help: "Always 1; the labels name the running build.",
	}, []string{"version", "commit"})

	rejected atomic.Pointer[func() uint64]
)

func init() {
	registry.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
		requests, cacheHits, upstreamDuration, gitLastSync, buildInfo,
		prometheus.NewCounterFunc(prometheus.CounterOpts{
			Name: "tspackages_rate_limited_total",
			Help: "Requests rejected by the per-identity rate limiter.",
		}, func() float64 {
			if f := rejected.Load(); f != nil {
				return float64((*f)())
			}
			return 0
		}),
	)
}

// RedactRemote strips any userinfo from a git remote URL, so credentials never
// reach labels, pages or logs even if a remote slipped through validation.
func RedactRemote(remote string) string {
	_, rest, ok := strings.Cut(remote, "://")
	if !ok {
		return remote
	}
	authority, _, _ := strings.Cut(rest, "/")
	at := strings.LastIndex(authority, "@")
	if at < 0 {
		return remote
	}
	scheme := remote[:len(remote)-len(rest)]
	return scheme + rest[at+1:]
}

// Registry is the registry served at /metrics.
func Registry() *prometheus.Registry { return registry }

// SetBuildInfo sets tspackages_build_info for the running build.
func SetBuildInfo(version, commit string) {
	buildInfo.Reset()
	buildInfo.WithLabelValues(version, commit).Set(1)
}

// SetRejected sets the function read by tspackages_rate_limited_total.
func SetRejected(f func() uint64) { rejected.Store(&f) }

func ObserveRequest(ecosystem, source string, code int) {
	requests.WithLabelValues(ecosystem, source, strconv.Itoa(code)).Inc()
}

func ObserveCacheHit(ecosystem, source string) {
	cacheHits.WithLabelValues(ecosystem, source).Inc()
}

func ObserveUpstream(source string, d time.Duration) {
	upstreamDuration.WithLabelValues(source).Observe(d.Seconds())
}

// SetGitLastSync sets the source's last-sync gauge; a zero t is reported as 0.
func SetGitLastSync(source string, t time.Time) {
	v := 0.0
	if !t.IsZero() {
		v = float64(t.Unix())
	}
	gitLastSync.WithLabelValues(source).Set(v)
}

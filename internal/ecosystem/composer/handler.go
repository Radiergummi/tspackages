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

	"github.com/radiergummi/tspackages/internal/archive"
	"github.com/radiergummi/tspackages/internal/authz"
	"github.com/radiergummi/tspackages/internal/ecosystem"
	"github.com/radiergummi/tspackages/internal/identity"
	"github.com/radiergummi/tspackages/internal/resolve"
)

const ecoName = "composer"

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
	mux.HandleFunc("PUT /composer/upload/{vendor}/{name}/{version}", c.wrap(c.upload))
}

// entry carries per-request log fields set by the handlers.
type entry struct {
	pkg, source string
	claimed     bool
	write       bool
}

type statusWriter struct {
	http.ResponseWriter
	status int
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

// wrap requires a Caller in the context and logs the request when it is done.
func (c *Composer) wrap(h func(http.ResponseWriter, *http.Request, identity.Caller, *entry)) http.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request) {
		caller, ok := identity.FromContext(r.Context())
		if !ok {
			http.Error(rw, "forbidden", http.StatusForbidden)
			return
		}
		w := &statusWriter{ResponseWriter: rw}
		e := &entry{}
		h(w, r, caller, e)
		level := slog.LevelDebug
		if e.write || e.claimed {
			level = slog.LevelInfo
		}
		c.log.Log(r.Context(), level, "composer request",
			"caller", caller.String(),
			"node", caller.NodeStableID,
			"package", e.pkg,
			"source", e.source,
			"status", w.status,
		)
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
	unclaimed := false
	for _, s := range c.sources {
		if len(s.Claims()) == 0 {
			unclaimed = true
		}
	}
	if !unclaimed {
		seen := map[string]bool{}
		names := []string{}
		for _, s := range c.sources {
			list, enumerable, err := s.Packages(r.Context())
			if err != nil {
				c.log.Warn("composer: listing packages failed", "source", s.Name(), "error", err)
				continue
			}
			if !enumerable {
				continue
			}
			for _, n := range list {
				n, err := Normalize(n)
				if err != nil || seen[n] || !authz.Allowed(caller.Rules, ecoName, n, authz.Read, Match) {
					continue
				}
				seen[n] = true
				names = append(names, n)
			}
		}
		slices.Sort(names)
		body["available-packages"] = names
	}
	writeJSON(w, http.StatusOK, body)
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
	e.pkg = name
	if !authz.Allowed(caller.Rules, ecoName, name, authz.Read, Match) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	cands, claimed := resolve.Candidates(c.sources, name, Match)
	e.claimed = claimed
	vs, src, err := resolve.First(r.Context(), cands, func(ctx context.Context, s Source) ([]Version, error) {
		return s.Versions(ctx, name)
	})
	if err != nil {
		c.fail(w, r, err)
		return
	}
	e.source = src.Name()
	out := []map[string]any{}
	for _, v := range vs {
		if v.Dev != dev {
			continue
		}
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
	e.pkg = name
	if !authz.Allowed(caller.Rules, ecoName, name, authz.Read, Match) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	cands, claimed := resolve.Candidates(c.sources, name, Match)
	e.claimed = claimed
	var src Source
	for _, s := range cands {
		if s.Name() == r.PathValue("source") {
			src = s
		}
	}
	if src == nil {
		http.NotFound(w, r)
		return
	}
	e.source = src.Name()
	art, _, err := resolve.First(r.Context(), []Source{src}, func(ctx context.Context, s Source) (Artifact, error) {
		return s.Dist(ctx, name, r.PathValue("version"), r.PathValue("reference"))
	})
	if err != nil {
		c.fail(w, r, err)
		return
	}
	defer art.Body.Close()
	w.Header().Set("Content-Type", "application/zip")
	if art.Size > 0 {
		w.Header().Set("Content-Length", fmt.Sprint(art.Size))
	}
	_, _ = io.Copy(w, art.Body)
}

func (c *Composer) upload(w http.ResponseWriter, r *http.Request, caller identity.Caller, e *entry) {
	e.write = true
	name, err := Normalize(r.PathValue("vendor") + "/" + r.PathValue("name"))
	if err != nil {
		http.Error(w, "invalid package name", http.StatusBadRequest)
		return
	}
	e.pkg = name
	if !authz.Allowed(caller.Rules, ecoName, name, authz.Write, Match) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	cands, claimed := resolve.Candidates(c.sources, name, Match)
	var store *StorageSource
	if claimed {
		for _, s := range cands {
			if ss, ok := s.(*StorageSource); ok {
				store = ss
				break
			}
		}
	}
	if store == nil {
		http.Error(w, fmt.Sprintf("no storage source claims %q", name), http.StatusForbidden)
		return
	}
	e.source = store.Name()
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, c.limits.MaxBytes))
	if err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			http.Error(w, fmt.Sprintf("upload exceeds %d bytes", c.limits.MaxBytes), http.StatusRequestEntityTooLarge)
		} else {
			http.Error(w, "could not read request body", http.StatusBadRequest)
		}
		return
	}
	v, err := store.Upload(r.Context(), caller, name, r.PathValue("version"), data)
	var ae *archive.Error
	var ue *UploadError
	switch {
	case errors.Is(err, ErrVersionExists):
		http.Error(w, "version already exists", http.StatusConflict)
	case errors.As(err, &ae), errors.As(err, &ue):
		http.Error(w, err.Error(), http.StatusBadRequest)
	case err != nil:
		c.log.Error("composer upload failed", "package", name, "source", store.Name(), "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
	default:
		writeJSON(w, http.StatusCreated, c.withDistURL(r, store.Name(), name, v))
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

// withDistURL returns a deep copy of v.Package whose dist.url points back at
// this server.
func (c *Composer) withDistURL(r *http.Request, source, name string, v Version) map[string]any {
	pkg, _ := deepCopy(v.Package).(map[string]any)
	if pkg == nil {
		pkg = map[string]any{}
	}
	dist, _ := pkg["dist"].(map[string]any)
	if dist == nil {
		dist = map[string]any{}
		pkg["dist"] = dist
	}
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

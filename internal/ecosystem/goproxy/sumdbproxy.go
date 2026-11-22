package goproxy

import (
	"log/slog"
	"net/http"
	"strings"

	"golang.org/x/mod/module"
	"golang.org/x/mod/sumdb/tlog"

	"github.com/radiergummi/tspackages/internal/authz"
	"github.com/radiergummi/tspackages/internal/identity"
	"github.com/radiergummi/tspackages/internal/resolve"
)

// SumDBProxy answers /go/sumdb/sum.golang.org/ for clients: supported, lookups
// of modules a registry source serves, and tiles. Other databases and paths
// are 404, so the go command falls back to the database itself.
type SumDBProxy struct {
	v       *Verifier
	sources []Source
	private func(path string) bool
	log     *slog.Logger
}

// NewSumDBProxy answers /go/sumdb/sum.golang.org/. private reports
// whether any git source claims a path (whatever the order); sources are
// the ecosystem's sources, for resolution. A nil private treats every path
// as private.
func NewSumDBProxy(v *Verifier, sources []Source, private func(path string) bool, log *slog.Logger) SumDB {
	if log == nil {
		log = slog.Default()
	}
	if private == nil {
		private = func(string) bool { return true }
	}
	return &SumDBProxy{v: v, sources: sources, private: private, log: log}
}

// ServeSumDB answers rest, what follows "sumdb/". The handler has already
// checked the caller's go: read rule.
func (p *SumDBProxy) ServeSumDB(w http.ResponseWriter, r *http.Request, caller identity.Caller, rest string) {
	sub, ok := strings.CutPrefix(rest, SumDBName+"/")
	switch {
	case !ok:
		textError(w, "not found", http.StatusNotFound)
	case sub == "supported":
		w.WriteHeader(http.StatusOK)
	case strings.HasPrefix(sub, "lookup/"):
		p.lookup(w, r, caller, strings.TrimPrefix(sub, "lookup/"))
	case strings.HasPrefix(sub, "tile/"):
		p.tile(w, r, sub)
	default:
		textError(w, "not found", http.StatusNotFound)
	}
}

// lookup answers "<escaped path>@<escaped version>" with the signed record
// the verifier obtained in this same call. Nothing about a path a git source
// claims leaves the node.
func (p *SumDBProxy) lookup(w http.ResponseWriter, r *http.Request, caller identity.Caller, file string) {
	escPath, escVers, ok := strings.CutLast(file, "@")
	if !ok {
		textError(w, "not found", http.StatusNotFound)
		return
	}
	path, err := module.UnescapePath(escPath)
	if err != nil {
		textError(w, "not found", http.StatusNotFound)
		return
	}
	vers, err := module.UnescapeVersion(escVers)
	if err != nil || module.Check(path, vers) != nil || module.CanonicalVersion(vers) != vers {
		textError(w, "not found", http.StatusNotFound)
		return
	}
	lower := strings.ToLower(path)
	if !authz.Allowed(caller.Rules, ecoName, lower, authz.Read, Match) {
		textError(w, "forbidden: no go:"+lower+" read rule", http.StatusForbidden)
		return
	}
	if p.private(path) {
		textError(w, path+" is private: add it to GONOSUMDB", http.StatusNotFound)
		return
	}
	cands, _ := resolve.Candidates(p.sources, path, Match)
	if len(cands) == 0 {
		textError(w, "not found", http.StatusNotFound)
		return
	}
	for _, s := range cands {
		if _, ok := s.(*RegistrySource); !ok {
			textError(w, "not found", http.StatusNotFound)
			return
		}
	}
	l, err := p.v.Lookup(r.Context(), path, vers)
	if err != nil {
		p.fail(w, err)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write(l.Record)
}

// tile answers a tile of the database, cached under the proxy's own keys.
func (p *SumDBProxy) tile(w http.ResponseWriter, r *http.Request, tilePath string) {
	if _, err := tlog.ParseTilePath(tilePath); err != nil {
		textError(w, "not found", http.StatusNotFound)
		return
	}
	b, err := p.v.Tile(r.Context(), tilePath)
	if err != nil {
		p.fail(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	_, _ = w.Write(b)
}

// fail answers a database error: a miss is 404, anything else 502 or 504.
func (p *SumDBProxy) fail(w http.ResponseWriter, err error) {
	err = resolve.Wrap("sumdb", err)
	status := resolve.HTTPStatus(err)
	if status >= 500 {
		p.log.Error("go checksum database request failed", "error", err)
	}
	textError(w, strings.ToLower(http.StatusText(status)), status)
}

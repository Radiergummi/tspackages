package server

import (
	"fmt"
	"html/template"
	"maps"
	"path/filepath"
	"slices"
	"strings"

	"github.com/radiergummi/tspackages/internal/config"
	"github.com/radiergummi/tspackages/internal/ecosystem/goproxy"
	"github.com/radiergummi/tspackages/internal/gitmirror"
	"github.com/radiergummi/tspackages/internal/limits"
	"github.com/radiergummi/tspackages/internal/metrics"
	"github.com/radiergummi/tspackages/internal/pins"
	"github.com/radiergummi/tspackages/internal/web"
	"github.com/radiergummi/tspackages/internal/workdir"
)

// buildGo builds the Go endpoint from e's sources in order. The checksum
// database verifier, present when any registry source is, fetches through
// the first registry source's upstream client (its fetch_hosts contain
// sum.golang.org); without one, every /go/sumdb/ path answers 404.
func buildGo(sh *shared, e config.Ecosystem) (built, error) {
	var (
		sources  []goproxy.Source
		status   []web.StatusSource
		gitSrcs  []*goproxy.GitSource
		verifier *goproxy.Verifier
	)
	for _, s := range e.Sources {
		switch s.Type {
		case "registry":
			client, err := sh.upstream(s)
			if err != nil {
				return built{}, fmt.Errorf("go source %q: %w", s.Name, err)
			}
			if verifier == nil {
				verifier = goproxy.NewVerifier(goproxy.VerifierOptions{
					Key: sh.hooks.GoSumDB.Key, URL: sh.hooks.GoSumDB.URL, Client: client,
					State: sh.stores.state, Cache: sh.cache, TTL: s.MetadataTTL, Log: sh.log,
				})
			}
			src := goproxy.NewRegistrySource(goproxy.RegistryOptions{
				Name: s.Name, Claims: s.Claims, BaseURL: s.URL, Client: client, Cache: sh.cache, Relay: sh.relay,
				Records: sh.records, TTL: s.MetadataTTL, MaxArtifact: int64(sh.cfg.Limits.MaxArtifactBytes),
				Verifier: verifier, Wait: limits.UpstreamWait, Log: sh.log,
			})
			sources, status = append(sources, src), append(status, src)
		case "git":
			for _, c := range config.GoHostWideClaims(s) {
				sh.log.Warn("go git source claims a whole host: every module under it is private and skips the checksum database",
					"source", s.Name, "claim", c)
			}
			src, err := goGitSource(sh, s)
			if err != nil {
				return built{}, fmt.Errorf("go source %q: %w", s.Name, err)
			}
			sources, status = append(sources, src), append(status, src)
			gitSrcs = append(gitSrcs, src)
		}
	}

	var sumdb goproxy.SumDB
	if verifier != nil {
		status = append(status, verifier)
		private := func(p string) bool {
			for _, g := range gitSrcs {
				if slices.ContainsFunc(g.Claims(), func(c string) bool { return goproxy.Match(c, p) }) {
					return true
				}
			}
			return false
		}
		sumdb = goproxy.NewSumDBProxy(verifier, sources, private, sh.log)
	}
	b := built{eco: goproxy.New(sources, sumdb, sh.log), status: status}
	for _, g := range gitSrcs {
		b.loops = append(b.loops, g.Run)
	}
	b.section = goSection(gonosumdb(e), gitSrcs)
	return b, nil
}

// goGitSource builds a git source over one mirror per distinct module
// remote. Key files live in keys/go/, where no composer or pypi source's can.
func goGitSource(sh *shared, s config.Source) (*goproxy.GitSource, error) {
	keyDir := filepath.Join(sh.keyDir, "go")
	if err := workdir.EnsurePrivateDir(keyDir); err != nil {
		return nil, err
	}
	var (
		mods    []goproxy.Module
		remotes []string
	)
	for _, p := range slices.Sorted(maps.Keys(s.Modules)) {
		m := s.Modules[p]
		mods = append(mods, goproxy.Module{Path: p, Remote: m.Remote, Dir: m.Dir})
		if !slices.Contains(remotes, m.Remote) {
			remotes = append(remotes, m.Remote)
		}
	}
	ms, err := sh.mirrors(s, filepath.Join(keyDir, s.Name), remotes)
	if err != nil {
		return nil, err
	}
	mirrors := map[string]*gitmirror.Mirror{}
	for i, r := range remotes {
		mirrors[r] = ms[i]
	}
	return goproxy.NewGitSource(goproxy.GitOptions{
		Name: s.Name, Claims: s.Claims, Modules: mods, Mirrors: mirrors, Branches: s.Branches,
		Pins: sh.pins, State: sh.stores.state, Cache: sh.cache, Records: sh.records, Poll: s.PollInterval,
		MaxArtifact: int64(sh.cfg.Limits.MaxArtifactBytes), TmpDir: filepath.Join(sh.workDir, "go-build"), Log: sh.log,
	})
}

// gonosumdb lists the git sources' claims ("a/b/*" → "a/b") in config
// order, then each git source's modules keys as written (sorted; a map has
// no order), deduplicated and comma-joined. The keys keep their case:
// the go command matches GONOSUMDB case-sensitively.
func gonosumdb(e config.Ecosystem) string {
	var out []string
	add := func(p string) {
		if !slices.Contains(out, p) {
			out = append(out, p)
		}
	}
	for _, s := range e.Sources {
		if s.Type == "git" {
			for _, c := range s.Claims {
				add(strings.TrimSuffix(c, "/*"))
			}
		}
	}
	for _, s := range e.Sources {
		if s.Type == "git" {
			for _, k := range slices.Sorted(maps.Keys(s.Modules)) {
				add(k)
			}
		}
	}
	return strings.Join(out, ",")
}

// goSection is Go's part of the status page. noSumDB is the GONOSUMDB
// value; "" leaves its line out of the snippet.
func goSection(noSumDB string, gitSrcs []*goproxy.GitSource) web.Section {
	code := "go env -w GOPROXY=https://{{host}}/go\n"
	if noSumDB != "" {
		code += "go env -w GONOSUMDB=" + noSumDB + "\n"
	}
	code += "go env -u GOPRIVATE GONOPROXY"
	refusals := func(moved bool) []goproxy.Refusal {
		var out []goproxy.Refusal
		for _, g := range gitSrcs {
			for _, r := range g.Refusals() {
				if (r.Kind == goproxy.RefusalMovedAfterStore) == moved {
					out = append(out, r)
				}
			}
		}
		return out
	}
	line := func(s string) web.Cell { return web.Cell{Lines: []string{s}} }
	return web.Section{
		Ecosystem: "go",
		Title:     "Go",
		Match:     goproxy.Match,
		Snippets: []web.Snippet{
			{Intro: "Configure the go command:", Code: code},
			{Intro: template.HTML("No <code>,direct</code>: a 404 for a private module would fall through to VCS.")},
		},
		MovedPackage: func(m pins.MovedTag) string {
			for _, g := range gitSrcs {
				if p := g.MovedPackage(m); p != "" {
					return p
				}
			}
			return ""
		},
		Tables: []web.Table{
			{
				Title:   "Tags skipped or refused",
				Empty:   "None.",
				Level:   3,
				Columns: []string{"Module", "Version", "Remote", "Tag", "Reason"},
				Rows: func() []web.Row {
					var rows []web.Row
					for _, r := range refusals(false) {
						rows = append(rows, web.Row{Packages: []string{r.Module}, Cells: []web.Cell{
							line(r.Module), line(r.Version), line(metrics.RedactRemote(r.Remote)), line(r.Tag), line(r.Reason),
						}})
					}
					return rows
				},
			},
			{
				Title:   "Tags moved after the version was stored",
				Empty:   "None.",
				Level:   3,
				Columns: []string{"Module", "Tag", "Remote", "Commit"},
				Rows: func() []web.Row {
					var rows []web.Row
					for _, r := range refusals(true) {
						rows = append(rows, web.Row{Packages: []string{r.Module}, Cells: []web.Cell{
							line(r.Module), line(r.Tag), line(metrics.RedactRemote(r.Remote)), line(r.Commit),
						}})
					}
					return rows
				},
			},
		},
	}
}

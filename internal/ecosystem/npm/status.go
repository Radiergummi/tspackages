package npm

import (
	"html/template"
	"strings"
	"time"

	"github.com/radiergummi/tspackages/internal/web"
)

// StatusSection is npm's part of the status page. A nil changed reports
// nothing.
func StatusSection(changed func() []ChangedTarball) web.Section {
	const npmrc = "registry=https://{{host}}/npm/\n//{{host}}/npm/:_authToken=tailscale"
	return web.Section{
		Ecosystem: "npm",
		Title:     "npm",
		Match:     Match,
		Snippets: []web.Snippet{
			{
				Intro: template.HTML("npm (<code>.npmrc</code>). The token is never checked, but npm wants one for publishing. Don't add <code>@scope:registry=</code> lines that point elsewhere:"),
				Code:  npmrc,
			},
			{
				Intro: template.HTML("pnpm (<code>.npmrc</code>):"),
				Code:  npmrc,
			},
			{
				Intro: template.HTML("Publish: set <code>publishConfig</code> in <code>package.json</code> or pass the registry:"),
				Code: "\"publishConfig\": {\"registry\": \"https://{{host}}/npm/\"}\n" +
					"npm publish --registry https://{{host}}/npm/",
			},
		},
		Tables: []web.Table{
			{
				Title:   "Changed tarballs",
				Intro:   "These upstream tarballs changed after first being seen for the same version. The new tarball is served.",
				Empty:   "None.",
				Level:   3,
				Columns: []string{"Package", "Version", "Source", "First sha256", "Now sha256", "Seen"},
				Rows: func() []web.Row {
					if changed == nil {
						return nil
					}
					var rows []web.Row
					for _, c := range changed() {
						rows = append(rows, web.Row{
							// Rules match normalised names; c.Package is exact.
							Packages: []string{strings.ToLower(c.Package)},
							Cells: []web.Cell{
								{Lines: []string{c.Package}}, {Lines: []string{c.Version}}, {Lines: []string{c.Source}},
								{Lines: []string{c.FirstSHA256}, Code: true}, {Lines: []string{c.NowSHA256}, Code: true},
								{Lines: []string{c.Seen.UTC().Format(time.RFC3339)}},
							},
						})
					}
					return rows
				},
			},
		},
	}
}

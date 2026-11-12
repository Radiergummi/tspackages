package composer

import (
	"html/template"

	"github.com/radiergummi/tspackages/internal/metrics"
	"github.com/radiergummi/tspackages/internal/pins"
	"github.com/radiergummi/tspackages/internal/web"
)

// StatusSection is Composer's part of the status page. Nil conflicts or
// changed report nothing; a nil movedPackage hides moved tags. The tables for
// name conflicts and changed archives are part of this section, so they are
// absent from the page when Composer isn't mounted.
func StatusSection(conflicts func() []Conflict, changed func() []ChangedDist, movedPackage func(pins.MovedTag) string) web.Section {
	return web.Section{
		Ecosystem: "composer",
		Title:     "Composer",
		Match:     Match,
		Snippets: []web.Snippet{
			{
				Intro: template.HTML("Add to <code>composer.json</code>:"),
				Code:  `{"repositories":[{"type":"composer","url":"https://{{host}}/composer"},{"packagist.org":false}]}`,
			},
			{
				Intro: "Upload a package:",
				Code:  "curl -fT pkg.zip https://{{host}}/composer/upload/<vendor>/<name>/<version>",
			},
		},
		MovedPackage: movedPackage,
		Tables: []web.Table{
			{
				Title:   "Package name conflicts",
				Intro:   "These names are declared by several remotes and are not served.",
				Empty:   "None.",
				Level:   2,
				Columns: []string{"Package", "Remotes"},
				Rows: func() []web.Row {
					if conflicts == nil {
						return nil
					}
					var rows []web.Row
					for _, c := range conflicts() {
						remotes := make([]string, len(c.Remotes))
						for i, r := range c.Remotes {
							remotes[i] = metrics.RedactRemote(r)
						}
						rows = append(rows, web.Row{
							Packages: []string{c.Package},
							Cells:    []web.Cell{{Lines: []string{c.Package}}, {Lines: remotes}},
						})
					}
					return rows
				},
			},
			{
				Title:   "Changed archives",
				Intro:   "These upstream archives changed after first being seen for the same version and reference. The new archive is served.",
				Empty:   "None.",
				Level:   2,
				Columns: []string{"Source", "Package", "Version", "Reference", "First sha256", "Seen sha256"},
				Rows: func() []web.Row {
					if changed == nil {
						return nil
					}
					var rows []web.Row
					for _, c := range changed() {
						rows = append(rows, web.Row{
							Packages: []string{c.Package},
							Cells: []web.Cell{
								{Lines: []string{c.Source}}, {Lines: []string{c.Package}}, {Lines: []string{c.Version}},
								{Lines: []string{c.Reference}, Code: true}, {Lines: []string{c.Pinned}, Code: true}, {Lines: []string{c.Seen}, Code: true},
							},
						})
					}
					return rows
				},
			},
		},
	}
}

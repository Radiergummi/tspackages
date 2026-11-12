package pypi

import (
	"html/template"

	"github.com/radiergummi/tspackages/internal/metrics"
	"github.com/radiergummi/tspackages/internal/web"
)

// StatusSection is PyPI's part of the status page. Nil conflicts or skipped
// report nothing. PyPI pins no tags, so it has no moved-tag mapping.
func StatusSection(conflicts func() []Conflict, skipped func() []Skipped) web.Section {
	return web.Section{
		Ecosystem: "pypi",
		Title:     "PyPI",
		Match:     Match,
		Snippets: []web.Snippet{
			{
				Intro: template.HTML("pip (<code>pip.conf</code>):"),
				Code:  "[global]\nindex-url = https://{{host}}/pypi/simple/",
			},
			{
				Intro: template.HTML("uv (<code>pyproject.toml</code> or <code>uv.toml</code>):"),
				Code:  "[[tool.uv.index]]\nname = \"tspackages\"\nurl = \"https://{{host}}/pypi/simple/\"\ndefault = true",
			},
			{Intro: "Don't add PyPI as an extra index: tspackages already passes public packages through."},
			{
				Intro: "Upload:",
				Code: "uv publish --publish-url https://{{host}}/pypi/legacy/ --username x --password x dist/*\n" +
					"twine upload --repository-url https://{{host}}/pypi/legacy/ -u x -p x dist/*",
			},
		},
		Tables: []web.Table{
			{
				Title:   "Git releases not served as tagged",
				Empty:   "None.",
				Level:   3,
				Columns: []string{"Package", "Version", "Problem", "Tags", "Remotes"},
				Rows: func() []web.Row {
					if conflicts == nil {
						return nil
					}
					var rows []web.Row
					for _, c := range conflicts() {
						rows = append(rows, web.Row{
							Packages: []string{c.Package},
							Cells: []web.Cell{
								{Lines: []string{c.Package}}, {Lines: []string{c.Version}}, {Lines: []string{c.Kind}},
								{Lines: c.Tags}, {Lines: c.Remotes},
							},
						})
					}
					return rows
				},
			},
			{
				Title:   "Packages skipped",
				Empty:   "None.",
				Level:   3,
				Columns: []string{"Package", "Remote", "Tag", "Directory", "Reason"},
				Rows: func() []web.Row {
					if skipped == nil {
						return nil
					}
					var rows []web.Row
					for _, s := range skipped() {
						rows = append(rows, web.Row{
							Packages: []string{s.Package},
							Cells: []web.Cell{
								{Lines: []string{s.Package}}, {Lines: []string{metrics.RedactRemote(s.Remote)}},
								{Lines: []string{s.Tag}}, {Lines: []string{s.Dir}}, {Lines: []string{s.Reason}},
							},
						})
					}
					return rows
				},
			},
		},
	}
}

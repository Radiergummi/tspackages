package pypi

import (
	"html/template"
	"time"

	"github.com/radiergummi/tspackages/internal/metrics"
	"github.com/radiergummi/tspackages/internal/web"
)

// StatusSection is PyPI's part of the status page. Nil conflicts or skipped
// report nothing; github lists the github sources, whose names, skipped
// assets, withheld and changed files get tables of their own. PyPI pins no
// tags, so it has no moved-tag mapping.
func StatusSection(conflicts func() []Conflict, skipped func() []Skipped, github []*GitHubSource) web.Section {
	sec := web.Section{
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
	if len(github) > 0 {
		sec.Tables = append(sec.Tables, githubTables(github)...)
	}
	return sec
}

// githubTables list, per github source, the names each repository owns, the
// assets left out, the files withheld and the files whose bytes changed.
func githubTables(srcs []*GitHubSource) []web.Table {
	rows := func(each func(s *GitHubSource) []web.Row) func() []web.Row {
		return func() []web.Row {
			var out []web.Row
			for _, s := range srcs {
				out = append(out, each(s)...)
			}
			return out
		}
	}
	line := func(s string) web.Cell { return web.Cell{Lines: []string{s}} }
	return []web.Table{
		{
			Title:   "GitHub release names",
			Empty:   "None.",
			Level:   3,
			Columns: []string{"Package", "Repository", "Source"},
			Rows: rows(func(s *GitHubSource) []web.Row {
				owners := s.Owners()
				var out []web.Row
				for _, name := range sortedKeys(owners) {
					out = append(out, web.Row{Packages: []string{name}, Cells: []web.Cell{line(name), line(owners[name]), line(s.Name())}})
				}
				return out
			}),
		},
		{
			Title:   "GitHub release assets skipped",
			Empty:   "None.",
			Level:   3,
			Columns: []string{"Package", "Repository", "Release", "Asset", "Reason"},
			Rows: rows(func(s *GitHubSource) []web.Row {
				var out []web.Row
				for _, k := range s.Skipped() {
					out = append(out, web.Row{Packages: []string{k.Package}, Cells: []web.Cell{
						line(k.Package), line(k.Repo), line(k.Release), line(k.Asset), line(k.Reason),
					}})
				}
				return out
			}),
		},
		{
			Title:   "GitHub release files withheld",
			Intro:   "Releases of the owning repository publish these files with different bytes.",
			Empty:   "None.",
			Level:   3,
			Columns: []string{"Package", "File", "Releases"},
			Rows: rows(func(s *GitHubSource) []web.Row {
				var out []web.Row
				for _, c := range s.Conflicts() {
					out = append(out, web.Row{Packages: []string{c.Package}, Cells: []web.Cell{
						line(c.Package), line(c.Filename), {Lines: c.Releases},
					}})
				}
				return out
			}),
		},
		{
			Title:   "GitHub release files changed",
			Intro:   "These files are served with bytes other than those first recorded for them.",
			Empty:   "None.",
			Level:   3,
			Columns: []string{"Package", "File", "Source", "First sha256", "Now sha256", "Seen"},
			Rows: rows(func(s *GitHubSource) []web.Row {
				var out []web.Row
				for _, c := range s.Changed() {
					out = append(out, web.Row{Packages: []string{c.Package}, Cells: []web.Cell{
						line(c.Package), line(c.Filename), line(s.Name()),
						{Lines: []string{c.FirstSHA256}, Code: true}, {Lines: []string{c.NewSHA256}, Code: true},
						line(c.Seen.UTC().Format(time.RFC3339)),
					}})
				}
				return out
			}),
		},
	}
}

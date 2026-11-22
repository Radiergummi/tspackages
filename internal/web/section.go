package web

import (
	"html/template"
	"strings"

	"github.com/radiergummi/tspackages/internal/authz"
	"github.com/radiergummi/tspackages/internal/identity"
	"github.com/radiergummi/tspackages/internal/pins"
)

// Cell is one table cell: its lines are joined by <br>, and Code wraps each
// in <code>.
type Cell struct {
	Lines []string
	Code  bool
}

// Row is one table row, shown when the caller may read any of its Packages.
// A row without packages is shown to nobody.
type Row struct {
	Packages []string
	Cells    []Cell
}

// Table is a status-page table that lists rows of one ecosystem.
type Table struct {
	Title string
	Intro string // shown above the table when it has rows
	Empty string // shown instead of the table when it has none
	// Level is the heading level: 2 puts the table in the shared part of the
	// page after "Moved tags", 3 under its section's heading.
	Level   int
	Columns []string
	Rows    func() []Row
}

// Snippet is a client-configuration hint. Intro is trusted HTML and must be
// built only from server-side strings, never request data. Code is plain
// text, shown in a pre block when not empty; "{{host}}" in it is replaced
// with the request host before the text is escaped.
type Snippet struct {
	Intro template.HTML
	Code  string
}

// Section is one ecosystem's part of the status page. It is shown when an
// ecosystem of the same name is mounted.
type Section struct {
	Ecosystem string
	Title     string        // h2
	Match     authz.Matcher // matches the ecosystem's package names against capability rules
	Snippets  []Snippet
	// MovedPackage names the package a moved tag's remote declares, so the
	// page shows the tag only to callers allowed to read that package. Nil:
	// the ecosystem pins nothing and its moved tags are hidden.
	MovedPackage func(pins.MovedTag) string
	// Tables with Level 2 are shown only while the section is, so a table such
	// as Composer's name conflicts is absent when Composer isn't mounted.
	Tables []Table
}

type (
	sectionView struct {
		Title    string
		Snippets []snippetView
		Tables   []tableView // level 3
	}
	snippetView struct {
		Intro template.HTML
		Code  string
	}
	tableView struct {
		Level   int
		Title   string
		Intro   string
		Empty   string
		Columns []string
		Rows    [][]template.HTML
	}
)

// readable reports whether the caller may read any of the packages; an empty
// name is never readable.
func (s Section) readable(c identity.Caller, pkgs []string) bool {
	for _, p := range pkgs {
		if p != "" && authz.Allowed(c.Rules, s.Ecosystem, p, authz.Read, s.Match) {
			return true
		}
	}
	return false
}

func (s Section) view(c identity.Caller, host string) sectionView {
	v := sectionView{Title: s.Title}
	for _, sn := range s.Snippets {
		v.Snippets = append(v.Snippets, snippetView{Intro: sn.Intro, Code: strings.ReplaceAll(sn.Code, "{{host}}", host)})
	}
	for _, t := range s.Tables {
		if t.Level == 3 {
			v.Tables = append(v.Tables, s.tableView(c, t))
		}
	}
	return v
}

func (s Section) tableView(c identity.Caller, t Table) tableView {
	v := tableView{Level: t.Level, Title: t.Title, Intro: t.Intro, Empty: t.Empty, Columns: t.Columns}
	if t.Rows == nil {
		return v
	}
	for _, r := range t.Rows() {
		if !s.readable(c, r.Packages) {
			continue
		}
		cells := make([]template.HTML, len(r.Cells))
		for i, cell := range r.Cells {
			cells[i] = cell.html()
		}
		v.Rows = append(v.Rows, cells)
	}
	return v
}

func (c Cell) html() template.HTML {
	parts := make([]string, len(c.Lines))
	for i, l := range c.Lines {
		parts[i] = template.HTMLEscapeString(l)
		if c.Code {
			parts[i] = "<code>" + parts[i] + "</code>"
		}
	}
	return template.HTML(strings.Join(parts, "<br>")) //nolint:gosec // every line is escaped above
}

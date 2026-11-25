package apt

import (
	"html/template"
	"path"
	"strings"

	"github.com/radiergummi/tspackages/internal/web"
)

// StatusSection is apt's part of the status page: one deb822 stanza per
// source, storage sources (names in storage) first, then registry sources
// with their configured suites and components. A nil signer hides the key
// fingerprint; a nil changed reports nothing.
func StatusSection(storage []string, registry []RegistryStanza, signer *Signer, changed func() []ChangedFile) web.Section {
	var snippets []web.Snippet
	snippets = append(snippets, web.Snippet{
		Intro: template.HTML("apt: install the signing key of the generated repositories (<code>apt/key.asc</code>):"),
		Code:  "curl -fsSL https://{{host}}/apt/key.asc -o /etc/apt/keyrings/tspackages.asc",
	})
	for _, s := range storage {
		snippets = append(snippets, web.Snippet{
			Intro: template.HTML("apt source for a hosted repository (<code>/etc/apt/sources.list.d/tspackages.sources</code>). Replace <code>&lt;suite&gt;</code> with the suite you upload to:"),
			Code: "Types: deb\n" +
				"URIs: https://{{host}}/apt/" + s + "/\n" +
				"Suites: <suite>\n" +
				"Components: main\n" +
				"Signed-By: /etc/apt/keyrings/tspackages.asc",
		})
	}
	for _, r := range registry {
		snippets = append(snippets, web.Snippet{
			Intro: template.HTML("apt source for an upstream repository (a <code>.sources</code> file in <code>/etc/apt/sources.list.d/</code>). tspackages serves the upstream's own signed Release, so trust the upstream's keyring here, not the tspackages key:"),
			Code: "Types: deb\n" +
				"URIs: https://{{host}}/apt/" + r.Name + "/\n" +
				"Suites: " + strings.Join(r.Suites, " ") + "\n" +
				"Components: " + strings.Join(r.Components, " ") + "\n" +
				"# Use the upstream's keyring, e.g. /usr/share/keyrings/debian-archive-keyring.gpg\n" +
				"Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg",
		})
	}
	snippets = append(snippets,
		web.Snippet{
			Intro: template.HTML("apt pinning. Without this file a client is not protected against a claimed name being shadowed by another repository."),
			Code:  "curl -fsSL https://{{host}}/apt/preferences -o /etc/apt/preferences.d/tspackages.pref",
		},
	)
	if len(storage) > 0 {
		snippets = append(snippets, web.Snippet{
			Intro: template.HTML("apt upload (CI needs an <code>apt:</code> write grant):"),
			Code:  "curl -fT pkg.deb https://{{host}}/apt/" + storage[0] + "/<suite>/<component>/",
		})
	}
	if signer != nil {
		snippets = append(snippets, web.Snippet{
			Intro: template.HTML("apt signing key fingerprint:"),
			Code:  signer.Fingerprint(),
		})
	}
	return web.Section{
		Ecosystem: "apt",
		Title:     "apt",
		Match:     Match,
		Snippets:  snippets,
		Tables: []web.Table{
			{
				Title:   "Changed artifacts",
				Intro:   "These upstream files changed after first being seen. The new file is served.",
				Empty:   "None.",
				Level:   3,
				Columns: []string{"Package", "File", "Source", "First sha256", "Now sha256"},
				Rows: func() []web.Row {
					if changed == nil {
						return nil
					}
					var rows []web.Row
					for _, c := range changed() {
						file := path.Base(c.Path)
						pkg, _, _ := strings.Cut(file, "_")
						rows = append(rows, web.Row{
							Packages: []string{pkg},
							Cells: []web.Cell{
								{Lines: []string{pkg}}, {Lines: []string{file}}, {Lines: []string{c.Source}},
								{Lines: []string{c.First}, Code: true}, {Lines: []string{c.Now}, Code: true},
							},
						})
					}
					return rows
				},
			},
		},
	}
}

// RegistryStanza is what the status page shows for one registry source.
type RegistryStanza struct {
	Name               string
	Suites, Components []string
}

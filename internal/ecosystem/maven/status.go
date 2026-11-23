package maven

import (
	"html/template"
	"strings"
	"time"

	"github.com/radiergummi/tspackages/internal/web"
)

// StatusSection is Maven's part of the status page. A nil changed reports
// nothing.
func StatusSection(changed func() []ChangedFile) web.Section {
	return web.Section{
		Ecosystem: "maven",
		Title:     "Maven",
		Match: func(pattern, name string) bool {
			group, artifact, _ := strings.Cut(name, ":")
			return Match(pattern, Coords{Group: group, Artifact: artifact})
		},
		Snippets: []web.Snippet{
			{
				Intro: template.HTML("Maven (<code>~/.m2/settings.xml</code>). No <code>&lt;server&gt;</code> entry or credentials are needed. tspackages must be the only repository, so the mirror covers everything and the profile enables snapshots on it:"),
				Code: "<settings>\n" +
					"  <mirrors>\n" +
					"    <mirror>\n" +
					"      <id>tspackages</id>\n" +
					"      <mirrorOf>*</mirrorOf>\n" +
					"      <url>https://{{host}}/maven/</url>\n" +
					"    </mirror>\n" +
					"  </mirrors>\n" +
					"  <profiles>\n" +
					"    <profile>\n" +
					"      <id>tspackages</id>\n" +
					"      <repositories>\n" +
					"        <repository>\n" +
					"          <id>tspackages</id>\n" +
					"          <url>https://{{host}}/maven/</url>\n" +
					"          <snapshots><enabled>true</enabled></snapshots>\n" +
					"        </repository>\n" +
					"      </repositories>\n" +
					"    </profile>\n" +
					"  </profiles>\n" +
					"  <activeProfiles>\n" +
					"    <activeProfile>tspackages</activeProfile>\n" +
					"  </activeProfiles>\n" +
					"</settings>",
			},
			{
				Intro: template.HTML("Maven deploy (<code>pom.xml</code>). CI needs <code>maven:</code> read and write grants, and no <code>&lt;server&gt;</code> entry:"),
				Code: "<distributionManagement>\n" +
					"  <repository>\n" +
					"    <id>tspackages</id>\n" +
					"    <url>https://{{host}}/maven/</url>\n" +
					"  </repository>\n" +
					"  <snapshotRepository>\n" +
					"    <id>tspackages</id>\n" +
					"    <url>https://{{host}}/maven/</url>\n" +
					"  </snapshotRepository>\n" +
					"</distributionManagement>",
			},
			{
				Intro: template.HTML("Gradle (<code>build.gradle.kts</code>). No <code>credentials</code> block is needed. Use tspackages as the only repository:"),
				Code: "repositories {\n" +
					"    maven { url = uri(\"https://{{host}}/maven/\") }\n" +
					"}",
			},
			{
				Intro: template.HTML("Gradle publish (<code>build.gradle.kts</code>):"),
				Code: "publishing {\n" +
					"    repositories {\n" +
					"        maven { url = uri(\"https://{{host}}/maven/\") }\n" +
					"    }\n" +
					"}",
			},
			{
				Intro: template.HTML("Gradle plugins (<code>settings.gradle.kts</code>). Plugins resolve through the Gradle plugin portal, so keep it and send your private groups to tspackages only. Replace <code>com.example</code> with your own group:"),
				Code: "pluginManagement {\n" +
					"    repositories {\n" +
					"        exclusiveContent {\n" +
					"            forRepository { maven { url = uri(\"https://{{host}}/maven/\") } }\n" +
					"            filter { includeGroupByRegex(\"com\\\\.example(\\\\..*)?\") }\n" +
					"        }\n" +
					"        gradlePluginPortal()\n" +
					"    }\n" +
					"}",
			},
		},
		Tables: []web.Table{
			{
				Title:   "Changed artifacts",
				Intro:   "These upstream files changed after first being seen for the same version. The new file is served.",
				Empty:   "None.",
				Level:   3,
				Columns: []string{"Package", "Version", "File", "Source", "First sha256", "Now sha256", "Seen"},
				Rows: func() []web.Row {
					if changed == nil {
						return nil
					}
					var rows []web.Row
					for _, c := range changed() {
						rows = append(rows, web.Row{
							// Rules match lowercased names; c.Package is exact.
							Packages: []string{strings.ToLower(c.Package)},
							Cells: []web.Cell{
								{Lines: []string{c.Package}}, {Lines: []string{c.Version}}, {Lines: []string{c.File}}, {Lines: []string{c.Source}},
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

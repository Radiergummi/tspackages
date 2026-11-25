package apt

import "testing"

func TestRenderPreferences(t *testing.T) {
	got := string(RenderPreferences([]Uploader{
		&fakeSource{name: "hosted", claims: []string{"acme-*", "acme"}},
		&fakeSource{name: "team", claims: []string{"team-*"}},
	}))
	want := `Package: acme-* acme
Pin: release o=tspackages,l=hosted
Pin-Priority: 1001

Package: acme-* acme
Pin: release *
Pin-Priority: -1

Package: team-*
Pin: release o=tspackages,l=team
Pin-Priority: 1001

Package: team-*
Pin: release *
Pin-Priority: -1
`
	if got != want {
		t.Fatalf("got:\n%s\nwant:\n%s", got, want)
	}
}

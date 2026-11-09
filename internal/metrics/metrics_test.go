package metrics

import "testing"

func TestRedactRemote(t *testing.T) {
	for in, want := range map[string]string{
		"https://tok@github.com/a/b.git":     "https://github.com/a/b.git",
		"https://user:pw@github.com/a/b.git": "https://github.com/a/b.git",
		"https://github.com/a/b@c.git":       "https://github.com/a/b@c.git",
		"ssh://git@github.com/a/b.git":       "ssh://github.com/a/b.git",
		"git@github.com:a/b.git":             "git@github.com:a/b.git",
		"https://github.com/a/b.git":         "https://github.com/a/b.git",
		"/srv/repos/a":                       "/srv/repos/a",
	} {
		if got := RedactRemote(in); got != want {
			t.Errorf("RedactRemote(%q) = %q, want %q", in, got, want)
		}
	}
}

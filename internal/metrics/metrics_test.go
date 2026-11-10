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

func TestSetBuildInfoKeepsOneSeries(t *testing.T) {
	SetBuildInfo("v0.0.1", "aaa")
	SetBuildInfo("v0.0.2", "bbb")
	mfs, err := Registry().Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, mf := range mfs {
		if mf.GetName() != "tspackages_build_info" {
			continue
		}
		if len(mf.GetMetric()) != 1 {
			t.Fatalf("%d series, want 1", len(mf.GetMetric()))
		}
		labels := map[string]string{}
		for _, l := range mf.GetMetric()[0].GetLabel() {
			labels[l.GetName()] = l.GetValue()
		}
		if labels["version"] != "v0.0.2" || labels["commit"] != "bbb" || mf.GetMetric()[0].GetGauge().GetValue() != 1 {
			t.Fatalf("series %v = %v", labels, mf.GetMetric()[0].GetGauge().GetValue())
		}
		return
	}
	t.Fatal("tspackages_build_info not registered")
}

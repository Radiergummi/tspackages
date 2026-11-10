package main

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

func TestScrubEnv(t *testing.T) {
	for _, k := range []string{"TSP_SECRET", "PATH", "HOME", "USER", "TMPDIR", "LANG", "LC_ALL", "TS_AUTHKEY", "TS_AUTH_KEY", "TS_CLIENT_SECRET", "TS_ID_TOKEN"} {
		t.Setenv(k, "v")
	}
	scrubEnv([]string{"TSP_SECRET", "PATH", "HOME", "USER", "TMPDIR", "LANG", "LC_ALL"})
	if _, ok := os.LookupEnv("TSP_SECRET"); ok {
		t.Error("referenced secret not unset")
	}
	for _, k := range []string{"PATH", "HOME", "USER", "TMPDIR", "LANG", "LC_ALL"} {
		if _, ok := os.LookupEnv(k); !ok {
			t.Errorf("%s unset", k)
		}
	}
	scrubEnv(tsnetEnv)
	for _, k := range []string{"TS_AUTHKEY", "TS_AUTH_KEY", "TS_CLIENT_SECRET", "TS_ID_TOKEN"} {
		if _, ok := os.LookupEnv(k); ok {
			t.Errorf("%s not unset", k)
		}
	}
}

func TestNewLogger(t *testing.T) {
	var buf bytes.Buffer
	log, err := newLogger(&buf, "warn", "text")
	if err != nil {
		t.Fatal(err)
	}
	log.Info("hidden")
	log.Warn("shown")
	if out := buf.String(); strings.Contains(out, "hidden") || !strings.Contains(out, "level=WARN msg=shown") {
		t.Fatalf("text output: %q", out)
	}
	buf.Reset()
	log, _ = newLogger(&buf, "info", "json")
	log.Info("x")
	if !strings.HasPrefix(buf.String(), `{"time":`) {
		t.Fatalf("json output: %q", buf.String())
	}
	if _, err := newLogger(&buf, "loud", "json"); err == nil {
		t.Error("bad level accepted")
	}
	if _, err := newLogger(&buf, "info", "xml"); err == nil {
		t.Error("bad format accepted")
	}
}

package main

import (
	"os"
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

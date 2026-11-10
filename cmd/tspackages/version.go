package main

import "runtime/debug"

// version is set by the release build with -ldflags "-X main.version=v1.2.3"
// (see the Makefile and the Dockerfile's VERSION build arg). A plain build
// says "dev"; `go install` reports its module version.
var version = "dev"

// commit is set with -X main.commit for builds without a .git (the Dockerfile's
// REVISION build arg). Elsewhere Go's VCS stamp is used.
var commit = ""

// buildVersion returns the version and commit this binary was built from.
func buildVersion() (v, c string) {
	v, c = version, commit
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return v, c
	}
	if v == "dev" && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
		v = bi.Main.Version
	}
	for _, s := range bi.Settings {
		if c == "" && s.Key == "vcs.revision" {
			c = s.Value
		}
	}
	return v, c
}

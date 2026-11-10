package composer

import "testing"

// The tables below are ported from composer/semver (MIT),
// tests/VersionParserTest.php: successfulNormalizedVersions,
// failingNormalizedVersions and successfulNormalizedBranches.

var normalizeSuccess = []struct{ name, in, want string }{
	{"none", "1.0.0", "1.0.0.0"},
	{"none/2", "1.2.3.4", "1.2.3.4"},
	{"parses state", "1.0.0RC1dev", "1.0.0.0-RC1-dev"},
	{"zero stability number", "1.0.0-RC0", "1.0.0.0-RC0"},
	{"zero stability number after dot", "1.0.0-RC.0", "1.0.0.0-RC0"},
	{"CI parsing", "1.0.0-rC15-dev", "1.0.0.0-RC15-dev"},
	{"delimiters", "1.0.0.RC.15-dev", "1.0.0.0-RC15-dev"},
	{"RC uppercase", "1.0.0-rc1", "1.0.0.0-RC1"},
	{"patch replace", "1.0.0.pl3-dev", "1.0.0.0-patch3-dev"},
	{"forces w.x.y.z", "1.0-dev", "1.0.0.0-dev"},
	{"forces w.x.y.z/2", "0", "0.0.0.0"},
	{"forces w.x.y.z/maximum major", "99999", "99999.0.0.0"},
	{"parses long", "10.4.13-beta", "10.4.13.0-beta"},
	{"parses long/2", "10.4.13beta2", "10.4.13.0-beta2"},
	{"parses long/semver", "10.4.13beta.2", "10.4.13.0-beta2"},
	{"parses long/semver2", "v1.13.11-beta.0", "1.13.11.0-beta0"},
	{"parses long/semver3", "1.13.11.0-beta0", "1.13.11.0-beta0"},
	{"expand shorthand", "10.4.13-b", "10.4.13.0-beta"},
	{"expand shorthand/2", "10.4.13-b5", "10.4.13.0-beta5"},
	{"strips leading v", "v1.0.0", "1.0.0.0"},
	{"parses dates y-m as classical", "2010.01", "2010.01.0.0"},
	{"parses dates w/ . as classical", "2010.01.02", "2010.01.02.0"},
	{"parses dates y.m.Y as classical", "2010.1.555", "2010.1.555.0"},
	{"parses dates y.m.Y/2 as classical", "2010.10.200", "2010.10.200.0"},
	{"parses CalVer YYYYMMDD (as MAJOR) versions", "20230131.0.0", "20230131.0.0"},
	{"parses CalVer YYYYMMDDhhmm (as MAJOR) versions", "202301310000.0.0", "202301310000.0.0"},
	{"strips v/datetime", "v20100102", "20100102"},
	{"parses dates no delimiter", "20100102", "20100102"},
	{"parses dates no delimiter/2", "20100102.0", "20100102.0"},
	{"parses dates no delimiter/3", "20100102.1.0", "20100102.1.0"},
	{"parses dates no delimiter/4", "20100102.0.3", "20100102.0.3"},
	{"parses dates no delimiter/earliest year", "100000", "100000"},
	{"parses dates w/ - and .", "2010-01-02-10-20-30.0.3", "2010.01.02.10.20.30.0.3"},
	{"parses dates w/ - and ./2", "2010-01-02-10-20-30.5", "2010.01.02.10.20.30.5"},
	{"parses dates w/ -", "2010-01-02", "2010.01.02"},
	{"parses dates w/ .", "2012.06.07", "2012.06.07.0"},
	{"parses numbers", "2010-01-02.5", "2010.01.02.5"},
	{"parses dates y.m.Y", "2010.1.555", "2010.1.555.0"},
	{"parses datetime", "20100102-203040", "20100102.203040"},
	{"parses date dev", "20100102.x-dev", "20100102.9999999.9999999.9999999-dev"},
	{"parses datetime dev", "20100102.203040.x-dev", "20100102.203040.9999999.9999999-dev"},
	{"parses dt+number", "20100102203040-10", "20100102203040.10"},
	{"parses dt+patch", "20100102-203040-p1", "20100102.203040-patch1"},
	{"parses dt Ym", "201903.0", "201903.0"},
	{"parses dt Ym dev", "201903.x-dev", "201903.9999999.9999999.9999999-dev"},
	{"parses dt Ym+patch", "201903.0-p2", "201903.0-patch2"},
	{"parses master", "dev-master", "dev-master"},
	{"parses master w/o dev", "master", "dev-master"},
	{"parses trunk", "dev-trunk", "dev-trunk"},
	{"parses branches", "1.x-dev", "1.9999999.9999999.9999999-dev"},
	{"parses arbitrary", "dev-feature-foo", "dev-feature-foo"},
	{"parses arbitrary/2", "DEV-FOOBAR", "dev-FOOBAR"},
	{"parses arbitrary/3", "dev-feature/foo", "dev-feature/foo"},
	{"parses arbitrary/4", "dev-feature+issue-1", "dev-feature+issue-1"},
	{"ignores aliases", "dev-master as 1.0.0", "dev-master"},
	{"ignores aliases/2", "dev-load-varnish-only-when-used as ^2.0", "dev-load-varnish-only-when-used"},
	{"ignores aliases/3", "dev-load-varnish-only-when-used@dev as ^2.0@dev", "dev-load-varnish-only-when-used"},
	{"ignores stability", "1.0.0+foo@dev", "1.0.0.0"},
	{"ignores stability/2", "dev-load-varnish-only-when-used@stable", "dev-load-varnish-only-when-used"},
	{"semver metadata/2", "1.0.0-beta.5+foo", "1.0.0.0-beta5"},
	{"semver metadata/3", "1.0.0+foo", "1.0.0.0"},
	{"semver metadata/4", "1.0.0-alpha.3.1+foo", "1.0.0.0-alpha3.1"},
	{"semver metadata/5", "1.0.0-alpha2.1+foo", "1.0.0.0-alpha2.1"},
	{"semver metadata/6", "1.0.0-alpha-2.1-3+foo", "1.0.0.0-alpha2.1-3"},
	{"metadata w/ alias", "1.0.0+foo as 2.0", "1.0.0.0"},
	{"keep zero-padding", "00.01.03.04", "00.01.03.04"},
	{"keep zero-padding/2", "000.001.003.004", "000.001.003.004"},
	{"keep zero-padding/3", "0.000.103.204", "0.000.103.204"},
	{"keep zero-padding/4", "0700", "0700.0.0.0"},
	{"keep zero-padding/5", "041.x-dev", "041.9999999.9999999.9999999-dev"},
	{"keep zero-padding/6", "dev-041.003", "dev-041.003"},
	{"dev with mad name", "dev-1.0.0-dev<1.0.5-dev", "dev-1.0.0-dev<1.0.5-dev"},
	{"dev prefix with spaces", "dev-foo bar", "dev-foo bar"},
	{"space padding", " 1.0.0", "1.0.0.0"},
	{"space padding/2", "1.0.0 ", "1.0.0.0"},
}

var normalizeFailures = []struct{ name, in string }{
	{"empty ", ""},
	{"invalid chars", "a"},
	{"invalid type", "1.0.0-meh"},
	{"too many bits", "1.0.0.0.0"},
	{"non-dev arbitrary", "feature-foo"},
	{"metadata w/ space", "1.0.0+foo bar"},
	{"maven style release", "1.0.1-SNAPSHOT"},
	{"dev with less than", "1.0.0<1.0.5-dev"},
	{"dev with less than/2", "1.0.0-dev<1.0.5-dev"},
	{"dev suffix with spaces", "foo bar-dev"},
	{"any with spaces", "1.0 .2"},
	{"no version, no alias", " as "},
	{"no version, only alias", " as 1.2"},
	{"just an operator", "^"},
	{"just an operator/2", "^8 || ^"},
	{"just an operator/3", "~"},
	{"just an operator/4", "~1 ~"},
	{"constraint", "~1"},
	{"constraint/2", "^1"},
	{"constraint/3", "1.*"},
	{"date versions with 4 bits", "20100102.0.3.4"},
	{"date versions with 4 bits/earliest year", "100000.0.0.0"},
	{"invalid CalVer (as MAJOR) versions/YYYYMMD", "2023013.0.0"},
	{"invalid CalVer (as MAJOR) versions/YYYYMMDDh", "202301311.0.0"},
	{"invalid CalVer (as MAJOR) versions/YYYYMMDDhhm", "20230131000.0.0"},
	{"invalid CalVer (as MAJOR) versions/YYYYMMDDhhmmX", "2023013100000.0.0"},
}

var normalizeBranchCases = []struct{ name, in, want string }{
	{"parses x", "v1.x", "1.9999999.9999999.9999999-dev"},
	{"parses *", "v1.*", "1.9999999.9999999.9999999-dev"},
	{"parses digits", "v1.0", "1.0.9999999.9999999-dev"},
	{"parses digits/2", "2.0", "2.0.9999999.9999999-dev"},
	{"parses long x", "v1.0.x", "1.0.9999999.9999999-dev"},
	{"parses long *", "v1.0.3.*", "1.0.3.9999999-dev"},
	{"parses long digits", "v2.4.0", "2.4.0.9999999-dev"},
	{"parses long digits/2", "2.4.4", "2.4.4.9999999-dev"},
	{"parses master", "master", "dev-master"},
	{"parses trunk", "trunk", "dev-trunk"},
	{"parses arbitrary", "feature-a", "dev-feature-a"},
	{"parses arbitrary/2", "FOOBAR", "dev-FOOBAR"},
	{"parses arbitrary/3", "feature+issue-1", "dev-feature+issue-1"},
}

func TestNormalizeVersionComposerFixtures(t *testing.T) {
	for _, tc := range normalizeSuccess {
		t.Run("ok/"+tc.name, func(t *testing.T) {
			got, err := NormalizeVersion(tc.in)
			if err != nil || got != tc.want {
				t.Fatalf("NormalizeVersion(%q) = %q, %v; want %q", tc.in, got, err, tc.want)
			}
		})
	}
	for _, tc := range normalizeFailures {
		t.Run("fail/"+tc.name, func(t *testing.T) {
			if got, err := NormalizeVersion(tc.in); err == nil {
				t.Fatalf("NormalizeVersion(%q) = %q, want error", tc.in, got)
			}
		})
	}
}

func TestNormalizeBranchComposerFixtures(t *testing.T) {
	for _, tc := range normalizeBranchCases {
		t.Run(tc.name, func(t *testing.T) {
			v, got := NormalizeBranch(tc.in)
			if got != tc.want || v != tc.in {
				t.Fatalf("NormalizeBranch(%q) = %q, %q; want %q", tc.in, v, got, tc.want)
			}
		})
	}
}

func TestCompareNormalized(t *testing.T) {
	asc := []string{"1.0.0.0-alpha1", "1.0.0.0-alpha2", "1.0.0.0-beta1", "1.0.0.0-RC1", "1.0.0.0", "1.0.0.0-patch1", "1.0.1.0", "1.2.0.0", "1.10.0.0", "2.0.0.0"}
	for i := 0; i+1 < len(asc); i++ {
		if compareNormalized(asc[i], asc[i+1]) >= 0 || compareNormalized(asc[i+1], asc[i]) <= 0 {
			t.Errorf("%s should sort below %s", asc[i], asc[i+1])
		}
	}
	if compareNormalized("1.0.0.0", "1.0.0.0") != 0 || compareNormalized("1.0.0", "1.0.0.0") != 0 {
		t.Error("equal versions must compare 0")
	}
	if compareNormalized("1.0.0.0-dev", "1.0.0.0-alpha1") >= 0 {
		t.Error("dev sorts below alpha")
	}
}

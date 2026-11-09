package digest

import "testing"

func TestOf(t *testing.T) {
	s1, s256 := Of([]byte("abc"))
	if s1 != "a9993e364706816aba3e25717850c26c9cd0d89d" ||
		s256 != "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" {
		t.Fatalf("Of = %s %s", s1, s256)
	}
}

func TestIsHex(t *testing.T) {
	for _, tc := range []struct {
		s    string
		lens []int
		want bool
	}{
		{"0123456789abcdef", []int{16}, true},
		{"0123456789abcdef", []int{40, 64}, false},
		{"0123456789ABCDEF", []int{16}, false},
		{"0123456789abcdeg", []int{16}, false},
		{"", []int{0}, true},
	} {
		if got := IsHex(tc.s, tc.lens...); got != tc.want {
			t.Errorf("IsHex(%q, %v) = %v", tc.s, tc.lens, got)
		}
	}
}

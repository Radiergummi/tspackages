package storage

import "testing"

func TestFS(t *testing.T) {
	d, err := NewFS(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	runDriverSuite(t, d)
}

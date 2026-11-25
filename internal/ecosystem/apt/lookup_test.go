package apt

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ulikunitz/xz"
)

func TestLookupStreams(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a 60,000-package index")
	}
	const n = 60000
	e := newRegEnv(t)
	// Descriptions make the decompressed index larger than the bound, so
	// holding it whole fails the test.
	desc := strings.Repeat(" Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor.\n", 6)
	var xzBuf bytes.Buffer
	w, err := xz.NewWriter(&xzBuf)
	if err != nil {
		t.Fatal(err)
	}
	plainSize := 0
	for i := range n {
		sum := sha256.Sum256(fmt.Appendf(nil, "%d", i))
		s := fmt.Sprintf("Package: pkg%05d\nVersion: 1:1.%d-1\nArchitecture: amd64\nFilename: pool/main/p/pkg%05d/pkg%05d_1.%d-1_amd64.deb\n"+
			"Size: %d\nSHA256: %s\nDescription: package %d\n%s\n", i, i, i, i, i, 1000+i, hex.EncodeToString(sum[:]), i, desc)
		plainSize += len(s)
		if _, err := w.Write([]byte(s)); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if plainSize < 32<<20 {
		t.Fatalf("generated index is only %d bytes decompressed", plainSize)
	}
	idx := xzBuf.Bytes()
	sum := hexSHA256(idx)
	text := fmt.Sprintf("Suite: %s\nDate: %s\nAcquire-By-Hash: yes\nSHA256:\n %s %d %s.xz\n", regSuite,
		e.clock.Add(-time.Hour).Format(releaseDate), sum, len(idx), pkgsPath)
	e.up.set("dists/"+regSuite+"/main/binary-amd64/by-hash/SHA256/"+sum, idx)
	in, err := signer(t, e.key).ClearSign([]byte(text))
	if err != nil {
		t.Fatal(err)
	}
	e.up.set("dists/"+regSuite+"/InRelease", in)

	ctx := context.Background()
	st, err := e.src.current(ctx, regSuite)
	if err != nil {
		t.Fatal(err)
	}
	defer debug.SetGCPercent(debug.SetGCPercent(10))
	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)
	var peak atomic.Uint64
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Go(func() {
		var m runtime.MemStats
		for {
			runtime.ReadMemStats(&m)
			if m.HeapAlloc > peak.Load() {
				peak.Store(m.HeapAlloc)
			}
			select {
			case <-stop:
				return
			case <-time.After(5 * time.Millisecond):
			}
		}
	})
	want := "pool/main/p/pkg30000/pkg30000_1.30000-1_amd64.deb"
	got, found, err := e.src.find(ctx, regSuite, st, want)
	close(stop)
	wg.Wait()
	if err != nil || !found {
		t.Fatalf("find = %+v, %v, %v", got, found, err)
	}
	wantSum := sha256.Sum256([]byte("30000"))
	if got.Path != want || got.Package != "pkg30000" || got.Version != "1:1.30000-1" || got.Size != 31000 ||
		got.SHA256 != hex.EncodeToString(wantSum[:]) {
		t.Errorf("entry = %+v", got)
	}
	growth := int64(peak.Load()) - int64(before.HeapAlloc)
	t.Logf("heap growth building the lookup: %.1f MiB", float64(growth)/(1<<20))
	if growth >= 32<<20 {
		t.Errorf("heap grew by %d MiB building the lookup", growth>>20)
	}
	if _, found, err := e.src.find(ctx, regSuite, st, "pool/main/p/pkg30000/absent.deb"); err != nil || found {
		t.Errorf("absent path: found %v, %v", found, err)
	}
}

func TestLookupSkipsBadEntries(t *testing.T) {
	e := newRegEnv(t)
	good := "pool/main/g/good/good_1.0_amd64.deb"
	sum := strings.Repeat("ab", 32)
	var idx strings.Builder
	for _, fn := range []string{"/etc/passwd", "pool/../../x.deb", "pool//x.deb", "", good} {
		fmt.Fprintf(&idx, "Package: good\nVersion: 1.0\nFilename: %s\nSize: 1\nSHA256: %s\n\n", fn, sum)
	}
	fmt.Fprintf(&idx, "Package: nohash\nVersion: 1.0\nFilename: pool/n.deb\nSize: 1\n\n")
	e.publishIndex(t, []byte(idx.String()))
	ctx := context.Background()
	st, err := e.src.current(ctx, regSuite)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"/etc/passwd", "pool/../../x.deb", "pool//x.deb", "pool/n.deb"} {
		if _, found, err := e.src.find(ctx, regSuite, st, p); err != nil || found {
			t.Errorf("find(%q): found %v, %v", p, found, err)
		}
	}
	if got, found, err := e.src.find(ctx, regSuite, st, good); err != nil || !found || got.SHA256 != sum {
		t.Errorf("find(good) = %+v, %v, %v", got, found, err)
	}
}

package apt

import (
	"bytes"
	"cmp"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/radiergummi/tspackages/internal/flight"
	"github.com/radiergummi/tspackages/internal/storage"
	"github.com/ulikunitz/xz"
	"golang.org/x/sync/errgroup"
)

// lookupShards is the number of shard objects per lookup, at most 256: the
// first byte of sha256(pool path), modulo lookupShards, picks one. Tests
// lower it.
var lookupShards = 256

const (
	// shardWriters bounds the shard objects written at once.
	shardWriters = 16
	// lookupTimeout bounds building a lookup, its index downloads
	// included.
	lookupTimeout = 30 * time.Minute
	// maxIndexStanza caps a stanza of an upstream Packages index.
	maxIndexStanza = 1 << 20
	// maxPackagesIndex caps a Packages index decompressed.
	maxPackagesIndex = 1 << 30
	// maxShard caps a shard object read back from the cache.
	maxShard = 64 << 20
	// maxFilename caps a Filename in an upstream index.
	maxFilename = 4096
)

// lookupEntry is a pool file a verified Packages index lists.
type lookupEntry struct {
	Path    string `json:"path"` // Filename: from the repository root
	SHA256  string `json:"sha256"`
	Size    int64  `json:"size"`
	Package string `json:"package"`
	Version string `json:"version"` // with its epoch
}

// The pool lookup of a suite's Release maps each pool path its Packages
// indexes list (for every configured component and architecture, and
// "all") to its entry. It is built once per Release, identified by the
// sha256 of its verified bytes, and stored as lookupShards objects (written
// shardWriters at a time), each a JSON array of entries sorted by path:
//
//	apt/<src>/lookup/<release sha256>/<xx>.json
//
// Every shard is written, empty or not, so a missing one means the lookup
// was never built or was evicted, and is built again. Building streams each
// index through Stanzas and keeps only the entries, grouped by shard; the
// index is never held whole.

func (s *RegistrySource) shardKey(sum string, shard int) string {
	return fmt.Sprintf("apt/%s/lookup/%s/%02x.json", s.cfg.Name, sum, shard)
}

func shardOf(poolPath string) int {
	h := sha256.Sum256([]byte(poolPath))
	return int(h[0]) % lookupShards
}

// find returns rel's entry in the lookup of suite's Release st, building
// the lookup (once for concurrent callers) when its shard is missing.
func (s *RegistrySource) find(ctx context.Context, suite string, st *relState, rel string) (lookupEntry, bool, error) {
	key := s.shardKey(st.sum, shardOf(rel))
	es, err := s.readShard(ctx, key)
	if errors.Is(err, storage.ErrNotFound) {
		if _, err := flight.Do(ctx, &s.lookupFlight, suite+"\x00"+st.sum, func() (struct{}, error) {
			return struct{}{}, s.build(ctx, suite, st)
		}); err != nil {
			return lookupEntry{}, false, err
		}
		es, err = s.readShard(ctx, key)
		if errors.Is(err, storage.ErrNotFound) {
			return lookupEntry{}, false, fmt.Errorf("apt pool lookup shard %s missing right after it was built", key)
		}
	}
	if err != nil {
		return lookupEntry{}, false, err
	}
	i, found := slices.BinarySearchFunc(es, rel, func(e lookupEntry, p string) int { return cmp.Compare(e.Path, p) })
	if !found {
		return lookupEntry{}, false, nil
	}
	return es[i], true, nil
}

func (s *RegistrySource) readShard(ctx context.Context, key string) ([]lookupEntry, error) {
	rc, _, err := s.cache.Get(ctx, key)
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	var es []lookupEntry
	if err := json.NewDecoder(io.LimitReader(rc, maxShard)).Decode(&es); err != nil {
		return nil, fmt.Errorf("apt pool lookup shard %s: %w", key, err)
	}
	return es, nil
}

// build builds the lookup of suite's Release st. It runs on its own
// context: a client leaving does not cancel it while another waits.
func (s *RegistrySource) build(ctx context.Context, suite string, st *relState) error {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), lookupTimeout)
	defer cancel()
	// Entries as "path\tsha256\tsize\tpackage\tversion\n" lines, by shard:
	// none of the fields can hold a tab or a newline.
	shards := make([][]byte, lookupShards)
	skipped := 0
	for _, comp := range s.cfg.Components {
		for _, arch := range s.archs {
			fh, ok := pickIndex(st, comp, arch)
			if !ok {
				continue
			}
			err := s.scanIndex(ctx, suite, st, fh, func(e lookupEntry, ok bool) {
				if !ok {
					skipped++
					return
				}
				i := shardOf(e.Path)
				shards[i] = fmt.Appendf(shards[i], "%s\t%s\t%d\t%s\t%s\n", e.Path, e.SHA256, e.Size, e.Package, e.Version)
			})
			if err != nil {
				s.log.Warn("apt pool lookup build failed", "source", s.cfg.Name, "suite", suite, "index", fh.Path, "error", err)
				return fmt.Errorf("apt index %s of %s: %w", fh.Path, suite, err)
			}
		}
	}
	if skipped > 0 {
		s.log.Warn("apt index entries skipped: malformed Filename, SHA256, Size, Package or Version", "source", s.cfg.Name,
			"suite", suite, "count", skipped)
	}
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(shardWriters)
	for i := range shards {
		lines := shards[i]
		shards[i] = nil
		g.Go(func() error {
			es := parseShardLines(lines)
			// Stable: the first index listing a path wins.
			slices.SortStableFunc(es, func(a, b lookupEntry) int { return cmp.Compare(a.Path, b.Path) })
			es = slices.CompactFunc(es, func(a, b lookupEntry) bool { return a.Path == b.Path })
			if es == nil {
				es = []lookupEntry{}
			}
			b, err := json.Marshal(es)
			if err != nil {
				return err
			}
			if err := s.cache.Put(gctx, s.shardKey(st.sum, i), bytes.NewReader(b)); err != nil {
				return fmt.Errorf("cache apt pool lookup: %w", err)
			}
			return nil
		})
	}
	return g.Wait()
}

func parseShardLines(b []byte) []lookupEntry {
	var es []lookupEntry
	for line := range strings.SplitSeq(strings.TrimSuffix(string(b), "\n"), "\n") {
		f := strings.Split(line, "\t")
		if len(f) != 5 {
			continue // only the empty shard's single empty line
		}
		size, _ := strconv.ParseInt(f[2], 10, 64)
		es = append(es, lookupEntry{Path: f[0], SHA256: f[1], Size: size, Package: f[3], Version: f[4]})
	}
	return es
}

// pickIndex returns the best variant of comp's binary-arch Packages index
// the Release lists: .xz, else .gz, else uncompressed.
func pickIndex(st *relState, comp, arch string) (FileHash, bool) {
	base := comp + "/binary-" + arch + "/Packages"
	for _, ext := range []string{".xz", ".gz", ""} {
		if fh, ok := st.files[base+ext]; ok {
			return fh, true
		}
	}
	return FileHash{}, false
}

// scanIndex calls add for every stanza of the Packages index fh, with
// ok false for one that names no usable pool file. The index is verified
// before it is decompressed: a download is read to its end (and so
// cached) first, then read back.
func (s *RegistrySource) scanIndex(ctx context.Context, suite string, st *relState, fh FileHash, add func(lookupEntry, bool)) error {
	body, _, hit, err := s.openListed(ctx, suite, st, fh)
	if err != nil {
		return err
	}
	if !hit {
		_, err := io.Copy(io.Discard, body)
		body.Close()
		if err != nil {
			return err
		}
		if body, _, _, err = s.openListed(ctx, suite, st, fh); err != nil {
			return err
		}
	}
	defer body.Close()
	var dec io.Reader = body
	switch {
	case strings.HasSuffix(fh.Path, ".xz"):
		z, err := xz.NewReader(body)
		if err != nil {
			return err
		}
		dec = z
	case strings.HasSuffix(fh.Path, ".gz"):
		z, err := gzip.NewReader(body)
		if err != nil {
			return err
		}
		defer z.Close()
		dec = z
	}
	lr := &io.LimitedReader{R: dec, N: maxPackagesIndex + 1}
	for stanza, err := range Stanzas(lr, maxIndexStanza) {
		if err != nil {
			return err
		}
		add(entryOf(stanza))
	}
	if lr.N <= 0 {
		return fmt.Errorf("exceeds %d bytes decompressed", int64(maxPackagesIndex))
	}
	// To the end: a cached copy is checked against its hash on its last
	// byte.
	_, err = io.Copy(io.Discard, body)
	return err
}

// entryOf returns the lookup entry a Packages stanza describes, and false
// when one of its fields is missing or malformed.
func entryOf(st Stanza) (lookupEntry, bool) {
	fn, _ := st.Get("Filename")
	sum, _ := st.Get("SHA256")
	size, _ := st.Get("Size")
	pkg, _ := st.Get("Package")
	ver, _ := st.Get("Version")
	sum = strings.ToLower(sum)
	n, err := strconv.ParseInt(size, 10, 64)
	if err != nil || n < 0 || !validFilename(fn) || !isHex64(sum) || !ValidName(pkg) || !ValidVersion(ver) {
		return lookupEntry{}, false
	}
	return lookupEntry{Path: fn, SHA256: sum, Size: n, Package: pkg, Version: ver}, true
}

// validFilename reports whether fn is a relative path of non-empty
// segments, none "." or "..", without spaces or control characters.
func validFilename(fn string) bool {
	if fn == "" || len(fn) > maxFilename || fn[0] == '/' {
		return false
	}
	for _, r := range fn {
		if r <= ' ' || r == 0x7f {
			return false
		}
	}
	for seg := range strings.SplitSeq(fn, "/") {
		if seg == "" || seg == "." || seg == ".." {
			return false
		}
	}
	return true
}

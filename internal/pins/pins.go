// Package pins records trust-on-first-use git tag pins in the state store.
package pins

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/radiergummi/tspackages/internal/storage"
)

// ErrCorrupt marks a pin file that cannot be decoded or holds an invalid SHA.
var ErrCorrupt = errors.New("pins: corrupt pin")

var shaRE = regexp.MustCompile(`^([0-9a-f]{40}|[0-9a-f]{64})$`)

// MovedTag is a tag whose upstream SHA differs from its pin. Seen is the
// newly observed SHA.
type MovedTag struct {
	Ecosystem, Source, Remote, Tag string
	Pinned, Seen                   string
}

type pinFile struct {
	Tag       string    `json:"tag"`
	SHA       string    `json:"sha"`
	FirstSeen time.Time `json:"first_seen"`
}

// Store pins tags in the state store. It is safe for concurrent use.
type Store struct {
	d storage.Driver

	mu    sync.Mutex
	moved map[[4]string]MovedTag
	cache map[string]pinFile // by key; a pin never changes once written
}

func New(d storage.Driver) *Store {
	return &Store{d: d, moved: map[[4]string]MovedTag{}, cache: map[string]pinFile{}}
}

// Pin records sha for the tag on first sight and returns the pinned SHA. If
// the tag was pinned to a different SHA, it returns the pinned one with
// moved=true and remembers the move.
func (s *Store) Pin(ctx context.Context, ecosystem, source, remote, tag, sha string) (pinned string, moved bool, err error) {
	if !shaRE.MatchString(sha) {
		return "", false, fmt.Errorf("pins: invalid sha %q", sha)
	}
	key := keyPrefix(ecosystem, source, remote) + storage.EscapeSegment(tag) + ".json"
	fresh := pinFile{Tag: tag, SHA: sha, FirstSeen: time.Now().UTC()}
	body, err := json.Marshal(fresh)
	if err != nil {
		return "", false, err
	}
	_, err = s.d.PutIfAbsent(ctx, key, bytes.NewReader(body))
	if err == nil {
		s.mu.Lock()
		s.cache[key] = fresh // replaces a stale entry for a pin deleted by an operator
		s.mu.Unlock()
		return sha, false, nil
	}
	if !errors.Is(err, storage.ErrExists) {
		return "", false, err
	}
	pf, err := s.read(ctx, key)
	if err != nil {
		return "", false, err
	}
	if pf.SHA == sha {
		return pf.SHA, false, nil
	}
	s.mu.Lock()
	s.moved[[4]string{ecosystem, source, remote, tag}] = MovedTag{
		Ecosystem: ecosystem, Source: source, Remote: remote, Tag: tag, Pinned: pf.SHA, Seen: sha,
	}
	s.mu.Unlock()
	return pf.SHA, true, nil
}

func keyPrefix(ecosystem, source, remote string) string {
	return "pins/" + ecosystem + "/" + source + "/" + storage.EscapeSegment(remote) + "/"
}

// Pin is one stored pin.
type Pin struct {
	Tag       string
	SHA       string
	FirstSeen time.Time
}

// read returns the pin stored at key. Valid pins are cached, since a pin is
// immutable once written; corrupt ones are re-read every time.
func (s *Store) read(ctx context.Context, key string) (pinFile, error) {
	s.mu.Lock()
	pf, ok := s.cache[key]
	s.mu.Unlock()
	if ok {
		return pf, nil
	}
	rc, _, err := s.d.Get(ctx, key)
	if err != nil {
		return pinFile{}, err
	}
	defer rc.Close()
	raw, err := io.ReadAll(rc)
	if err != nil {
		return pinFile{}, err
	}
	if err := json.Unmarshal(raw, &pf); err != nil {
		return pinFile{}, fmt.Errorf("%w %s: %v", ErrCorrupt, key, err)
	}
	if !shaRE.MatchString(pf.SHA) {
		return pinFile{}, fmt.Errorf("%w %s: invalid sha", ErrCorrupt, key)
	}
	s.mu.Lock()
	s.cache[key] = pf
	s.mu.Unlock()
	return pf, nil
}

// List returns every readable pin of the remote, sorted by tag. Pins whose tag
// no longer exists upstream are included. Corrupt pins are left out and
// returned in corrupt, so one bad file does not hide the others; err is a
// failure to list or read at all.
func (s *Store) List(ctx context.Context, ecosystem, source, remote string) (pins []Pin, corrupt []error, err error) {
	prefix := keyPrefix(ecosystem, source, remote)
	var keys []string
	listed := map[string]bool{}
	for info, err := range s.d.List(ctx, prefix) {
		if err != nil {
			return nil, nil, err
		}
		keys = append(keys, info.Key)
		listed[info.Key] = true
	}
	// An operator deletes a pin to accept a moved tag: forget what is gone.
	s.mu.Lock()
	for k := range s.cache {
		if strings.HasPrefix(k, prefix) && !listed[k] {
			delete(s.cache, k)
		}
	}
	s.mu.Unlock()
	for _, key := range keys {
		pf, err := s.read(ctx, key)
		if err != nil {
			if ctx.Err() != nil || !errors.Is(err, ErrCorrupt) {
				return nil, nil, err
			}
			corrupt = append(corrupt, err)
			continue
		}
		pins = append(pins, Pin{Tag: pf.Tag, SHA: pf.SHA, FirstSeen: pf.FirstSeen})
	}
	slices.SortFunc(pins, func(a, b Pin) int { return strings.Compare(a.Tag, b.Tag) })
	return pins, corrupt, nil
}

// Moved returns the moved tags seen since start, sorted.
func (s *Store) Moved() []MovedTag {
	s.mu.Lock()
	out := make([]MovedTag, 0, len(s.moved))
	for _, m := range s.moved {
		out = append(out, m)
	}
	s.mu.Unlock()
	slices.SortFunc(out, func(a, b MovedTag) int {
		return strings.Compare(strings.Join([]string{a.Ecosystem, a.Source, a.Remote, a.Tag}, "\x00"),
			strings.Join([]string{b.Ecosystem, b.Source, b.Remote, b.Tag}, "\x00"))
	})
	return out
}

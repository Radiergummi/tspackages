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
}

func New(d storage.Driver) *Store {
	return &Store{d: d, moved: map[[4]string]MovedTag{}}
}

// Pin records sha for the tag on first sight and returns the pinned SHA. If
// the tag was pinned to a different SHA, it returns the pinned one with
// moved=true and remembers the move.
func (s *Store) Pin(ctx context.Context, ecosystem, source, remote, tag, sha string) (pinned string, moved bool, err error) {
	if !shaRE.MatchString(sha) {
		return "", false, fmt.Errorf("pins: invalid sha %q", sha)
	}
	key := "pins/" + ecosystem + "/" + source + "/" + storage.EscapeSegment(remote) + "/" + storage.EscapeSegment(tag) + ".json"
	body, err := json.Marshal(pinFile{Tag: tag, SHA: sha, FirstSeen: time.Now().UTC()})
	if err != nil {
		return "", false, err
	}
	_, err = s.d.PutIfAbsent(ctx, key, bytes.NewReader(body))
	if err == nil {
		return sha, false, nil
	}
	if !errors.Is(err, storage.ErrExists) {
		return "", false, err
	}
	rc, _, err := s.d.Get(ctx, key)
	if err != nil {
		return "", false, err
	}
	defer rc.Close()
	raw, err := io.ReadAll(rc)
	if err != nil {
		return "", false, err
	}
	var pf pinFile
	if err := json.Unmarshal(raw, &pf); err != nil {
		return "", false, fmt.Errorf("pins: corrupt pin %s: %w", key, err)
	}
	if !shaRE.MatchString(pf.SHA) {
		return "", false, fmt.Errorf("pins: corrupt pin %s: invalid sha", key)
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

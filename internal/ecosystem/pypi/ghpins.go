package pypi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/radiergummi/tspackages/internal/digest"
	"github.com/radiergummi/tspackages/internal/githubapp"
	"github.com/radiergummi/tspackages/internal/storage"
)

// errCorruptGHPin marks a pin file that cannot be decoded or holds invalid
// values.
var errCorruptGHPin = errors.New("pypi: corrupt github pin")

// ghPins keeps a github source's trust-on-first-use pins in the state store:
// which repository owns a project name, and the sha256 of release assets
// GitHub reports no digest for. It is safe for concurrent use.
type ghPins struct {
	d      storage.Driver
	prefix string
	log    *slog.Logger
	source string

	mu      sync.Mutex
	owners  map[string]ghOwnerPin  // by key; an operator may delete a pin (Owners drops such entries)
	digests map[string]ghDigestPin // by key, likewise
}

type ghOwnerPin struct {
	Name     string    `json:"name"`
	RepoID   int64     `json:"repo_id"`
	Repo     string    `json:"repo"`
	PinnedAt time.Time `json:"pinned_at"`
}

type ghDigestPin struct {
	AssetID  int64     `json:"asset_id"`
	SHA256   string    `json:"sha256"`
	Size     int64     `json:"size"`
	PinnedAt time.Time `json:"pinned_at"`
}

func newGHPins(d storage.Driver, source string, log *slog.Logger) *ghPins {
	return &ghPins{
		d:       d,
		log:     log,
		source:  source,
		prefix:  "pypi-github/" + source + "/",
		owners:  map[string]ghOwnerPin{},
		digests: map[string]ghDigestPin{},
	}
}

func (p *ghPins) ownerKey(name string) string {
	return p.prefix + "owners/" + storage.EscapeSegment(name) + ".json"
}

func (p *ghPins) digestKey(assetID int64) string {
	return p.prefix + "digests/" + strconv.FormatInt(assetID, 10) + ".json"
}

// PinOwner records repo as the owner of the normalised project name on first
// sight and returns the pinned owner's repository ID, which is the stored one
// when the name was pinned before.
func (p *ghPins) PinOwner(ctx context.Context, name string, repo githubapp.Repo) (int64, error) {
	if name == "" || repo.ID <= 0 {
		return 0, fmt.Errorf("pypi: invalid owner pin %q -> %d", name, repo.ID)
	}
	key := p.ownerKey(name)
	fresh := ghOwnerPin{Name: name, RepoID: repo.ID, Repo: repo.FullName, PinnedAt: time.Now().UTC()}
	body, err := json.Marshal(fresh)
	if err != nil {
		return 0, err
	}
	_, err = p.d.PutIfAbsent(ctx, key, bytes.NewReader(body))
	if err == nil {
		p.mu.Lock()
		p.owners[key] = fresh // replaces a stale entry for a pin deleted by an operator
		p.mu.Unlock()
		return repo.ID, nil
	}
	if !errors.Is(err, storage.ErrExists) {
		return 0, err
	}
	pin, err := p.readOwner(ctx, key)
	if err != nil {
		return 0, err
	}
	return pin.RepoID, nil
}

// Owners returns every readable owner pin as normalised name to repository
// ID. Corrupt pins are skipped, so one bad file does not hide the others.
func (p *ghPins) Owners(ctx context.Context) (map[string]int64, error) {
	keys, err := p.list(ctx, p.prefix+"owners/", func(k string) { delete(p.owners, k) })
	if err != nil {
		return nil, err
	}
	out := map[string]int64{}
	for _, key := range keys {
		pin, err := p.readOwner(ctx, key)
		if err != nil {
			if skip, err := p.skipPin(ctx, key, err); !skip {
				return nil, err
			}
			continue
		}
		out[pin.Name] = pin.RepoID
	}
	return out, nil
}

// PinDigest records the sha256 (64 lowercase hex) of an asset on first sight
// and returns the pinned digest, which is the stored one when the asset was
// pinned before.
func (p *ghPins) PinDigest(ctx context.Context, assetID int64, sha256 string, size int64) (string, error) {
	if assetID <= 0 || !digest.IsHex(sha256, 64) {
		return "", fmt.Errorf("pypi: invalid digest pin %d: %q", assetID, sha256)
	}
	key := p.digestKey(assetID)
	fresh := ghDigestPin{AssetID: assetID, SHA256: sha256, Size: size, PinnedAt: time.Now().UTC()}
	body, err := json.Marshal(fresh)
	if err != nil {
		return "", err
	}
	_, err = p.d.PutIfAbsent(ctx, key, bytes.NewReader(body))
	if err == nil {
		p.mu.Lock()
		p.digests[key] = fresh
		p.mu.Unlock()
		return sha256, nil
	}
	if !errors.Is(err, storage.ErrExists) {
		return "", err
	}
	pin, err := p.readDigest(ctx, key)
	if err != nil {
		return "", err
	}
	return pin.SHA256, nil
}

// Digests returns every readable digest pin as asset ID to sha256. Corrupt
// pins are skipped.
func (p *ghPins) Digests(ctx context.Context) (map[int64]string, error) {
	keys, err := p.list(ctx, p.prefix+"digests/", func(k string) { delete(p.digests, k) })
	if err != nil {
		return nil, err
	}
	out := map[int64]string{}
	for _, key := range keys {
		pin, err := p.readDigest(ctx, key)
		if err != nil {
			if skip, err := p.skipPin(ctx, key, err); !skip {
				return nil, err
			}
			continue
		}
		out[pin.AssetID] = pin.SHA256
	}
	return out, nil
}

// list returns the keys under prefix and forgets, through forget, cached pins
// that are gone: an operator deletes a pin to re-pin it.
func (p *ghPins) list(ctx context.Context, prefix string, forget func(key string)) ([]string, error) {
	var keys []string
	listed := map[string]bool{}
	for info, err := range p.d.List(ctx, prefix) {
		if err != nil {
			return nil, err
		}
		keys = append(keys, info.Key)
		listed[info.Key] = true
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	for k := range p.owners {
		if strings.HasPrefix(k, prefix) && !listed[k] {
			forget(k)
		}
	}
	for k := range p.digests {
		if strings.HasPrefix(k, prefix) && !listed[k] {
			forget(k)
		}
	}
	return keys, nil
}

// skipPin reports whether a failed read of the pin at key is skipped: a pin
// an operator deleted since the listing is dropped silently, a corrupt one is
// logged. Any other error is returned.
func (p *ghPins) skipPin(ctx context.Context, key string, err error) (bool, error) {
	if ctx.Err() != nil {
		return false, err
	}
	switch {
	case errors.Is(err, storage.ErrNotFound):
		p.mu.Lock()
		delete(p.owners, key)
		delete(p.digests, key)
		p.mu.Unlock()
		return true, nil
	case errors.Is(err, errCorruptGHPin):
		p.log.Warn("pypi github: ignoring a corrupt pin", "source", p.source, "key", key, "error", err)
		return true, nil
	}
	return false, err
}

func (p *ghPins) readOwner(ctx context.Context, key string) (ghOwnerPin, error) {
	p.mu.Lock()
	pin, ok := p.owners[key]
	p.mu.Unlock()
	if ok {
		return pin, nil
	}
	if err := p.readJSON(ctx, key, &pin); err != nil {
		return ghOwnerPin{}, err
	}
	if pin.Name == "" || pin.RepoID <= 0 {
		return ghOwnerPin{}, fmt.Errorf("%w %s: invalid owner", errCorruptGHPin, key)
	}
	p.mu.Lock()
	p.owners[key] = pin
	p.mu.Unlock()
	return pin, nil
}

func (p *ghPins) readDigest(ctx context.Context, key string) (ghDigestPin, error) {
	p.mu.Lock()
	pin, ok := p.digests[key]
	p.mu.Unlock()
	if ok {
		return pin, nil
	}
	if err := p.readJSON(ctx, key, &pin); err != nil {
		return ghDigestPin{}, err
	}
	if pin.AssetID <= 0 || !digest.IsHex(pin.SHA256, 64) {
		return ghDigestPin{}, fmt.Errorf("%w %s: invalid digest", errCorruptGHPin, key)
	}
	p.mu.Lock()
	p.digests[key] = pin
	p.mu.Unlock()
	return pin, nil
}

func (p *ghPins) readJSON(ctx context.Context, key string, v any) error {
	rc, _, err := p.d.Get(ctx, key)
	if err != nil {
		return err
	}
	defer rc.Close()
	raw, err := io.ReadAll(rc)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(raw, v); err != nil {
		return fmt.Errorf("%w %s: %w", errCorruptGHPin, key, err)
	}
	return nil
}

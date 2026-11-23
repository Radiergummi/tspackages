package npm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/radiergummi/tspackages/internal/flight"
	"github.com/radiergummi/tspackages/internal/metrics"
	"github.com/radiergummi/tspackages/internal/relay"
	"github.com/radiergummi/tspackages/internal/resolve"
	"github.com/radiergummi/tspackages/internal/storage"
)

const (
	// maxKeysBytes caps the upstream signing keys document.
	maxKeysBytes = 1 << 20
	// maxAttestationBytes caps an upstream attestation bundle.
	maxAttestationBytes = 4 << 20
	// keysFetchTimeout bounds a keys request including its body.
	keysFetchTimeout = time.Minute
)

// Keys passes through the upstream's registry signing keys, cached for ttl
// and served stale when the upstream fails. An upstream 404 is a miss.
func (s *RegistrySource) Keys(ctx context.Context) (Artifact, error) {
	key := "npm/" + s.name + "/keys.json"
	cached, written, have := s.readSmall(ctx, key)
	if have && s.now().Sub(written) < s.ttl {
		metrics.ObserveCacheHit(ecoName, s.name)
		return bytesArtifact(cached), nil
	}
	body, err := flight.Do(ctx, &s.keysFlight, key, func() ([]byte, error) {
		return s.fetchKeys(context.WithoutCancel(ctx), key)
	})
	switch {
	case err == nil:
		return bytesArtifact(body), nil
	case have && !errors.Is(err, resolve.ErrNotFound):
		s.log.Warn("serving stale npm keys", "source", s.name, "error", err)
		return bytesArtifact(cached), nil
	}
	return Artifact{}, err
}

func (s *RegistrySource) fetchKeys(ctx context.Context, key string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, keysFetchTimeout)
	defer cancel()
	if err := s.wait(ctx); err != nil {
		return nil, err
	}
	start := time.Now()
	rc, _, err := s.c.Open(ctx, s.base+"-/npm/v1/keys", maxKeysBytes)
	metrics.ObserveUpstream(s.name, time.Since(start))
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	b, err := io.ReadAll(rc)
	if err != nil {
		return nil, err
	}
	if !json.Valid(b) {
		return nil, errors.New("upstream keys are not JSON")
	}
	if err := s.cache.Put(ctx, key, bytes.NewReader(b)); err != nil {
		s.log.Warn("caching npm keys failed", "source", s.name, "error", err)
	}
	return b, nil
}

func (s *RegistrySource) readSmall(ctx context.Context, key string) ([]byte, time.Time, bool) {
	rc, written, err := s.cache.Get(ctx, key)
	if err != nil {
		return nil, time.Time{}, false
	}
	defer rc.Close()
	b, err := io.ReadAll(io.LimitReader(rc, maxKeysBytes))
	if err != nil {
		return nil, time.Time{}, false
	}
	return b, written, true
}

func bytesArtifact(b []byte) Artifact {
	return Artifact{Body: io.NopCloser(bytes.NewReader(b)), Size: int64(len(b))}
}

// Attestations streams the attestation bundle at the upstream URL the
// version's dist.attestations.url named. It declares no hash; it is cached
// per package and version.
func (s *RegistrySource) Attestations(ctx context.Context, n Name, version string) (Artifact, error) {
	e, err := s.lookup(ctx, n, n.TarballFile(version))
	if err != nil {
		return Artifact{}, err
	}
	// The file name may be another version's upstream alias.
	if e.Version != version || e.Attestations == "" {
		return Artifact{}, fmt.Errorf("%w: no attestations for %s@%s", resolve.ErrNotFound, n.Exact, version)
	}
	// No ".json" suffix: an escaped 156-byte version fills a whole segment.
	key := "npm/" + s.name + "/attest/" + storage.EscapeSegment(n.Exact) + "/" + storage.EscapeSegment(version)
	return s.open(ctx, key, e.Attestations, relay.Digest{}, maxAttestationBytes, nil)
}

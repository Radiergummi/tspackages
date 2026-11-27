package githubapp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Repo is a repository the installation can see.
type Repo struct {
	ID       int64
	FullName string
}

// Release is a GitHub release as returned, drafts included.
type Release struct {
	ID         int64
	Tag        string
	Draft      bool
	Prerelease bool
	CreatedAt  time.Time
	Assets     []Asset
}

// Asset is a release asset. Digest is GitHub's "sha256:<hex>" and empty for
// assets uploaded before GitHub computed one.
type Asset struct {
	ID        int64
	Name      string
	State     string
	Digest    string
	Size      int64
	CreatedAt time.Time
	UpdatedAt time.Time
}

// cachedPage is the last answer for one page URL, kept for conditional
// requests: a 304 returns val and next without parsing anything.
type cachedPage struct {
	etag string
	val  any
	next string
}

// Repositories lists the repositories the installation can access.
func (a *App) Repositories(ctx context.Context) ([]Repo, error) {
	first, err := a.apiURL("/installation/repositories", "per_page=100")
	if err != nil {
		return nil, err
	}
	return listPages(ctx, a, first, func(r io.Reader) ([]Repo, error) {
		var body struct {
			Repositories []struct {
				ID       int64  `json:"id"`
				FullName string `json:"full_name"`
			} `json:"repositories"`
		}
		if err := json.NewDecoder(io.LimitReader(r, maxJSONBytes)).Decode(&body); err != nil {
			return nil, err
		}
		out := make([]Repo, len(body.Repositories))
		for i, v := range body.Repositories {
			out[i] = Repo{ID: v.ID, FullName: v.FullName}
		}
		return out, nil
	})
}

// Releases lists a repository's releases, drafts and prereleases included.
func (a *App) Releases(ctx context.Context, r Repo) ([]Release, error) {
	path, err := repoPath(r)
	if err != nil {
		return nil, err
	}
	first, err := a.apiURL(path+"/releases", "per_page=100")
	if err != nil {
		return nil, err
	}
	return listPages(ctx, a, first, func(rd io.Reader) ([]Release, error) {
		var body []struct {
			ID         int64     `json:"id"`
			Tag        string    `json:"tag_name"`
			Draft      bool      `json:"draft"`
			Prerelease bool      `json:"prerelease"`
			CreatedAt  time.Time `json:"created_at"`
			Assets     []struct {
				ID        int64     `json:"id"`
				Name      string    `json:"name"`
				State     string    `json:"state"`
				Digest    *string   `json:"digest"`
				Size      int64     `json:"size"`
				CreatedAt time.Time `json:"created_at"`
				UpdatedAt time.Time `json:"updated_at"`
			} `json:"assets"`
		}
		if err := json.NewDecoder(io.LimitReader(rd, maxJSONBytes)).Decode(&body); err != nil {
			return nil, err
		}
		out := make([]Release, len(body))
		for i, v := range body {
			rel := Release{ID: v.ID, Tag: v.Tag, Draft: v.Draft, Prerelease: v.Prerelease, CreatedAt: v.CreatedAt}
			for _, as := range v.Assets {
				d := ""
				if as.Digest != nil {
					d = *as.Digest
				}
				rel.Assets = append(rel.Assets, Asset{
					ID: as.ID, Name: as.Name, State: as.State, Digest: d,
					Size: as.Size, CreatedAt: as.CreatedAt, UpdatedAt: as.UpdatedAt,
				})
			}
			out[i] = rel
		}
		return out, nil
	})
}

// listPages follows rel="next" links from first and concatenates the pages.
func listPages[T any](ctx context.Context, a *App, first string, decode func(io.Reader) ([]T, error)) ([]T, error) {
	var all []T
	target := first
	for seen := 0; target != ""; seen++ {
		if seen >= 1000 {
			return nil, errors.New("github: too many pages")
		}
		page, next, err := getPage(ctx, a, target, decode)
		if err != nil {
			return nil, err
		}
		all = append(all, page...)
		target = next
	}
	return all, nil
}

// getPage fetches one page, conditionally when an earlier answer is cached,
// and returns it with the URL of the next page ("" for the last).
func getPage[T any](ctx context.Context, a *App, target string, decode func(io.Reader) ([]T, error)) ([]T, string, error) {
	var page []T
	var next string
	err := a.withToken(ctx, func(tok string) error {
		req, err := newAPIRequest(ctx, target, tok, acceptJSON)
		if err != nil {
			return err
		}
		a.mu.Lock()
		cached, have := a.pages[target]
		a.mu.Unlock()
		if have {
			req.Header.Set("If-None-Match", cached.etag)
		}
		resp, err := a.c.Do(req)
		if err != nil {
			return fmt.Errorf("github: %w", err)
		}
		defer resp.Body.Close()
		a.noteRate(resp.Header)
		switch {
		case resp.StatusCode == http.StatusNotModified && have:
			page, next = cached.val.([]T), cached.next
			return nil
		case resp.StatusCode != http.StatusOK:
			return a.statusError(resp)
		}
		page, err = decode(resp.Body)
		if err != nil {
			return fmt.Errorf("github: decoding %s: %w", resp.Request.URL.Path, err)
		}
		next, err = a.nextLink(resp.Header.Get("Link"))
		if err != nil {
			return err
		}
		if etag := resp.Header.Get("ETag"); etag != "" {
			a.mu.Lock()
			a.pages[target] = cachedPage{etag: etag, val: page, next: next}
			a.mu.Unlock()
		}
		return nil
	})
	return page, next, err
}

// nextLink returns the rel="next" URL of a Link header, or "" without one.
// It must point at the API host: the token goes with every request.
func (a *App) nextLink(header string) (string, error) {
	for part := range strings.SplitSeq(header, ",") {
		target, params, ok := strings.Cut(strings.TrimSpace(part), ";")
		if !ok || !strings.Contains(params, `rel="next"`) {
			continue
		}
		target = strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(target), "<"), ">")
		u, err := url.Parse(target)
		if err != nil || a.api == nil || u.Scheme != a.api.Scheme || u.Host != a.api.Host {
			return "", errors.New("github: pagination link leaves the API host")
		}
		return u.String(), nil
	}
	return "", nil
}

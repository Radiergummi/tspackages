# CLAUDE.md

Guidance for agents working in this repository. Read this first, then README.md
and docs/security.md.

## What this is

tspackages is a package registry that exists only on a Tailscale tailnet. It
runs as one tsnet node, serves one endpoint per ecosystem in that ecosystem's
native protocol, assembles each endpoint from ordered sources (`git`,
`storage`, `registry` pass-through), and authorizes every request by Tailscale
identity (WhoIs + an app capability in tailnet grants). Clients hold no
registry credentials.

Status (2026-11-09): milestone 1 (core + Composer) is done and on `main`.
Next: milestone 2, PyPI (`storage` + `registry` sources; CI uploads with
`twine`/`uv publish`). Later: Go (git + registry + sumdb proxy), npm, OCI,
Maven.

The design spec and the milestone-1 plan live in `docs/superpowers/`, which the
owner's global gitignore excludes. They exist only in the owner's local
checkout. If they are missing, this file and the code are the source of truth.

## Commands

```sh
go vet ./... && go test -race ./...
go test -tags integration ./integration/...   # needs composer 2.x and git
go build ./cmd/tspackages
gofmt -l .                                     # must print nothing
```

S3 tests run only with `TSP_TEST_S3_ENDPOINT` pointing at a MinIO
(minioadmin/minioadmin by default). Go toolchain 1.27.3+ (required by
tailscale.com).

## Layout

- `cmd/tspackages` — main: flags, tsnet, TLS listener on :443 only, state dir
  checks, env scrubbing, graceful shutdown.
- `internal/server` — `Build(ctx, cfg, who, log, Hooks)`: wires everything.
  `Hooks` are test-only switches (local file remotes, plain-http/private
  upstreams); `main` always passes the zero value.
- `internal/config` — YAML load (`KnownFields`), `${env:}`/`${file:}`
  expansion, `ApplyDefaults`, `Validate`/`ValidateWith`.
- `internal/identity` (WhoIs → Caller, strips client Authorization),
  `internal/authz` (pure rule matching), `internal/limits` (per-node rate
  limits).
- `internal/resolve` — `Candidates`/`First`/`HTTPStatus`: the
  dependency-confusion core.
- `internal/storage` — fs + S3 drivers, LRU cache, key rules
  (lowercase only, `EscapeSegment`).
- `internal/upstream` — the only HTTP client for upstreams: host allowlist,
  dial-time private-address block, credentials per exact host, no redirects
  with credentials, digest verification.
- `internal/gitmirror` — bare mirrors via the git binary, hardened argv/env.
- `internal/pins` (TOFU tag pins), `internal/records` (provenance + audit),
  `internal/digest`, `internal/archive` (safe zip inspection),
  `internal/workdir` (private dirs + instance lock), `internal/metrics`,
  `internal/web` (status page, /healthz, /readyz, /metrics).
- `internal/ecosystem/composer` — names, Composer version parsing (port of
  composer/semver), the three sources, the HTTP handler.
- `internal/testutil` — test-only helpers (git, zips, fake WhoIs).
- `integration/` — real-Composer end-to-end test (`-tags integration`).

## Invariants — do not break

- Tailscale is the only authentication. No tokens, no dev mode that skips
  WhoIs. Default deny: no matching capability means 403.
- Resolution: a name claimed by a source is consulted only on claiming
  sources, in order; only a definite `resolve.ErrNotFound` moves to the next
  one; any other error is a 502/504. At most one unclaimed source per
  ecosystem; `storage` sources must have claims. Never merge versions across
  sources. `ErrUnavailable` (conflicts, not yet indexed) must never wrap
  `ErrNotFound`.
- Claims are `*` or lowercase `<vendor>/<name>` patterns using `[a-z0-9_.-]`
  and `*`. Anything else is a config error, because a malformed claim would
  silently route private names to the public source.
- URLs returned to clients point at tspackages and are opaque routes, never
  encoded upstream URLs.
- Upstream artifact bytes are verified against the declared hash before
  caching. Metadata is passed through except: `dist.url` is rewritten and
  `source` blocks are stripped. Metadata built from storage/git sources uses
  `composer.PublishableFields` (an allowlist; `notification-url` must never
  pass).
- Durable data (tag pins, git-built archives and sidecars, provenance, audit)
  lives in the state store, never the cache. Served git versions stay served
  even if the tag disappears upstream or the mirror is lost.
- Hosted artifacts are immutable; indexes are rebuildable from them and
  written with `If-Match`.
- Uploads are content-bound: the name in `composer.json` must match the URL.
- One instance per `work_dir` (flock) and per tsnet state dir.

## Conventions

- Commits are signed (SSH via Secretive on the owner's Mac). If signing fails,
  stop and ask; never switch keys or commit unsigned.
- Test first for behaviour changes; tests judge protocol conformance with real
  clients where possible.
- Comments state current behaviour, not history.
- CI: `.github/workflows/ci.yml`; actions pinned by full SHA.

## Known open items

- CI is green (tests with MinIO, real-Composer integration, Docker build).
  MinIO images can't be pulled anonymously any more, so CI builds a pinned
  MinIO commit from source; bump that pin deliberately.
- `main` releases the work_dir lock without waiting for background git loops
  to stop.
- The config check for overlapping claims is exact-string only (a git source
  `acme/*` plus a storage source `acme/x` validates, but uploads to `acme/x`
  then get 409).
- Rule patterns in tailnet grants are not grammar-checked.
- `noteFetch` in the registry source compares error strings, so errors with
  changing text log on every failure.
- Open decision for the owner: whether `replace`/`provide` in hosted packages
  should be restricted to the uploader's own claims.

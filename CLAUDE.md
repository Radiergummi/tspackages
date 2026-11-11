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

Roadmap: Composer and PyPI (`storage`, `registry` and `git` sdists; CI
uploads with `twine`/`uv publish`) ship; then Go (git + registry + sumdb
proxy), npm, OCI and Maven.

The design spec and the milestone-1 plan live in `docs/superpowers/`, which the
owner's global gitignore excludes. They exist only in the owner's local
checkout. If they are missing, this file and the code are the source of truth.

## Commands

```sh
make check         # golangci-lint, actionlint, zizmor, Vale, fmt-check, vet, race tests
make integration   # real Composer/pip/uv/twine end-to-end; need composer 2.x, git, python3 with pip, uv, twine (S3 variant: TSP_TEST_S3_ENDPOINT)
make tailnet       # real tsnet nodes + in-process testcontrol: WhoIs, grants, startup and shutdown
make vuln          # govulncheck; reachable findings fail unless VULN_IGNORE lists them
make build         # ./tspackages with version and commit stamped in
go test ./internal/<pkg> -run '^$' -fuzz '^FuzzX$' -fuzztime 30s   # fuzz targets
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
  (lowercase only, segments of at most `MaxSegment` bytes, `EscapeSegment`).
- `internal/upstream` — the only HTTP client for upstreams: host allowlist,
  dial-time private-address block, credentials per exact host, no redirects
  with credentials, digest verification.
- `internal/gitmirror` — bare mirrors via the git binary, hardened argv/env.
- `internal/pins` (TOFU tag pins), `internal/records` (provenance + audit),
  `internal/digest`, `internal/archive` (safe zip inspection),
  `internal/workdir` (private dirs + instance lock), `internal/metrics`,
  `internal/web` (status page, /healthz, /readyz, /metrics).
- `internal/relay` — one upstream fetch per artifact, streamed to every
  waiting client from a temp file, cached only after its digest matched.
- `internal/flight` — per-key single-flight shared by the ecosystems.
- `internal/ecosystem/composer` — names, Composer version parsing (port of
  composer/semver), the three sources, the HTTP handler.
- `internal/ecosystem/pypi` — PEP 503 names, PEP 440 versions, filenames,
  the simple API (HTML + JSON), the three sources, pyproject discovery,
  PKG-INFO and deterministic sdists, the HTTP handler. Must not import
  `composer` (nor the reverse).
- `internal/testutil` — test-only helpers (git, zips, fake WhoIs).
- `integration/` — end-to-end tests with real Composer, pip, uv and twine
  (`-tags integration`).

## Invariants — do not break

- Tailscale is the only authentication. No tokens, no dev mode that skips
  WhoIs. Default deny: no matching capability means 403.
- Resolution: a name claimed by a source is consulted only on claiming
  sources, in order; only a definite `resolve.ErrNotFound` moves to the next
  one; any other error is a 502/504. At most one unclaimed source per
  ecosystem; `storage` sources must have claims, none overlapping a claim of
  an earlier source (uploads go to the first claiming source). Never merge
  versions across sources. `ErrUnavailable` (conflicts, not yet indexed) must
  never wrap `ErrNotFound`.
- Claims are `*` or lowercase `<vendor>/<name>` patterns using `[a-z0-9_.-]`
  and `*`. Anything else is a config error, because a malformed claim would
  silently route private names to the public source. Composer capability
  rules use the same grammar (case-insensitive); a malformed one matches
  nothing. PyPI claims and rules: `*` or `[a-z0-9-]` and `*`, matched against
  the PEP 503 normalised name.
- URLs returned to clients point at tspackages and are opaque routes, never
  encoded upstream URLs.
- Upstream artifact bytes are verified against the declared hash before
  caching: the relay streams to clients while it hashes, commits to the
  cache only on a match, and breaks the client transfer on a mismatch. Whatever the declared hash, a dist whose sha256 differs from the
  first provenance record for its version and reference is served but
  reported (warn log, status page). Metadata is passed through except: `dist.url` is rewritten,
  `dist` keeps only `type`, `url`, `reference` and `shasum`, and `source`,
  `notification-url` and `transport-options` are stripped. Metadata built from storage/git sources uses
  `composer.PublishableFields` (an allowlist; `notification-url` must never
  pass).
- Durable data (tag pins, git-built archives and sidecars, provenance, audit)
  lives in the state store, never the cache. Served git versions stay served
  even if the tag disappears upstream or the mirror is lost.
- Hosted artifacts are immutable; indexes are rebuildable from them and
  written with `If-Match`.
- Uploads are content-bound: the name in `composer.json` must match the URL;
  a PyPI upload's form, filename and inner metadata must agree.
- PyPI keys are (PEP 503 normalised name, canonical PEP 440 version).
  A release has at most one sdist and one wheel per tag set; a published
  file never changes bytes. Git-generated sdists live in the state store,
  are built once and never regenerated (a change without a version bump is
  reported, not served).
- One instance per `work_dir` (flock) and per tsnet state dir.

## Conventions

- Commits are signed (SSH via Secretive on the owner's Mac). If signing fails,
  stop and ask; never switch keys or commit unsigned.
- Test first for behaviour changes; tests judge protocol conformance with real
  clients where possible.
- Comments state current behaviour, not history.
- User-visible changes get a line under `Unreleased` in CHANGELOG.md.
- Lint suppressions (`//nolint`, gosec excludes in `.golangci.yml`) carry a
  reason.
- CI: `.github/workflows/ci.yml`; `release.yml` runs on `v*` tags. Actions are
  pinned by full SHA; tool versions (golangci-lint, actionlint, zizmor, Vale,
  govulncheck) are pinned too and bumped deliberately.

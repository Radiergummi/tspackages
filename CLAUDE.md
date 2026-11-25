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

Roadmap: Composer, PyPI (`storage`, `registry` and `git` sdists; CI
uploads with `twine`/`uv publish`), Go (`git` + `registry` + sumdb
proxy) and npm (`storage` + `registry`; npm and pnpm, CI publishes with a
dummy `_authToken`) and Maven (`storage` + `registry`; mvn and Gradle,
no `<server>` or `credentials` entry) and apt (`storage` + `registry`;
signed per-source repositories, client pinning) ship; OCI is next.

The design spec and the milestone-1 plan live in `docs/superpowers/`, which the
owner's global gitignore excludes. They exist only in the owner's local
checkout. If they are missing, this file and the code are the source of truth.

## Commands

```sh
make check         # golangci-lint, actionlint, zizmor, Vale, fmt-check, vet, race tests
make integration   # real Composer/pip/uv/twine/go/npm/pnpm/mvn/gradle/apt end-to-end; need composer 2.x, git, python3 with pip, uv, twine, go, node with npm and pnpm, a JDK, mvn, gradle, gpg, apt-get and apt-cache (S3 variant: TSP_TEST_S3_ENDPOINT)
make maven-seed    # once, with network: the local repository the mvn tests' fake Central serves (TSP_TEST_MAVEN_SEED; missing: skip, fail under CI=true)
make tailnet       # real tsnet nodes + in-process testcontrol: WhoIs, grants, startup and shutdown
make vuln          # govulncheck; reachable findings fail unless VULN_IGNORE lists them
make build         # ./tspackages with version and commit stamped in
go test ./internal/<pkg> -run '^$' -fuzz '^FuzzX$' -fuzztime 30s   # fuzz targets
```

S3 tests run only with `TSP_TEST_S3_ENDPOINT` pointing at a MinIO
(minioadmin/minioadmin by default). Go toolchain 1.27.4+ (tailscale.com needs
1.27.3; 1.27.4 fixes GO-2026-6859 in net/http).

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
- `internal/lru` — in-memory cache bounded by total value size (rendered
  npm packuments, Maven metadata).
- `internal/ecosystem/composer` — names, Composer version parsing (port of
  composer/semver), the three sources, the HTTP handler.
- `internal/ecosystem/pypi` — PEP 503 names, PEP 440 versions, filenames,
  the simple API (HTML + JSON), the three sources, pyproject discovery,
  PKG-INFO and deterministic sdists, the HTTP handler. Must not import
  `composer` (nor the reverse).
- `internal/ecosystem/goproxy` — module paths and claims, the GOPROXY
  handler, the `git` source (tag versions, build queue, module zips,
  pseudo-versions, on-demand sync), the `registry` source, the
  sum.golang.org verifier and the client-facing sumdb proxy. Must not
  import `composer` or `pypi` (nor the reverse).
- `internal/ecosystem/npm` — names and claims, strict SemVer, request
  paths, the streamed packument rewrite and publish inspection, the
  `storage` source (dist-tags, precedence claims) and the `registry`
  source (tarballs, keys, attestations), the HTTP handler. Must not import
  `composer`, `pypi` or `goproxy` (nor the reverse).
- `internal/ecosystem/maven` — coordinates, layout paths and claims, the
  `ComparableVersion` port, the safe XML reader, checksums, deploy
  inspection (POM, `.module`, metadata), the `storage` source (write-once
  release and timestamped SNAPSHOT files, generated metadata) and the `registry`
  source (files verified by the upstream's `.sha1`, metadata passed
  through), the HTTP handler. Must not import `composer`, `pypi`,
  `goproxy` or `npm` (nor the reverse).
- `internal/ecosystem/apt` — package, suite and architecture names and
  claims, layout paths, deb822 reading and the hygiene check, `.deb`
  inspection, the `storage` source (write-once pool files, suite members,
  per-caller indexes signed with the signing key), the `registry` source
  (Release verified against the keyring, pool lookup), the preferences
  file, the HTTP handler. Must not import `composer`, `pypi`, `goproxy`,
  `npm` or `maven` (nor the reverse).
- `internal/testutil` — test-only helpers (git, zips, fake WhoIs).
- `integration/` — end-to-end tests with real Composer, pip, uv, twine,
  the go command, npm, pnpm, mvn, Gradle and apt (`-tags integration`).

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
  nothing. PyPI claims and rules: `*` or `[a-z0-9-]` and `*` with no leading,
  trailing or doubled `-`, matched against the PEP 503 normalised name.
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
- Go: claims and `go:` rules are `*` or `/`-separated segments of
  `[a-z0-9._~-]` and `*`, matched against the lowercased decoded module
  path (a claim covers every `/vN` of its module). `git` claims become
  clients' `GONOSUMDB`, so `*`, a wildcard in the host, and under
  `github.com`/`gitlab.com`/`bitbucket.org` the bare host or a wildcard in
  the owner segment are config errors. Tag versions are durable: built
  once into the state store (`go-git/`), never rebuilt with other bytes,
  rebuilds checked by `h1:`. Registry `.zip`/`.mod` are verified against
  sum.golang.org before caching; the verified tree head lives in the state
  store. Private paths (claimed by any `git` source) are never forwarded to
  sum.golang.org: `registry` sources answer them `404` before any upstream
  request. The one exception to "served git versions stay served":
  a pseudo-version whose commit is gone from the mirror becomes
  unavailable.
- npm: claims and `npm:` rules are `*`, `@<scope>/<name>` or an unscoped
  `<name>` of `[a-z0-9._-]` and `*` (a `*` matches within one part),
  matched against the lowercased name; storage accepts only names that are
  already lowercase. Every key segment from a name or version goes through
  `storage.EscapeSegment`, so names and versions are at most 156 raw bytes
  (`MaxSegment`). A storage version's metadata is built from the tarball's
  `package/package.json` through `npm.PublishableFields`, never from the
  publish body, except the informational `gitHead`, `_nodeVersion` and
  `_npmVersion` (strings of at most 256 bytes). A version is claimed with its sha256 (`~claim`) and its
  precedence without build metadata (`~precedence`), so other bytes, or
  `1.0.0+a` next to `1.0.0+b`, are `409`. Registry tarballs are verified
  by SHA-512 (or SHA-1 when that is all a version declares) before
  caching; versions without either are dropped. Never answer `401`: npm
  turns it into an OTP or login prompt; deny is `403`.
- Maven: claims and `maven:` rules are `*`, `<group>` or
  `<group>:<artifact>`, the group dotted segments of `[a-z0-9_-]` whose
  last may be `*` (one or more trailing segments, so `com.acme.*` doesn't
  cover `com.acme`), the artifact `[a-z0-9._-]` and `*`, matched against
  the lowercased `groupId:artifactId`. Coordinates are stored and served
  in their exact case; a deploy that differs from an existing artifact
  only in case is `409`. A `maven-metadata.xml` path is claimed when
  either reading (artifact level `g:a`, group level `g.a`) matches a
  claim; reading group-level metadata needs a rule for the whole group
  (`<group>` or `<group>:*`), and its sources are asked only for callers allowed it. Every key segment from a coordinate or file name goes through
  `storage.EscapeSegment`, so coordinate parts are at most 156 bytes, and
  storage accepts file names of at most 153 bytes and `groupId:artifactId`
  of at most 156. Release and timestamped SNAPSHOT files are write-once
  (same bytes `201`, other bytes `409`: they are served immutable), and a
  version is listed once its POM is stored; other SNAPSHOT files may be
  overwritten. Provenance is kept per file. Uploaded checksums and `maven-metadata.xml`
  are checked and discarded: tspackages serves its own, generated from
  the bytes it serves. Registry files are verified against the upstream's
  `.sha1` before caching; without one, a missing file is `404`, a
  signature is streamed uncached and anything else is `502`. A `404` has a
  plain-text body (Maven reads a problem+json `404` as a transfer error);
  other errors are problem+json. Never answer `401`; deny is `403`.
- apt: claims and `apt:` rules are `*` or patterns of `[a-z0-9+.-]` and
  `*`, matched against the package name; a `storage` claim can't be a bare
  `*` (its pin would block every package of every other repository), and
  none may overlap another's. Each source is its own repository, so
  `registry` sources take no claims and "at most one unclaimed source"
  doesn't apply; apt merges versions across repositories on the client, so
  the protection is the generated preferences file (`/apt/preferences`,
  pins on `o=tspackages,l=<source>`), and a client without it isn't
  protected. A package name claimed by any `storage` source is `404` on
  every `registry` source and is never fetched upstream. Claims are public.
  Reads: a `storage` source's indexes need any `apt:` read rule and list
  only the packages the caller may read; the signed `Release` is rendered
  once per visible set and cached keyed by the set and bound to the
  signing key's fingerprint; a download needs a rule for its package (else
  `404`, so names stay hidden). On `registry` sources any `apt:` read rule
  covers indexes and downloads. Uploads need a write rule for the name,
  checked before the body is read; files are keyed by name, version
  without epoch and architecture, written once (same bytes `201`, other
  bytes `409`), and the control fields kept are the
  `apt.PublishableFields` allowlist after the deb822 hygiene check (no
  blank line, CR, NUL or malformed field name, so no field can inject
  another entry into a generated index). The signing key is
  armored private-key text (`${file:}`/`${env:}`), a legacy v4 Ed25519 or RSA of
  3072 bits or more; RFC 9580 (v6) keys are refused because apt's gpgv
  can't verify them. Never logged or served. A registry `keyring` is a
  file path read at startup. The upstream's `Release` (or `InRelease`) is
  verified against it (any one valid signature), served byte for byte,
  and rejected, with the previous copy served, when `Valid-Until` has
  passed, its `Suite` or `Codename` isn't the configured suite, or its
  `Date` is older than the newest accepted, which is kept in the state
  store (`apt/<src>/release-mark/<suite>`) so a lost cache doesn't allow a
  rollback. Index and pool files are served only when the verified
  `Release` or `Packages` lists them, and are verified by SHA-256 before
  caching; only configured suites, components and architectures are
  served. Every key segment goes through `storage.EscapeSegment`, so
  names and versions are at most 156 bytes. Never answer `401`; deny is
  `403`, errors have plain-text bodies.
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

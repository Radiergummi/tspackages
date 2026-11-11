# Changelog

All notable changes to tspackages are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

### Added

- A PyPI endpoint at `/pypi/simple/` (PEP 503 HTML and PEP 691 JSON) with
  legacy uploads at `/pypi/legacy/` for `twine` and `uv publish`. Sources:
  `storage` for uploaded wheels and sdists, `registry` for `pypi.org`
  pass-through, and `git`, which generates deterministic sdists from tagged
  `pyproject.toml` packages and uv workspace members, with an optional
  per-remote tag mapping. Releases are keyed by normalised name and PEP 440
  version and never change bytes once published. The status page lists
  PyPI client settings, git conflicts and skipped packages. Until every
  remote of a `git` source has been indexed since startup and every tag
  read, it builds no new release, and a name without a stored release
  answers `502` instead of falling through to a later source.
- A PyPI `git` source refuses a tag whose tree has more than 100,000
  entries or a path over 1MiB, or whose workspace has more than 1,000
  members, and lists it on the status page; it no longer reads such trees
  whole. A release refused while building isn't built again until restart.
- A PyPI `git` source also refuses a `pyproject.toml` over 256KiB or with
  `[`/`{` nesting or dotted keys deeper than 64, a workspace member nested in
  another, a workspace with more than 1,000 globs or a glob or member
  directory over 4KiB, and a path listed twice or as both a file and a
  directory. Composer `git` archives with such a path are refused too.
  docs/security.md describes the threat model these caps enforce.
- A registry archive whose bytes differ from the ones first fetched for the
  same version and reference is logged at warn and listed on the status page.
  Packagist declares no checksum for most GitHub archives, so this is the
  only check on archives fetched again. Provenance records of registry
  archives now include the reference.
- `-version` prints the build, `-log-format text` switches the logs from
  JSON, and `tspackages_build_info` reports the running version.

### Changed

- `tspackages_git_last_sync_timestamp_seconds` has an `ecosystem` label, so
  a Composer and a PyPI `git` source of the same name no longer share one
  series. Queries and alerts that select on `source` alone may need it.
- Upstream artifact downloads stream: the first client gets bytes while the
  archive is still downloading, concurrent clients share one upstream fetch,
  and the archive is cached only after its digest matched. The last byte is
  held back until then, so a mismatch (or a cached copy that changed at rest)
  breaks the client's transfer short of its `Content-Length` instead of ending
  it like a complete file. Clients finish without waiting for the cache
  write. An
  upstream that sends nothing for two minutes fails the download; there is
  no longer a total download timeout.
- `max_artifact_bytes` defaults to 8GiB and no longer means memory use.
  Composer git-built archives are capped at 512MiB (or `max_artifact_bytes`,
  if lower), since they are built in memory.
- S3 stores upload objects above 64MiB in parts, without buffering them.
- Built with Go 1.27.4, which fixes an HTTP/1 server crash in `net/http`
  (GO-2026-6859).
- A Composer dist is served only by the source that resolution picks for the
  name: when several sources claim it, a dist URL naming a later source
  answers `404` while an earlier one knows the name. Lock files written
  before sources were reordered may need `composer update`.
- A `storage` source's claims must not overlap a claim of any earlier source.
  This used to be checked for identical claims only, and an overlapping
  pattern left uploads to the shared names answering `409`.
- Capability rules for Composer follow the claim grammar. A rule that uses `?`
  or `[...]` no longer matches anything, and a malformed rule is logged when a
  request it belongs to is denied.
- `fs` stores create directories mode 0700 and files 0600. They lock through a
  fixed set of files in `<path>/#locks` instead of one file per object, and
  temp files older than an hour are removed at startup. Don't run an earlier
  version against the same `fs` store at the same time.
- Numeric git branches are named as Composer names them: branch `1.2` is
  `1.2.x-dev`, not `1.2-dev`.
- A git remote too long to pin (over 156 bytes) fails validation at startup.
- Tailnet identity (WhoIs) failures log one warning per 10 seconds at most; the rest
  are logged at debug.
- An upstream's health is logged when it changes, not on every failure.
- Upstream fetches also refuse IPv6 site-local, SIIT (`::ffff:0:0:0/96`) and
  `3fff::/20` addresses.
- SSH remotes ignore the system's known hosts file.

### Security

- Archives built from git sources leave out symlinks, as uploads already
  must. Each one left out is logged at warn. Archives built before this
  change are served unchanged.
- Served Composer metadata drops upstream `dist.mirrors`,
  `transport-options` and `notification-url`. Before, a registry source passed
  them through, so Composer could download from a mirror the upstream named
  and send install notices to the upstream directly.
- `github.com/klauspost/compress` is v1.20.2, which fixes a reachable panic on
  two-block frames (GO-2026-6865).

### Fixed

- `tailscale.state_dir` inside an `fs` store, or an `fs` store inside it, now
  fails validation, as docs/security.md said it would. Before, the cache could
  evict the node's keys.
- An S3 store with only one of `access_key_id` and `secret_access_key` fails
  validation.
- A tag that moved upstream stays served when recording the move fails.
- A registry source's missing `~dev` file no longer lets dev versions come
  from a later source while stable versions come from the registry.
- A retried upload completes the publish record if the interrupted upload
  never wrote it, even when a reader indexed the version meanwhile.
- An index listing no versions is rebuilt from the stored archives instead of
  being trusted, so the next upload no longer drops the other versions.
- Upload versions with a trailing NUL or vertical tab are rejected.
- A request waiting on another request's upstream fetch stops waiting when
  its own client disconnects.
- On shutdown, the background git loops stop before the `work_dir` lock is
  released, and a second signal exits at once.
- The status page, `/readyz` and `/metrics` need a capability rule with at
  least one entry; an empty `{}` grant no longer opens them.

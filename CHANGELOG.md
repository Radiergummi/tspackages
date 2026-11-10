# Changelog

All notable changes to tspackages are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

### Added

- `-version` prints the build, `-log-format text` switches the logs from
  JSON, and `tspackages_build_info` reports the running version.

### Changed

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

# Operations

How to run tspackages: deploying, backups, upgrades, monitoring and what to
do when something goes wrong. Read [security.md](security.md) first,
including its [threat model](security.md#threat-model); this page assumes
it.

tspackages is one process and one tsnet node. There is no cluster mode and no
standby. Everything below follows from that.

## Before the first start

- **MagicDNS and HTTPS in the tailnet.** Turn on both in the admin console.
  Without them startup fails with `you must enable MagicDNS in the DNS page
  of the admin panel` or `you must enable HTTPS in the admin panel`.
- **A tag and a key.** Give the node a tag (`tailscale.tags`, for example
  `tag:registry`; tagged nodes don't expire) and register it with an auth key
  or an OAuth client secret, as the
  [README quick start](../README.md#quick-start) shows. With an OAuth client
  secret (`tskey-client-...` in `TS_AUTHKEY` or `TS_CLIENT_SECRET`):
  - the node is ephemeral unless the secret says otherwise, and an
    ephemeral node is removed soon after it goes offline. Append
    `?ephemeral=false&preauthorized=true` to the secret;
  - every start calls the Tailscale API to mint a key, even for a
    registered node, and fails while that API is unreachable. Remove the
    secret from the environment once the node is up.
- **Tailnet Lock.** With Tailnet Lock on, a new node must be signed before
  it can talk to anyone: sign its node key with `tailscale lock sign` from a
  signing node, or register it with an auth key you signed beforehand. Keys
  minted from an OAuth secret can't be signed beforehand.
- **Grants.** Write the tailnet policy as
  [README: Tailnet policy](../README.md#tailnet-policy) shows. A monitoring
  node needs a grant too (see [Monitoring](#monitoring)).
- **Directories.** `tailscale.state_dir` and `storage.work_dir` follow the
  rules in the [security notes on secrets and state](security.md#secrets-and-state)
  and the README quick start. tspackages creates missing ones with mode 0700
  and refuses to start on one with another owner or mode, or on a symlink.
- **Stores.** Pick `fs` or `s3` for each of `storage.cache`, `storage.state`
  and the hosted `storage.stores`. No two may share a location (one path or
  prefix inside another counts). Keep the cache on local disk or in a bucket
  of its own: it deletes objects all the time, which a versioned bucket
  keeps as noncurrent versions. tspackages refuses to start while any store
  is unreachable.
- **git and ssh.** `git` sources run the `git` binary, and SSH remotes run
  `ssh`. The container image includes both; a host install needs them.

## Getting the binary or image

Release binaries and images come from a tagged release. Until the first one
is tagged, build them from a checkout:

```sh
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 make build   # ./tspackages
docker build --build-arg VERSION=$(git describe --tags --always) \
  --build-arg REVISION=$(git rev-parse HEAD) -t tspackages .
```

A release carries `tspackages_linux_amd64` and `tspackages_linux_arm64`,
each with a `.sha256` file, a provenance bundle and an SBOM bundle:

```sh
sha256sum -c tspackages_linux_amd64.sha256
gh attestation verify tspackages_linux_amd64 --repo radiergummi/tspackages \
  --bundle tspackages_linux_amd64.provenance.sigstore.json
```

and pushes the image `ghcr.io/radiergummi/tspackages` for `linux/amd64` and
`linux/arm64`, tagged with its version without the `v` (`1.2.3`); `1.2`, `1`
and `latest` move to the newest release. Pin an exact version or a digest,
and verify it with
`gh attestation verify oci://ghcr.io/radiergummi/tspackages:1.2.3 --repo radiergummi/tspackages`.

## Running under systemd

```sh
install -m 0755 tspackages /usr/local/bin/tspackages
useradd --system --home-dir /var/lib/tspackages --shell /usr/sbin/nologin tspackages
install -d -m 0750 -g tspackages /etc/tspackages
install -m 0640 -g tspackages config.yaml /etc/tspackages/config.yaml
install -m 0600 env /etc/tspackages/env   # read by systemd as root
```

The config and any file it names with `${file:}` must be readable by the
service user; owner root, group `tspackages` and mode 0640 keep them from
everyone else. A unit, with the paths from
[examples/config.yaml](../examples/config.yaml):

```ini
# /etc/systemd/system/tspackages.service
[Unit]
Description=tspackages
Wants=network-online.target
After=network-online.target

[Service]
User=tspackages
Group=tspackages
ExecStart=/usr/local/bin/tspackages -config /etc/tspackages/config.yaml
# TS_AUTHKEY=..., TS_NO_LOGS_NO_SUPPORT=1 and anything ${env:} names.
EnvironmentFile=/etc/tspackages/env
StateDirectory=tspackages
StateDirectoryMode=0700
Restart=on-failure
RestartSec=5s
# Shutdown waits up to 30 seconds for open requests, then for the git loops.
TimeoutStopSec=60s
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
```

`StateDirectory` creates `/var/lib/tspackages` owned by the service user, and
`ProtectSystem=strict` leaves it as the only writable path. Put `fs` stores
on another path and add it with `ReadWritePaths=`. Secrets can come from
systemd credentials too: `LoadCredential=deploy_key:/etc/tspackages/deploy_key`
and `ssh_key: ${file:/run/credentials/tspackages.service/deploy_key}`. That
path exists only inside the service, though, which rules out the config check
in [Upgrading](#upgrading).

Set `TS_NO_LOGS_NO_SUPPORT=1` unless you want tsnet's logs uploaded to
Tailscale. The process logs to stderr (JSON by default, `-log-format text`
otherwise), so the journal has everything. A configuration error exits with
status 1.

## Running the container

```sh
docker run -d --name tspackages --restart unless-stopped --stop-timeout 60 \
  --env-file /etc/tspackages/env \
  -v /etc/tspackages:/etc/tspackages:ro \
  -v tspackages-data:/var/lib/tspackages \
  ghcr.io/radiergummi/tspackages:1.2.3
```

The image runs as uid 10001, reads `/etc/tspackages/config.yaml` and declares
`/var/lib/tspackages` a volume. `/etc/tspackages` must be traversable and
the config and the files it names readable by uid 10001 (for example group
10001, mode 0750 on the directory and 0640 on the files).

The `--env-file` option takes one unquoted `KEY=value` per line: quotes stay
part of the value, and a value can't span lines. Write `TS_AUTHKEY` there
without quotes, and put multi-line secrets such as the SSH key and
`known_hosts` in files under `/etc/tspackages`, named in the config with
`${file:/etc/tspackages/deploy_key}`. Docker stops a
container after 10 seconds by default, sooner than tspackages' 30-second
drain, hence `--stop-timeout`. A bind mount instead of a named volume must
be owned by uid 10001 with mode 0700.

There is no local health port: tspackages listens only on the tailnet, on
443. A container health check from the host can't reach it; probe it from
the tailnet as [Monitoring](#monitoring) describes.

## What to back up

| Data | Where | Back up? | If lost |
|------|-------|----------|---------|
| Node and TLS keys | `tailscale.state_dir` | Yes, as a secret | New node identity; see [Losing a piece](#losing-a-piece). |
| Tag pins, git-built Composer archives and their `.meta.json` sidecars, git-built PyPI sdists, provenance, audit records | `storage.state` | Yes | Git-served versions may change bytes or vanish; history is gone. |
| Uploaded packages and their indexes | each store in `storage.stores` | Yes | Uploaded packages are gone. |
| Registry metadata and archives | `storage.cache` | No | Fetched again from upstream. |
| Git mirrors, SSH key files, spooled uploads, downloads in progress | `storage.work_dir` | No | Mirrors are cloned again; key files are rewritten at every start. |

The state store and the hosted stores hold private packages; protect their
backups as you protect the stores.

The state store's keys are `pins/`, `composer-git/`, `pypi-git/`,
`provenance/` and `audit/`. tspackages only ever creates objects there and
never overwrites or deletes one. A hosted store holds `composer/` and `pypi/`;
its objects never change either, except each package's `index.json`, which is
rewritten on every upload and can be rebuilt from the other objects.

### Stores on disk

The `fs` driver writes every object to a temp file, syncs it and renames it
into place, so an object on disk is always complete. Its locks are held only
for one operation each and don't cover a copy made from outside. A copy of
a running store can catch an index older or newer than the files it lists.
The state store has no indexes and its objects never change, so a copy of
it made while tspackages runs is fine (leave out `*#tmp` files). Copy the
hosted stores with the service stopped or from a filesystem snapshot (ZFS
or LVM, for example), or delete their `index.json` files after restoring
(see [Restoring](#restoring)). For the layout in the README quick start,
with `fs` stores at `/var/lib/tspackages/state` and
`/var/lib/tspackages/hosted` (the example config uses S3 instead):

```sh
systemctl stop tspackages
tar --format=posix -C /var/lib/tspackages --exclude='#locks' --exclude='*#tmp' \
  -czf /backup/tspackages-$(date +%F).tar.gz tailscale state hosted
systemctl start tspackages
```

`--format=posix` keeps modification times to the nanosecond. The `#etag`
files record them, and with whole seconds only every first read after a
restore hashes the object again. The archive holds the node keys: encrypt it, or keep the state dir out of it
and accept registering a new node after a loss. `#locks` and `*#tmp` files
are recreated or removed at startup. A snapshot of a running store is as
good as a crash: a publish that was in flight may be stored but not listed.
Running that publish again with the same file completes it.

For the container, stop it and archive the named volume from a helper
container:
`docker run --rm -v tspackages-data:/data:ro -v /backup:/backup debian:stable-slim tar --format=posix -C /data --exclude='#locks' --exclude='*#tmp' -czf /backup/tspackages.tar.gz .`

### Stores in buckets

- Turn on **versioning** on the state and hosted buckets, and **Object
  Lock** with a default retention on the state bucket. tspackages never
  overwrites or deletes in the state store, so a retention period doesn't
  get in its way. Use separate buckets for the state store and the hosted
  stores, so each gets its own settings.
- Use **governance mode** if you may ever need to purge something, such as
  a leaked secret: an account with the bypass permission can then remove
  locked versions. Compliance mode allows that to nobody until the retention
  ends.
- Test an upload after turning on Object Lock: some S3-compatible services
  want a checksum on every write to a locked bucket, and with `endpoint` set
  tspackages sends checksums only where the API requires them.
- Add a lifecycle rule that aborts incomplete multipart uploads after a
  day: uploads over 64MiB go up in parts, and an abort tspackages couldn't
  finish leaves parts behind. On hosted buckets, also expire noncurrent
  versions after your retention period; every upload leaves one of
  `index.json`.
- **Replicate** both buckets to another region or account.
- To restore, copy back the object versions that were current at the chosen
  time, or point the config at the replica.

## Restoring

1. Make sure no other instance runs against the same state dir or stores.
   Two copies of one tsnet state dir are two nodes with one identity, and
   two instances fight over indexes.
2. Restore the tsnet state dir (owner and mode 0700 included), the state
   store and the hosted stores. Leave the cache and `work_dir` empty.
3. If a hosted store was copied while tspackages ran, delete its
   `index.json` files so they are rebuilt from the files they list. Composer
   rebuilds an index on the next read. PyPI lists a package from its file
   records at once, but the package stays out of the `/pypi/simple/` project
   list until its next upload; pip and uv don't read that list.
4. Start tspackages. `/readyz` answers `ok` once every store is reachable.
   PyPI releases already in the state store are served at once. Names
   claimed by a Composer git source answer `502` until the first index
   pass, which starts at once and clones the mirrors first. See
   [When the registry is down](#when-the-registry-is-down) for PyPI git
   sources, which can take longer.
5. Publish again what was published after the backup, from the **original
   artifacts**: the same zip, wheel or sdist bytes. A rebuilt file has
   another `reference` or SHA256, and lock files that pinned the original
   stop installing.

The state store and the hosted stores don't have to come from the same
moment: hosted packages need nothing from the state store.

### Losing a piece

- **tsnet state dir.** The node needs a new key to register, and with
  Tailnet Lock a new signature (see
  [Before the first start](#before-the-first-start)). Delete the old machine
  in the admin console first: otherwise the new node gets a numbered host
  name (`registry-1`) and clients' URLs stop working. The new node fetches a
  new TLS certificate. Grants match its tag, so access is unchanged.
- **State store.** Tags are pinned again to whatever they point at now, so
  a tag moved since its first pin is accepted silently. Composer archives are
  rebuilt from git; if the bytes differ (another git version, for one), the
  `shasum` in existing `composer.lock` files no longer matches. PyPI sdists
  are regenerated; they come out the same only while the sdist format is
  unchanged and the same tagged commit wins, otherwise hash-pinned lock files break.
  Versions whose tags are gone upstream are lost. Provenance and audit
  records are lost, and the check for registry archives that changed
  upstream starts over.
- **A hosted store.** Its packages are gone; only publishing the original
  artifacts again brings them back unchanged. A lost `index.json` alone is
  harmless (see [Restoring](#restoring)).
- **Cache.** Everything is fetched again. While an upstream is down, cached
  registry metadata is served stale; without a cache those requests fail.
- **`work_dir`.** Mirrors are cloned again. A Composer remote that is
  unreachable at that point serves its pinned versions from the stored
  archives; PyPI releases already stored stay served either way.

## Upgrading

Only one instance may run per `work_dir`: it holds a lock on
`<work_dir>/.lock`. A second one waits up to 60 seconds for it and then
exits. Nothing detects two instances that share only stores, so never run
an old and a new version side by side against the same stores, even
briefly. Stop the old one, then start the new one; the upgrade is a short
outage.

1. Read the CHANGELOG between the two versions. Look for config that stops
   validating, changes to the stores and steps for clients.
2. Back up the state store, so a rollback has something to return to.
3. Optionally check the config with the new binary while the old one still
   runs. This works only if every secret comes from the environment or
   from a file the service user can read, not from `LoadCredential`:

   ```sh
   systemd-run --wait --pty --uid=tspackages \
     -p EnvironmentFile=/etc/tspackages/env \
     /usr/local/bin/tspackages.new -config /etc/tspackages/config.yaml
   ```

   Run it only while the old instance runs. Validation errors print at
   once. A valid config gets as far as the lock and logs `work_dir is
   locked by another instance; waiting`; stop it with Ctrl-C. If that line
   doesn't appear within a few seconds, stop it at once: it got the lock
   and is bringing up the real node.
4. Stop the old instance, replace the binary or image, start the new one.
5. Check `/readyz`, the status page and `tspackages_build_info`.

## Monitoring

All endpoints are on `https://<hostname>.<tailnet>.ts.net` and need a
tailnet identity:

| Path | Answers | Who may call it |
|------|---------|-----------------|
| `/healthz` | `ok` while the process serves | Any tailnet identity |
| `/readyz` | `ok`, or `503` when a store doesn't answer | A grant with at least one rule |
| `/metrics` | Prometheus metrics | A grant with at least one rule |
| `/` | Status page | A grant with at least one rule |

There is no monitoring-only capability. The monitoring node needs a grant
with at least one `read` or `write` entry and can do what that entry allows,
so give it `read` on as little as you can.

Metrics:

- `tspackages_requests_total{ecosystem,source,code}`: alert on a rising
  share of `5xx`.
- `tspackages_git_last_sync_timestamp_seconds{ecosystem,source}`: the
  oldest last successful sync among a git source's remotes, `0` until every
  remote has synced at least once. Alert when it falls more than a few poll intervals behind.
- `tspackages_upstream_request_duration_seconds{source}`,
  `tspackages_cache_hits_total`, `tspackages_rate_limited_total` and
  `tspackages_build_info{version,commit}`.

The status page shows each source's health, tags that moved upstream,
Composer packages declared by several remotes, registry archives whose bytes
changed, and PyPI git conflicts and skipped packages. It shows what the
running process has seen; restarts clear the moved-tag and changed-archive
lists until those are seen again. The logs are the lasting record. Lines
worth an alert:

| Message | Level | Means |
|---------|-------|-------|
| `relay: download failed` with `relay: digest mismatch` in `error` | warn | An upstream archive didn't match its declared hash. Nothing was cached, and the client's transfer was broken off short of its `Content-Length`. |
| `relay: download failed` with `relay: cache` in `error` | warn | A verified archive reached the client but couldn't be cached; the next request fetches it again. |
| `composer dist changed upstream; serving the new bytes` | warn | A registry archive differs from the bytes first seen for that version and reference. |
| `composer git: tag moved upstream; serving the pinned commit` | warn | A tag was force-pushed. The pin keeps the first commit. |
| `composer package declared by several remotes; not served` | error | Two remotes of one git source declare the same package. |
| `composer git: serving pinned versions only` | warn | A remote can't be indexed, so only its pinned versions are served. |
| `composer git index failed`, `pypi git index failed` | error | A whole index pass failed. |
| `composer git: indexing failed; keeping previous index` | error | A remote couldn't be indexed; its previous versions stay served. |
| `composer git: tag skipped`, `composer git: branch skipped` | warn | A version wasn't served; `error` says why, for example an archive with a path git can't hand over intact. |
| `composer git sync failed; ...`, `pypi git sync failed; ...` | warn | A remote is unreachable. |
| `pypi git: indexing a remote failed; its last scan stands` | warn | A remote couldn't be indexed. Until it has been once since startup, the source builds no new release (see [When the registry is down](#when-the-registry-is-down)). |
| `pypi git: reading a tag failed` | warn | A tag couldn't be read; until it is, the source builds no new release. |
| `pypi git: a rebuilt sdist differs from its release record; not written` | warn | Rebuilding a stored release's missing sdist gave other bytes. |
| `pypi git: building a release failed` | error | A release couldn't be generated; it is retried on the next pass. |
| `pypi git: repairing a release failed` | error | A stored release lacks its sdist and couldn't be built again. |
| `composer upstream unhealthy`, `pypi upstream unhealthy` | warn | A registry upstream fails; `stale` says whether cached metadata is served. |
| `left symlinks out of a git archive` | warn | A git-built archive lacks the listed symlinks. |
| `composer source failed`, `pypi source failed` | error | A request ended in `5xx`. |
| `not ready` | warn | `/readyz` failed. |

PyPI git conflicts (a release changed without a version bump, divergent
histories, a package in several repositories) and refused content (a tree,
path, `pyproject.toml` or workspace over the caps in the
[threat model](security.md#threat-model), nested members, duplicate paths)
appear on the status page only, not in the logs. A refusal is remembered
for the commit until restart; a fixed repository needs a new tag, and with
it a new version, anyway.

## Removing a bad publish

tspackages has no delete or yank: published bytes never change, so lock files
stay valid. When something must go anyway (a leaked secret, a broken release
that clients keep picking), remove it from the stores by hand.

Before you do:

- Clients that installed it keep it, and lock files that name it fail to
  install from then on.
- Publish the fix under a **new version**. Reusing a version number with
  other bytes breaks every lock file that pinned the old hash, and
  Composer's `shasum` check. For PyPI uploads the version stays blocked for
  a corrected file with another filename anyway (see
  [An upload to a PyPI storage source](#an-upload-to-a-pypi-storage-source)).
- Leave the provenance and audit records alone. They are the history of
  what was served.
- The order of the steps matters: in the order given, an upload or index
  rebuild that runs at the same time can't bring the version back. Pause
  publishes of the package anyway.
- A mistyped key deletes nothing and reports no error: `rm -f` and S3
  `DeleteObject` both succeed on a missing key. **List the prefix first**
  and check that every key you are about to delete is in the listing.
  Afterwards, fetch the file's old download URL and expect `404`.
- In an `fs` store, delete each object's `<key>#etag` file with it.

Names in keys are normalised: Composer's `<vendor>/<name>` is in lowercase;
a PyPI name is normalised as PEP 503 says (lowercase; runs of `-`, `_` and
`.` become `-`, so `Acme_Utils` is `acme-utils`). Some segments are then
encoded as lowercase base32hex without padding. This computes one (Python
3.10 or later):

```sh
esc() { python3 -c 'import base64,sys; print(base64.b32hexencode(sys.argv[1].encode()).decode().rstrip("=").lower())' "$1"; }
esc 1.0.0.0   # 64n30bhg5oo0
```

The keys are relative to the store's `path` or `prefix`.

### An upload to a Composer storage source

Find the version's `version_normalized` (for example `1.0.0.0`) in
`composer/<vendor>/<name>/index.json`, then delete:

1. `composer/<vendor>/<name>/<esc(version_normalized)>.zip`
2. `composer/<vendor>/<name>/<esc(version_normalized)>.meta.json`
3. `composer/<vendor>/<name>/index.json`

The next read rebuilds the index from the remaining zips. No restart is
needed. Check that the old `dist.url` (from a `composer.lock`, under
`/composer/dist/`) answers `404`. Nothing then stops the same version from being
uploaded again.

### An upload to a PyPI storage source

Find the file's `version` (the canonical form, `1.0` is `1`) in
`pypi/<esc(name)>/index.json`. With `<dir>` for
`pypi/<esc(name)>/<esc(version)>` and `<file>` for `<esc(filename)>`, delete:

1. `<dir>/<file>`
2. `<dir>/<file>.metadata` and `<dir>/<file>.attestations`, where present
3. `<dir>/<file>.json`
4. `pypi/<esc(name)>/index.json`

Reads then list the package from the remaining `.json` records, and the next
upload writes a new index. Until then the package is missing from the
`/pypi/simple/` project list; pip and uv don't read that list. Between the
first and the last step, downloads of the file fail with `502`. Check that
`/pypi/files/<source>/<name>/<filename>` answers `404`. No restart is
needed.

Leave the release's claim files (`<dir>/~sdist` and
`<dir>/<esc(~wheel-<tags>)>`). They hold the filename: the same filename can
be uploaded again, but a corrected file under another filename can't take
that version's sdist or wheel. Publish a new version.

### A Composer version from a git tag

Pins keep a served tag alive even after it is deleted upstream, so remove
both:

1. Delete the tag in the repository.
2. Wait for one index pass that synced after the deletion: one
   `poll_interval` (default 1m), with
   `tspackages_git_last_sync_timestamp_seconds` for the source later than
   the deletion. A pass that indexes a mirror synced before the deletion,
   or a stale mirror after a failed sync, still sees the tag and pins it
   again.
3. Delete `pins/composer/<source>/<esc(remote)>/<esc(tag)>.json` from the
   state store, with `<remote>` exactly as the config lists it.
4. Check after the next pass that the version is gone from
   `/composer/p2/<vendor>/<name>.json`.

The archive under
`composer-git/` can stay unless it holds a secret: the archive of a commit
is shared by every tag and branch that points at it, and is built again
while one does.

### A PyPI release from a git tag

A stored release stays served whatever happens to its tag, and a tag that
still offers it builds it again. So:

1. Delete every tag that offers this name and version, or leave them out of
   the source's `tags` mapping and restart.
2. Wait for one index pass that synced after that, as for Composer.
3. Delete everything under
   `pypi-git/<esc(source)>/<esc(name)>/<esc(version)>/` in the state store
   (`release.json`, the sdist and its `.metadata`), `version` again in
   canonical form.
4. Check after the next pass that the release is gone from
   `/pypi/simple/<name>/`.

### From a registry source

A bad upstream release is for the upstream to yank. tspackages fetches its
metadata again after `metadata_ttl`. Archives it already cached stay in the
cache until evicted; to drop them, stop tspackages and empty the cache.

### A leaked secret

Removing the release isn't enough. The secret also lives in:

- noncurrent versions in versioned buckets, and their replicas;
- backups;
- for a git-served version, the archives under `composer-git/<source>/`
  (`<commit>.zip` and `<commit>.meta.json`) and the release directories
  under `pypi-git/` in the state store;
- the git mirrors under `<work_dir>/git/`. Their directories are named by
  a hash; `git -C <dir> config remote.origin.url` shows a mirror's remote,
  or delete everything under `<work_dir>/git/`. Stop tspackages first; it
  clones every missing mirror again at start. Remove the commit from the
  repository first, or the clone brings it back;
- the cache, for a release from a registry source;
- every client and CI cache that downloaded it.

Rotate the secret regardless.

## When the registry is down

While tspackages is stopped, clients can't reach `https://<hostname>.<tailnet>.ts.net`
at all: connections fail, usually by timing out. Installs that need metadata
or an archive fail, and so do publishes.

Right after a start, names claimed by a Composer git source answer `502`
until the first index pass. A PyPI git source serves its stored releases at
once, but builds no new release, and answers `502` for a name without a
stored release instead of letting a later source answer, until every one of
its remotes has been synced and scanned since startup and every tag was
read. A remote that can't be reached after a restart holds that state until
it can, even with a local mirror; watch for
`pypi git: indexing a remote failed` and
`tspackages_git_last_sync_timestamp_seconds{ecosystem="pypi"}` staying at
`0`.

To keep that window small and harmless:

- **Restart fast.** Let systemd or Docker restart it on failure. At every
  start tspackages joins the tailnet, probes every store, lists the whole
  cache to rebuild its index and walks each `fs` store for stale temp files,
  so a large cache in S3 or a large `fs` store slows the start. Then the
  first git index pass runs.
- **Keep client caches.** Composer keeps downloaded archives in its cache
  directory and installs from a lock file without fetching them again. Every
  tspackages response carries `Cache-Control: private, no-store`, so don't
  count on a client's HTTP cache.
- **Cache in CI.** Persist Composer's cache directory between runs
  (`composer config cache-dir`). pip's cache is mostly an HTTP cache, which
  `no-store` keeps empty. For Python builds that must not depend on the registry, keep a wheelhouse
  (`pip download -d wheelhouse`, then `pip install --no-index --find-links
  wheelhouse`).
- **Upgrade at a quiet time** and tell publishers: an upload sent during
  the restart fails and must be run again.

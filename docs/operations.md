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
| Tag pins, git-built Composer archives and their `.meta.json` sidecars, git-built PyPI sdists, git-built Go module zips and pseudo-version records, the latest verified sum.golang.org tree head, provenance, audit records | `storage.state` | Yes | Git-served versions may change bytes or vanish; history is gone. |
| Uploaded packages and their indexes | each store in `storage.stores` | Yes | Uploaded packages are gone. |
| Registry metadata and archives, checksum database tiles, Go pseudo-version zips | `storage.cache` | No | Fetched or built again. |
| Git mirrors, SSH key files, spooled uploads, downloads in progress | `storage.work_dir` | No | Mirrors are cloned again; key files are rewritten at every start. |

The state store and the hosted stores hold private packages; protect their
backups as you protect the stores.

The state store's keys are `pins/`, `composer-git/`, `pypi-git/`,
`go-git/`, `go-pseudo/`, `go-sumdb/`, `apt/`, `provenance/` and `audit/`.
tspackages only ever creates objects there and never deletes one. The one
object it overwrites is `go-sumdb/sum.golang.org/latest`, the latest
verified checksum database tree head, rewritten whenever the tree grows. `apt/<source>/release-mark/<suite>` holds the date of the newest upstream apt `Release` accepted and is rewritten when a newer one arrives. A hosted store holds `composer/` and `pypi/`;
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
  deletes in the state store, so a retention period doesn't get in its way.
  `go-sumdb/sum.golang.org/latest` gets a new version on every write; a
  lifecycle rule may expire its noncurrent versions. Use separate buckets for the state store and the hosted
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
   PyPI releases and Go tag versions already in the state store are
   served at once. Names
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
  Go module zips are built again from the tags as they are now. Their
  `h1:` hashes match while a tag still points at its first commit; a tag
  moved since then gives a version that `go.sum` files reject. Pseudo-version records are lost, and
  with them the `h1:` check on rebuilds. The checksum database tree head is
  fetched again, so a fork from before the loss goes unnoticed.
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
  archives; PyPI releases and Go tag versions already stored stay served
  either way. Go pseudo-versions answer `502` until their commits are in
  the new mirror.

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

The status page has a section per configured ecosystem, with each source's
health, tags that moved upstream, Composer packages declared by several
remotes, registry archives whose bytes changed, PyPI git conflicts and
skipped packages, Go tags that were skipped, refused or moved and the
state of the sum.golang.org verifier, and npm tarballs that changed
upstream. It shows what the
running process has seen; restarts clear the moved-tag and changed-archive
lists until those are seen again. The logs are the lasting record. Lines
worth an alert:

| Message | Level | Means |
|---------|-------|-------|
| `relay: download failed` with `relay: digest mismatch` in `error` | warn | An upstream archive didn't match its declared hash. Nothing was cached, and the client's transfer was broken off short of its `Content-Length`. |
| `relay: download failed` with `relay: cache` in `error` | warn | A verified archive reached the client but couldn't be cached; the next request fetches it again. |
| `composer dist changed upstream; serving the new bytes` | warn | A registry archive differs from the bytes first seen for that version and reference. |
| `npm tarball changed upstream; serving the new bytes` | warn | A registry tarball differs from the bytes first seen for that version. |
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
| `goproxy git: pass failed` | error | A whole Go index pass failed. |
| `goproxy git: sync failed; indexing the local mirror` | warn | A remote is unreachable. |
| `goproxy git: tag moved upstream; serving the stored version` | warn | A tag was force-pushed. The stored version keeps the first commit. |
| `goproxy git: tag version skipped`, `goproxy git: tag version refused` | warn | A tag isn't served; `reason` says why (see [Size refusals](#size-refusals)). |
| `goproxy git: stored version refused`, `goproxy git: pseudo-version refused` | warn | A rebuild gave another `h1:` than the record, or the commit is gone; the version answers `502`. |
| `go checksum database misbehaved` | error | sum.golang.org contradicted the stored tree head; registry fetches fail until restart (see [The checksum database](#the-checksum-database)). |
| `composer upstream unhealthy`, `pypi upstream unhealthy`, `npm upstream unhealthy` | warn | A registry upstream fails; `stale` says whether cached metadata is served. |
| `left symlinks out of a git archive` | warn | A git-built archive lacks the listed symlinks. |
| `composer source failed`, `pypi source failed`, `go source failed`, `npm request failed` | error | A request ended in `5xx`. |
| `not ready` | warn | `/readyz` failed. |

PyPI git conflicts (a release changed without a version bump, divergent
histories, a package in several repositories) and refused content (a tree,
path, `pyproject.toml` or workspace over the caps in the
[threat model](security.md#threat-model), nested members, duplicate paths)
appear on the status page only, not in the logs. A refusal is remembered
for the commit until restart; a fixed repository needs a new tag, and with
it a new version, anyway.

## Go

### Client setup

Each machine runs, with the `GONOSUMDB` value from the status page:

```sh
go env -w GOPROXY=https://<hostname>.<tailnet>.ts.net/go
go env -w GONOSUMDB=github.com/acme
go env -u GOPRIVATE GONOPROXY
```

`GOPRIVATE` must be unset, not only `GONOSUMDB` set. It is the default for
`GONOPROXY` and `GONOSUMDB`, and the go command falls back to it when either
is set to an empty value. With `GOPRIVATE` covering the private paths, the
go command fetches those modules straight from VCS, which needs git
credentials on every machine and skips tspackages' tag pins. `GOPROXY`
takes no `,direct` and no `|`: a `404` for a private module would fall
through to VCS. CI runners need the same three settings, as environment
variables or with `go env -w`.

### Rate limits

A cold `go mod download` or `go build` makes several requests per module
(`list` or `.info`, `.mod`, `.zip`, and for public modules checksum database
lookup and tile requests), and over HTTPS the go command repeats every `4xx` once.
A `429` fails the go command; it doesn't retry. Size `requests_per_second`
and `burst` for a CI job that downloads its whole module graph from an
empty cache.

### Builds

Each `git` source has one build queue with 2 workers. A job has 10 minutes
from when a worker takes it. A request for a tag version, a pseudo-version
zip or a repair goes ahead of the index pass's work. A pass syncs each
remote, queues every tag version that isn't stored yet and never waits for
the builds.

A request for an unknown version, a branch or a commit syncs that remote
first, at most once per 10 seconds per remote, pass syncs included. A
request waits at most 30 seconds in all, for the sync and its build, then
answers `502`; the go command reports that and stops, so run it again
later. Until a remote has synced once since tspackages
started, its modules serve their stored versions and recorded
pseudo-versions only, and everything else answers `502`, never `404`.

### Size refusals

A module is refused, reported on the status page and remembered for its
commit until restart when:

- its root directory in the repository holds more than 100,000 files;
- the archive it is built from is over 500MiB or `max_artifact_bytes`. The
  archive is stored uncompressed (`git archive -0`) and holds files the
  module zip later drops (nested modules, `vendor/`), so this cap counts
  more bytes than the go command's own 500MiB limit on compressed output;
- its `go.mod` or root `LICENSE` is over 16MiB;
- its `go` directive is newer than the Go version tspackages was built
  with, or doesn't parse. An upgrade and restart builds it again.

Building a zip holds one entry record per file in memory, bounded by the
500MiB cap at up to 200,000 archive entries; the bytes stream through temp
files in `<work_dir>/go-build/`.

### Cache sizing

Pseudo-version zips live in the cache and are rebuilt on demand from the
mirror. The cache must hold at least the largest pseudo-version zip you
serve: a zip larger than the whole cache is dropped as it is stored, and
every request for it builds it again and fails. Tag versions live in the
state store and don't count.

### The checksum database

Registry `.mod` and `.zip` files are checked against sum.golang.org before
they are cached. The latest verified tree head is kept in the state store
under `go-sumdb/sum.golang.org/latest`, so a rolled-back or forked database
is detected across restarts. When the database answers with a tree that
contradicts it, tspackages logs `go checksum database misbehaved` at error
and every registry fetch that needs a lookup fails with `502` until
restart. Cached registry versions keep being served. The status page shows
the sum.golang.org row as the security error until restart. After a
restart, the next lookup records the security error again while the tiles
verified before are still cached; once they are evicted, every lookup still
fails, but the row shows `lookup failed`.

If the stored tree head itself is bad (it can't be verified with the key, or
the object is corrupt), stop tspackages, delete
`go-sumdb/sum.golang.org/latest` from the state store and start it again.
The next lookup stores a new tree head. Do this only once you are sure
sum.golang.org itself isn't the problem: deleting the object also forgets
the tree head a real fork would be checked against.

## npm

### Client setup

Each project (or each user's `~/.npmrc`) needs two lines, and no others for
the registry:

```ini
registry=https://<hostname>.<tailnet>.ts.net/npm/
//<hostname>.<tailnet>.ts.net/npm/:_authToken=tailscale
```

npm refuses to publish without a token for the registry, so the second line
holds a dummy one. tspackages strips it and never checks it; the caller's
grant decides. pnpm reads the same `.npmrc`. Don't add
`@scope:registry=` lines that point elsewhere: that scope then bypasses
tspackages and its claims.

Lockfiles written against registry.npmjs.org install unchanged: npm swaps
the `resolved` host for the configured registry (its `replace-registry-host`
setting, `npmjs` by default; don't set it to `never`), and pnpm lockfiles
carry no URLs for registry packages. A lockfile written against tspackages
names tspackages' host in `resolved`.

pnpm holds back versions younger than its `minimumReleaseAge` and, when an
install picks a just-published private version anyway, adds it to
`minimumReleaseAgeExclude` in `pnpm-workspace.yaml`. To keep that file
stable, exclude your private scopes up front:

```yaml
# pnpm-workspace.yaml
minimumReleaseAgeExclude:
  - "@acme/*"
```

### Publishing from CI

Give the CI node's tag `write` on its own package (`npm:@acme/sdk`), put the
two `.npmrc` lines in place and publish. Set the registry in `package.json`
so a publish from a laptop with another configuration can't go to
registry.npmjs.org:

```json
"publishConfig": {"registry": "https://<hostname>.<tailnet>.ts.net/npm/"}
```

`npm publish --registry https://<hostname>.<tailnet>.ts.net/npm/` does the
same for one run. `pnpm publish` works the same way. Publishing the same
bytes again succeeds; other bytes for an existing version fail with `E409`
and `version already exists`, also with `--force`. A publish under the
`latest` tag of a version lower than the current `latest` succeeds but
leaves `latest` where it was, and npm prints `latest stayed at <version>`.
`npm dist-tag add` and `rm` work on names a `storage` source serves; `latest`
can't be removed. `npm deprecate` and `npm unpublish` fail with `E405`.
Each tag move is audited as a `dist-tag` record before it's written, with
an `attempt` ID; a `dist-tag-commit` record with the same ID follows once
the write took effect. A `dist-tag` record whose attempt has no commit
most likely lost a concurrent write and changed nothing; after a crash or
a failed commit record (logged as an error) the move may still have taken
effect, so check the package's dist-tags.

`npm publish --provenance` works where npm can get an OIDC token (GitHub
Actions with `id-token: write`). The bundle is stored and recorded in the
provenance records but not served, so `npm audit signatures` doesn't find
it. npm's trusted-publishing token exchange, sent to the host root, gets a
`404`, which npm ignores.

### npm audit

`/npm/-/npm/v1/security/advisories/bulk` answers `404`. Forwarding it would
send every dependency name in the tree, private ones included, to
registry.npmjs.org. `npm install` and `npm ci` carry on and mention the
failure only with `--loglevel verbose`. `npm audit` fails with `audit
endpoint returned an error`. No vulnerability report comes through
tspackages; audit public dependencies with a tool that doesn't send private
names, and set `audit=false` in `.npmrc` to skip the request.

### Revalidation and rate limits

Packuments carry `Cache-Control: no-cache` and an `ETag`, so a fresh
publish is visible at once. The cost: every install sends a conditional
request per package and gets a `304`, even with a warm npm cache, about
1,000 requests for a tree of 1,000 packages. Tarballs come from npm's cache
(`npm config get cache`) or pnpm's store. Size `requests_per_second` and
`burst` for your largest install from one node. npm retries a `429` twice,
waiting at least 10 seconds each time (`fetch-retries`,
`fetch-retry-mintimeout`), so a limit that is too tight makes installs slow
before it fails them.

## Maven

### Client setup

tspackages must be the client's only repository. Maven and Gradle both
treat a `403` as "try the next repository": with Maven Central next to
tspackages, a caller without a read rule for a private artifact would get
a public artifact with the same coordinates from there. tspackages itself
never asks an upstream for claimed coordinates; keeping clients from
asking is the client configuration's job.

For Maven, `~/.m2/settings.xml` (the status page shows it with the host
filled in):

```xml
<settings>
  <mirrors>
    <mirror>
      <id>tspackages</id>
      <mirrorOf>*</mirrorOf>
      <url>https://<hostname>.<tailnet>.ts.net/maven/</url>
    </mirror>
  </mirrors>
  <profiles>
    <profile>
      <id>tspackages</id>
      <repositories>
        <repository>
          <id>tspackages</id>
          <url>https://<hostname>.<tailnet>.ts.net/maven/</url>
          <snapshots><enabled>true</enabled></snapshots>
        </repository>
      </repositories>
    </profile>
  </profiles>
  <activeProfiles>
    <activeProfile>tspackages</activeProfile>
  </activeProfiles>
</settings>
```

`<mirrorOf>*</mirrorOf>` sends every repository to tspackages, including
the ones POMs declare and plugin repositories. A mirror of Central takes
Central's policy, which turns SNAPSHOT versions off, so the profile adds a
repository with SNAPSHOT versions on that the mirror also covers. Without SNAPSHOT
dependencies, the mirror alone is enough.

For Gradle, in `build.gradle.kts`, or in `settings.gradle.kts` under
`dependencyResolutionManagement`:

```kotlin
repositories {
    maven { url = uri("https://<hostname>.<tailnet>.ts.net/maven/") }
}
```

Neither client needs a `<server>` entry or a `credentials` block: without
one they send no `Authorization` header, and tspackages strips any that
arrives. Nothing answers `401`, so neither client prompts for a password.

### Deploying from CI

A deploy reads as well as writes: both clients fetch `maven-metadata.xml`
before they upload theirs, and Maven aborts on anything but a `200` or
`404` there. Give the CI node's tag both rules for its own artifacts:

```hujson
"app": {"github.com/radiergummi/tspackages": [
  {"read": ["maven:com.acme:lib"], "write": ["maven:com.acme:lib"]}
]}
```

Its builds also read their plugins and dependencies through tspackages,
so in practice the CI tag reads `*`. In `pom.xml`:

```xml
<distributionManagement>
  <repository>
    <id>tspackages</id>
    <url>https://<hostname>.<tailnet>.ts.net/maven/</url>
  </repository>
  <snapshotRepository>
    <id>tspackages</id>
    <url>https://<hostname>.<tailnet>.ts.net/maven/</url>
  </snapshotRepository>
</distributionManagement>
```

and run `mvn deploy`. For Gradle's `maven-publish`, in `build.gradle.kts`:

```kotlin
publishing {
    repositories {
        maven { url = uri("https://<hostname>.<tailnet>.ts.net/maven/") }
    }
}
```

and run `gradle publish`. Signatures from Gradle's `signing` plugin or
`maven-gpg-plugin` (`.asc`) are stored and served like any file.

- Deploying the same bytes again succeeds; other bytes for a file of a
  release fail the build with `409`, and the stored file stays. Maven's
  jars carry build timestamps, so a second `mvn deploy` of a release
  without `project.build.outputTimestamp` fails. Bump the version.
- A POM whose `groupId`, `artifactId` or `version` holds a `${…}` property
  is refused with `400 unresolved property … deploy a flattened POM`. With
  CI-friendly versions (`${revision}`), deploy through the
  `flatten-maven-plugin`.
- Uploaded checksums must match the file (`400 checksum mismatch`), and
  uploaded `maven-metadata.xml` must name the deployed artifact. Both are
  then discarded; tspackages serves its own.
- A `maven-plugin` deploys like any artifact. Storage sources serve no
  group-level `maven-metadata.xml`, so a private plugin doesn't resolve by
  its prefix (`mvn foo:goal`); call it by its coordinates,
  `mvn com.acme:foo-maven-plugin:1.0:goal`.
- A release version is listed once its POM is stored, before the deploy
  has uploaded everything. A build that resolves it in that moment gets a
  `404` for the jar, which Maven remembers for a day (`mvn -U` retries).
  Resolve after the deploy job ends.

### SNAPSHOT versions

Each SNAPSHOT deploy adds timestamped files (`lib-1.0-20261123.101010-3.jar`)
and the version's `maven-metadata.xml` points at the newest. They are kept
without limit; there is no retention. Timestamped files are written once:
two deploys of one SNAPSHOT version at the same moment may pick the same
build number, and the later one then fails with `409` (run it again for
a new build number).

Consumers need the profile from [Client setup](#client-setup-2). Maven
looks for a newer SNAPSHOT once a day (`mvn -U` forces it), Gradle every
24 hours (`--refresh-dependencies`).

### Gradle plugins

The Gradle Plugin Portal isn't proxied. A plugin's marker artifact lives
in a group named after the plugin ID, so the portal can't be a claimed
source, and Maven Central is the one unclaimed source. Keep the portal for
public plugins and send your own groups only to tspackages, in
`settings.gradle.kts`:

```kotlin
pluginManagement {
    repositories {
        exclusiveContent {
            forRepository { maven { url = uri("https://<hostname>.<tailnet>.ts.net/maven/") } }
            filter { includeGroupByRegex("com\\.acme(\\..*)?") }
        }
        gradlePluginPortal()
    }
}
```

Public plugins then come from the portal directly, not through tspackages.

### Upstream files without a checksum

Files from a `registry` source are verified against the upstream's
`<file>.sha1` before they are cached. Maven Central publishes none for
many signature files (`.asc`): those are fetched from the upstream on every
request, up to 64KiB, served without checksum headers and never cached.
Clients check signatures against the signer's key, not a digest. Any other
file without an upstream `.sha1` answers `502 upstream declares no checksum
for <file>`.

### Cold cache and rate limits

A file that isn't cached yet costs two upstream fetches, its `.sha1` and
then the file, and a Maven build's plugins alone are a few hundred files.
At the default `upstream_fetches_per_second` of 10 per node, the first
`mvn deploy` of a small project on an empty cache spends about a minute
waiting for the limiter. Raise the limit for CI nodes that build against a
cold cache. A release file's `.sha1` is fetched once and kept, so later
builds of release dependencies make no upstream request, even with a
fresh `~/.m2`. SNAPSHOT files' `.sha1`, files the upstream lacks and
`maven-metadata.xml` are fetched again after `metadata_ttl`. Files and
`maven-metadata.xml` carry `X-Checksum-Sha1` and `X-Checksum-Md5`, so
Maven doesn't request the checksum files.

## apt

### The signing key

Storage sources sign their `InRelease` and `Release.gpg` with one key from
`apt.signing_key`. It must be a legacy (v4) Ed25519 (EdDSA) or an RSA key
of 3072 bits or more. RFC 9580 keys (v6, algorithm 27) are refused at
startup, because apt's `gpgv` can't verify them. To generate one and
export it armored:

```sh
gpg --quick-generate-key 'tspackages apt' ed25519 sign never
gpg --armor --export-secret-keys 'tspackages apt' > /etc/tspackages/apt-signing.asc
chmod 600 /etc/tspackages/apt-signing.asc
```

Set `signing_key: ${file:/etc/tspackages/apt-signing.asc}`. A key with a
passphrase needs `signing_key_passphrase` (`${env:}` or `${file:}`).
Verified with apt 3.0.4 (`sqv`) and apt 2.8.4 (`gpgv`). The status page
shows the key's fingerprint.

Back the private key up like the tsnet state dir: it is a secret, and
tspackages never logs or serves it. Clients trust the public key at
`/apt/key.asc`; if you lose the private key, generate a new one, and every
client needs the new public key. There is no rotation tooling yet, so a
change of key means installing the new `key.asc` on every client at the
same time as the restart.

A registry source's `keyring` is the path of the upstream's public
keyring, armored or binary, read at startup (for Debian,
`/usr/share/keyrings/debian-archive-keyring.gpg`). It isn't a `${file:}`
reference.

### Client setup

A client needs three things per tailnet: the key, the preferences file
and one deb822 stanza per source. The status page shows them with the
host filled in.

```sh
curl -fsSL https://<hostname>.<tailnet>.ts.net/apt/key.asc -o /etc/apt/keyrings/tspackages.asc
curl -fsSL https://<hostname>.<tailnet>.ts.net/apt/preferences -o /etc/apt/preferences.d/tspackages.pref
```

```
# /etc/apt/sources.list.d/tspackages.sources
Types: deb
URIs: https://<hostname>.<tailnet>.ts.net/apt/hosted/
Suites: stable
Components: main
Signed-By: /etc/apt/keyrings/tspackages.asc
```

Use any tool that writes these three files and keeps them current. As
a shell script, the `curl` lines above run as they are. As a
configuration-management file resource, the preferences file is a file
whose content is fetched from `https://<hostname>.<tailnet>.ts.net/apt/preferences`
and refreshed regularly, because it changes when claims change.

For a `registry` source, the stanza lists the configured suites and
components, with `Signed-By` set to the upstream's keyring, not the
tspackages key: tspackages passes the upstream's own signed `Release`
through, and apt verifies it again.

**A client without the preferences file isn't protected.** apt merges the
versions of every repository it knows, so a claimed name that another
configured repository offers at a higher version would be installed from
there. The file pins each claimed name to `o=tspackages,l=<source>` at
priority 1001 and blocks it (priority -1) everywhere else. It lists
every claim of every `storage` source to any caller with an `apt:` read
rule. **Claims are public:** don't put a secret product name into a
claim. What stays hidden is which packages exist. `Origin` is
self-declared by a repository, so the pin doesn't defend against a
malicious repository the client already trusts with root.

As a second line, a name claimed by a `storage` source is `404` on every
`registry` source and is never fetched upstream, for clients that use the
mirror without the pins.

### Uploading from CI

```sh
curl -fT acme-tool_1.0-1_amd64.deb https://<hostname>.<tailnet>.ts.net/apt/hosted/stable/main/
```

`curl` appends the file name. Give the CI node's tag a write rule for the
package name, and no `Authorization` header or credentials:

```hujson
"app": {"github.com/radiergummi/tspackages": [
  {"read": ["apt:acme-*"], "write": ["apt:acme-tool"]}
]}
```

- The suite and component come from the URL and are free-form
  (`[a-z0-9][a-z0-9._-]*`, at most 64 bytes). A suite exists once it has a
  package. Write rules match package names only: a writer may upload to
  any suite. Suite-scoped write rules aren't there yet.
- The file name is `<name>_<version>_<arch>.deb`, with the version
  without its epoch. The name, version and architecture must match the
  package's `control` file, or the upload is `400`.
- The same bytes again are `201` and add the file to that suite too, so a
  package can be published to several suites. Other bytes for the same
  name, version and architecture are `409`, whatever the suite. Files are
  identified by name, version without epoch and architecture, so `1:2.0`
  and `2.0` are one file.
- `Expect: 100-continue` uploads send no body when the write rule is
  missing.
- Every version stays listed; apt installs the highest version its pins
  allow. Deleting answers `405` (see [Removing a bad
  publish](#removing-a-bad-publish)).

Readers see only the packages their `apt:` read rules match. Indexes of
a suite are generated and signed per caller, so a caller with no matching
rule gets valid, empty indexes for an existing suite.

### Upstream repositories

`registry` sources verify the upstream's `Release` against `keyring` (any
one valid signature is enough) before anything else is fetched. They
reject it, and serve the previous copy meanwhile, when its `Valid-Until`
has passed, when its `Suite` or `Codename` isn't the configured suite,
when its `Date` is more than a day ahead of the clock, or when its `Date`
is older than the newest accepted one. That date is
kept in the state store, so a lost cache doesn't allow a rollback. A
suite that the upstream renames or retires therefore stops updating and
needs its config changed. Files are served only when the verified
`Release` or `Packages` lists them, and are checked against that hash
before they are cached.

Any `apt:` read rule allows reading from a registry source, indexes and
downloads alike. The first `apt-get update` of a large suite fetches the
`Packages` index and builds a pool lookup from it; later ones fetch only
what changed.

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
`.` become `-`, so `Acme_Utils` is `acme-utils`); an npm name is in
lowercase, scope included (`@Acme/X` is `@acme/x`); an apt package name is lowercase. Some segments are then
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

### An upload to an npm storage source

Every segment is encoded, the name as a whole with its scope and slash:
`esc @acme/x` is `81gm6rb55ts0`, `esc 1.0.0` is `64n30bhg`. With `<pkg>`
for `npm/<esc(name)>` and `<dir>` for `<pkg>/<esc(version)>` (the version
as published, build metadata included):

1. If a dist-tag points at the version (`npm view <name> dist-tags`), move
   it first: `npm dist-tag add <name>@<other-version> latest`, and
   `npm dist-tag rm <name> <tag>` for other tags. A tag left on a removed
   version disappears from the packument; without `latest`,
   `npm install <name>` fails.
2. Delete `<dir>/package.json`, the version's record.
3. Delete `<pkg>/index.json`.
4. Delete `<dir>/package.tgz` and, where present, `<dir>/package.sigstore`.

Between the second and the third step, reads of the package fail with
`502`. After it, reads rebuild the index from the remaining
`package.json` records, scanning the package on every read until its next
publish writes a new index. Check that
`/npm/<name>/-/<base>-<version>.tgz` (`<base>` without the scope) answers
`404` and that `npm view <name> versions` no longer lists it. No restart is
needed.

If the tags weren't moved first, delete `<pkg>/dist-tags.json` as well:
`latest` then falls back to the highest remaining release, the status page
reports the lost document, and the next tag change (a publish or
`npm dist-tag add`) writes it afresh, holding only the fallback `latest`
and that change. Re-add the other tags.

Leave `<dir>/~claim`, `<dir>/~tagged` and the `~precedence` claim, which
sits under the version without build metadata (`<pkg>/<esc(1.0.0)>/` for
`1.0.0+a`). The claim holds the SHA256 of the tarball: the same bytes can be
published again, but other bytes for that version, or a version differing
from it only in build metadata, are refused with `409`. Publish a new
version.

### A deploy to a Maven storage source

Maven keys keep the exact case: every segment is the encoded `groupId`,
`artifactId`, version or file name as deployed (`esc com.acme` is
`cdnmqbj1cdmma`, `esc lib` is `dhkm4`, `esc 1.0` is `64n30`). With `<art>`
for `maven/<esc(groupId)>/<esc(artifactId)>` and `<dir>` for
`<art>/<esc(version)>`, to remove a whole version:

1. Delete `<dir>/~pom`, the version's claim.
2. Delete `<art>/index.json`.
3. Delete everything under `<dir>/files/`: each file and its `.json`
   record.

After the second step, reads rebuild the artifact's `maven-metadata.xml`
from the remaining `~pom` claims, scanning the artifact on every read until
its next deploy writes a new index. Check that the version is gone from
`/maven/<group path>/<artifactId>/maven-metadata.xml` and that the jar's
URL answers `404`. No restart is needed. Nothing then stops the same
version from being deployed again, but Maven and Gradle keep a release they
downloaded for good: publish the fix as a new version.

To drop one bad build of a SNAPSHOT, delete its timestamped files and
their `.json` records under `<dir>/files/`; the version's
`maven-metadata.xml` is built from the records that remain.

`maven/~case/<esc(lowercased groupId:artifactId)>` holds the case in which
an artifact was first deployed, and refuses a deploy of it in another
case. Leave it while files remain under that spelling. A first deploy
reserves it even when it fails, so a mistyped first deploy can block the
right spelling. Delete the entry once nothing remains under
`maven/<esc(groupId)>/<esc(artifactId)>/` for the reserved spelling.

A release file stored without its `.json` record (a deploy interrupted
between the two writes) isn't served, but blocks a deploy of other bytes
under its name with `409`. To unblock it, delete the orphan file under
`<dir>/files/`, then deploy again. The same bytes again complete the
interrupted deploy without that.

### An upload to an apt storage source

apt keys encode every segment of the package name, version without epoch
and architecture, suite and component (the `esc` function from earlier; `E()` below). With
`<pool>` for `apt/<src>/pool/E(name)/E(version)/E(arch)`:

1. Delete the suite member objects
   `apt/<src>/dists/E(suite)/E(component)/members/E(name)/E(version)/E(arch)`,
   one for each suite and component that lists the file.
2. Delete `<pool>/deb`, `<pool>/deb.json` and `<pool>/~claim`.
3. Delete `apt/<src>/dists/E(suite)/index.json` of each suite you
   changed. It is rebuilt from the members that remain.

Rendered indexes in the cache are keyed by the suite index's ETag, so
the next read replaces them, and no restart is needed. Check that
`apt-cache policy <name>` no longer shows the version and that the file's
download URL answers `404`. After step 2, nothing stops the same version
from being uploaded again; machines that installed it keep it, so publish
the fix as a new version.

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
until the first index pass, and a claimed name the source doesn't serve
keeps answering `502` until every one of its remotes has been indexed once
(a remote with pinned tags counts as soon as its pins are served). A PyPI git source serves its stored releases at
once, but builds no new release, and answers `502` for a name without a
stored release instead of letting a later source answer, until every one of
its remotes has been synced and scanned since startup and every tag was
read. A remote that can't be reached after a restart holds that state until
it can, even with a local mirror; watch for
`pypi git: indexing a remote failed` and
`tspackages_git_last_sync_timestamp_seconds{ecosystem="pypi"}` staying at
`0`, or absent before the first pass ends: alert on `absent()` as well.

To keep that window small and harmless:

- **Restart fast.** Let systemd or Docker restart it on failure. At every
  start tspackages joins the tailnet, probes every store, lists the whole
  cache to rebuild its index and walks each `fs` store for stale temp files,
  so a large cache in S3 or a large `fs` store slows the start. Then the
  first git index pass runs.
- **Keep client caches.** Composer keeps downloaded archives in its cache
  directory and installs from a lock file without fetching them again, and
  npm and pnpm keep tarballs by their integrity. npm packuments and version
  documents carry `Cache-Control: no-cache` (checked again on every use) and
  npm tarballs `private, max-age=31536000, immutable`; every other
  tspackages response carries `private, no-store`, so don't count on a
  client's HTTP cache.
- **Cache in CI.** Persist Composer's cache directory between runs
  (`composer config cache-dir`), and npm's cache or pnpm's store
  (`npm config get cache`, `pnpm store path`). pip's cache is mostly an HTTP cache, which
  `no-store` keeps empty. For Python builds that must not depend on the registry, keep a wheelhouse
  (`pip download -d wheelhouse`, then `pip install --no-index --find-links
  wheelhouse`).
- **Upgrade at a quiet time** and tell publishers: an upload sent during
  the restart fails and must be run again.

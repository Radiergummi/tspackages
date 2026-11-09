# tspackages

A package registry that exists only on your Tailscale tailnet. One endpoint per
ecosystem speaks the ecosystem's native protocol; each endpoint is assembled
from sources (another registry, its own storage, or a git remote). Every
request is authorized by Tailscale identity, so clients hold no registry
credentials.

Milestone 1 ships Composer. PyPI, Go, npm, OCI and Maven follow; see
[the design](docs/superpowers/specs/2026-11-09-tspackages-design.md) if you have
the repository checked out, and read [docs/security.md](docs/security.md) before
you deploy.

- Tailscale is the only authentication. There are no tokens, no basic auth and
  no dev mode. A caller without a matching capability gets `403`.
- Claimed names resolve only from the sources that claim them. A private name
  never falls through to a public source.
- Single static binary (plus `git`), no database. Runs as one tsnet node, so it
  cannot sit behind Tailscale Serve or another reverse proxy.

## Quick start

1. Write a config (see [examples/config.yaml](examples/config.yaml)):

   ```yaml
   tailscale:
     hostname: registry
     state_dir: /var/lib/tspackages/tailscale
   storage:
     work_dir: /var/lib/tspackages/work
     cache: {driver: fs, path: /var/lib/tspackages/cache, max_size: 50GiB}
     state: {driver: fs, path: /var/lib/tspackages/state}
     stores:
       main: {driver: fs, path: /var/lib/tspackages/hosted}
   ecosystems:
     composer:
       sources:
         - {name: hosted, type: storage, store: main, claims: ["acme/*"]}
         - name: packagist
           type: registry
           url: https://repo.packagist.org
           fetch_hosts: [repo.packagist.org, api.github.com, codeload.github.com]
   ```

   `storage.work_dir` is required. It holds git mirrors and SSH key material and
   must be absolute, mode 0700, owned by the service user, and share no location
   with any store or `tailscale.state_dir`. Startup validates the whole config
   and refuses to start on errors.

   Stores use `driver: fs` (`path`) or `driver: s3` with `bucket` and the
   optional keys `region` (default `us-east-1`), `endpoint` (for MinIO and
   other S3-compatible services; enables path-style addressing), `prefix`
   (lowercase), `access_key_id` and `secret_access_key`. Without the two key
   fields the AWS default credential chain applies (environment, shared config,
   instance or task role). `cache` also takes `max_size` (default 10GiB).

2. Run it with an auth key (or an OAuth client secret, in which case it
   advertises `tailscale.tags`):

   ```sh
   docker run -d --name tspackages \
     -e TS_AUTHKEY=tskey-... -e TS_NO_LOGS_NO_SUPPORT=1 \
     -v /etc/tspackages:/etc/tspackages:ro \
     -v tspackages-data:/var/lib/tspackages \
     tspackages
   ```

   The image runs as uid 10001 with `/var/lib/tspackages` as a volume and reads
   `/etc/tspackages/config.yaml`. With a bind mount instead of a named volume,
   the host directories for `work_dir` and `tailscale.state_dir` must be owned
   by uid 10001 with mode 0700 (`install -d -o 10001 -m 0700 <dir>`), or
   startup refuses them. Or build the binary: `go build ./cmd/tspackages`
   and run `tspackages -config config.yaml`.

3. Grant access in your tailnet policy (see below).

The node serves HTTPS on `https://<hostname>.<tailnet>.ts.net`. `/` (a status
page), `/readyz` and `/metrics` need at least one capability rule; `/healthz`
answers any tailnet identity. The status page lists a git remote only to
callers who may read the package it declares.

## Composer sources

Sources are listed per ecosystem, in order. A claim is `*` or a lowercase
`<vendor>/<name>` pattern of `[a-z0-9_.-]` and `*` wildcards (no `?` or `[...]`),
matched against the lowercase package name; anything else fails validation. At most one source
may be unclaimed (the public catch-all); `storage` sources must have claims.

| Type | Keys | Does |
|------|------|------|
| `git` | `remotes`, `branches`, `ssh_key`, `known_hosts`, `token`, `poll_interval` | Tags become versions, allowlisted branches become `dev-*`. Dist zips are built with `git archive` and kept. Package names come from each repo's `composer.json`. |
| `storage` | `store`, `claims` | Hosts uploaded dist zips on the named store. |
| `registry` | `url` (https), `fetch_hosts`, `credentials`, `download_credentials`, `metadata_ttl` | Pass-through to an upstream (Packagist). Dist URLs are rewritten to this server. |

`ssh_key`, `known_hosts`, `token` and credentials accept `${env:NAME}` or
`${file:/path}`. Limits (`max_upload_bytes`, `max_decompressed_bytes`,
`max_archive_entries`, `max_artifact_bytes`, `requests_per_second`, `burst`,
`upstream_fetches_per_second`) have defaults; see `internal/config`. Rates must
be positive. `max_artifact_bytes` (default 500MiB) caps a registry dist download
and a git-built archive; each is buffered in memory up to that size, so size
the container's memory for it. `max_decompressed_bytes` applies to upload
inspection.

## Client setup

In `composer.json`:

```json
{
  "repositories": [
    {"type": "composer", "url": "https://registry.<tailnet>.ts.net/composer"},
    {"packagist.org": false}
  ]
}
```

No `auth.json` is needed. Publish a dist zip to a `storage` source with a plain
HTTP `PUT` (Composer has no publish command); the version comes from the URL and
must match the `composer.json` inside the zip:

```sh
curl -fsS -X PUT --data-binary @b-1.0.0.zip \
  https://registry.<tailnet>.ts.net/composer/upload/acme/b/1.0.0
```

Republishing a version is rejected with `409`, and so is an upload of a name
that an earlier source also claims (it would be stored but never served).

## Tailnet policy

Humans read; each publishing repo gets its own CI tag with write on its own
package only ([examples/policy.hujson](examples/policy.hujson)):

```hujson
"grants": [
  {
    "src": ["group:dev"],
    "dst": ["tag:registry"],
    "ip":  ["tcp:443"],
    "app": {"github.com/radiergummi/tspackages": [{"read": ["*"]}]}
  },
  {
    "src": ["tag:ci-sdk-php"],
    "dst": ["tag:registry"],
    "ip":  ["tcp:443"],
    "app": {"github.com/radiergummi/tspackages": [
      {"read": ["*"], "write": ["composer:matchory-internal/sdk-php"]}
    ]}
  }
]
```

A rule is `<ecosystem>:<pattern>` or `*`. `read` covers metadata and
downloads, `write` covers publishing. Capabilities from several grants are
unioned. The capability name is configurable (`tailscale.capability`).

## Development

```sh
go vet ./... && go test -race ./...
go test -tags integration ./integration/...   # needs composer and git
```

S3 tests run when `TSP_TEST_S3_ENDPOINT` points at a MinIO.

Licensed under Apache-2.0.

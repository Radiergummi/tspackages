# tspackages

A package registry that exists only on your Tailscale tailnet. One endpoint per
ecosystem speaks the ecosystem's native protocol; each endpoint is assembled
from sources (another registry, its own storage, or a git remote). Every
request is authorized by Tailscale identity, so clients hold no registry
credentials.

Composer and PyPI ship today. Go, npm, OCI and Maven follow. Read
[docs/security.md](docs/security.md) before you deploy.

- Tailscale is the only authentication. There are no tokens, no basic auth and
  no dev mode. A caller without a matching capability gets `403`.
- Claimed names resolve only from the sources that claim them. A private name
  never falls through to a public source.
- Single static binary (plus `git`), no database. Runs as one tsnet node, so it
  can't sit behind Tailscale Serve or another reverse proxy.

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
   startup refuses them. Or build the binary with `make build` and run
   `tspackages -config config.yaml`. `-log-level` (`debug`, `info`, `warn`,
   `error`) and `-log-format` (`json`, `text`) set the logging, and
   `tspackages -version` prints the build.

3. Grant access in your tailnet policy (see [Tailnet policy](#tailnet-policy)).

The node serves HTTPS on `https://<hostname>.<tailnet>.ts.net`. `/` (a status
page), `/readyz` and `/metrics` need at least one capability rule; `/healthz`
answers any tailnet identity. The status page lists a git remote only to
callers who may read the package it declares.

## Composer sources

Sources are listed per ecosystem, in order. A claim is `*` or a lowercase
`<vendor>/<name>` pattern of `[a-z0-9_.-]` and `*` wildcards (no `?` or `[...]`),
matched against the lowercase package name; anything else fails validation. At most one source
may be unclaimed (the public catch-all); `storage` sources must have claims,
and none of them may overlap a claim of an earlier source, since uploads go to
the first claiming source.

| Type | Keys | Does |
|------|------|------|
| `git` | `remotes`, `branches`, `ssh_key`, `known_hosts`, `token`, `poll_interval` | Tags become versions, allowlisted branches become `dev-*`. Dist zips are built with `git archive` and kept. Package names come from each repo's `composer.json`. |
| `storage` | `store`, `claims` | Hosts uploaded dist zips on the named store. |
| `registry` | `url` (`https://` only), `fetch_hosts`, `credentials`, `download_credentials`, `metadata_ttl` | Pass-through to an upstream (Packagist). Dist URLs are rewritten to this server. |

`ssh_key`, `known_hosts`, `token` and credentials accept `${env:NAME}` or
`${file:/path}`. Limits (`max_upload_bytes`, `max_decompressed_bytes`,
`max_archive_entries`, `max_artifact_bytes`, `requests_per_second`, `burst`,
`upstream_fetches_per_second`) have defaults; see `internal/config`. Rates must
be positive. `max_artifact_bytes` (default 8GiB) caps an upstream artifact
download. Downloads stream to clients while they arrive and are cached once
their digest matches, so memory use doesn't grow with artifact size; size the
cache's `max_size` for the largest artifacts you expect. Composer git-built
archives and PyPI git-built sdists are built in memory and capped at 512MiB
(or `max_artifact_bytes`, if lower); a larger PyPI package is refused and
reported. `max_decompressed_bytes` applies to upload inspection.

## PyPI sources

PyPI has the same three source types and the same resolution rules. Names
are normalised as PEP 503 says (lowercase; runs of `-`, `_` and `.` become
`-`) before claims, authorization and storage, so `Acme_Utils` and
`acme.utils` are one package. A claim is `*` or a pattern of `[a-z0-9-]` and
`*` in normalised form, with no leading, trailing or doubled `-`. `acme-*`
doesn't match the bare name `acme`; claim both with `["acme", "acme-*"]`. Versions are compared by PEP 440 equality:
`1.0` and `1.0.0` are one version, so a release can't be published twice
under two spellings.

| Type | Keys | Does |
|------|------|------|
| `git` | `remotes`, `tags`, `ssh_key`, `known_hosts`, `token`, `poll_interval` | Each tag is a release point: every package found at the tagged commit is released at the version its `pyproject.toml` declares, as an sdist tspackages generates (no build runs on the server). |
| `storage` | `store`, `claims` | Hosts wheels and sdists uploaded with `twine` or `uv publish`. |
| `registry` | `url` (`https://`, ending in `/simple/`), `fetch_hosts`, `credentials`, `download_credentials`, `metadata_ttl` | Pass-through to a JSON simple API index (`pypi.org`). |

For `pypi.org` use `url: https://pypi.org/simple/` and
`fetch_hosts: [pypi.org, files.pythonhosted.org]`.

The `git` source finds the root `pyproject.toml`'s package and each uv
workspace member. A package needs a static `[project] name` and `version`;
packages with a dynamic version (`setuptools_scm`, `hatch-vcs`), without a
`[build-system]` table or with `[tool.uv] package = false` are skipped and
listed on the status page. Branches aren't served. Optionally, `tags` maps
tag patterns per remote to the member directories a matching tag releases
(`"."` for the root package, `"*"` for all); with a mapping, tags matching
no pattern release nothing:

```yaml
tags:
  "git@github.com:acme/mono.git":
    "core@*": [packages/core]
    "root@*": ["."]
    "v*": ["*"]
```

A release is stored once and never regenerated. If a later tag offers the
same name and version with other content, the first sdist keeps being served
and the status page reports the conflict as "changed without a version bump"
with the tags involved. An sdist whose writing was interrupted is rebuilt
only if the rebuild has the recorded SHA256 (`export-subst` placeholders
such as `$Format:%D$` can change it); otherwise it is reported and the file
stays missing. Releases whose package directory holds Git LFS files,
submodules or paths `git fsck` rejects (such as `..`), whose `readme` or
`license` file is missing, a symlink, larger than 1MiB or outside the
package directory, whose `pyproject.toml` doesn't parse or names an invalid
extra, whose name and version make a filename longer than 148 bytes, or
whose directory starts with `-` or holds a newline or carriage return, are
refused and reported. The earliest tag of a version decides: if it is
refused, so is the version, and a later tag doesn't stand in. A tag whose
tree has more than 100,000 entries, a path over 4KiB or a listing over
64MiB, or whose workspace has more than 1,000 members, is refused as a
whole; as no versions can be read from it, it doesn't block later tags.
Until every remote has been indexed since tspackages started and every tag
read, no new release is built (one may still be declared there), and a name
without a stored release answers `502` instead of moving on to the next
source. Files generated at build time but not committed aren't in the sdist,
and setuptools includes non-Python package data only if `MANIFEST.in` or
`package-data` lists it. Publish such packages through a `storage` source.

## Client setup

### Composer

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
that an earlier source also claims (the earlier source would shadow it on
reads).

### Python clients

Point every client at the one index; tspackages already passes public names
through to `pypi.org`. Don't add tspackages with `--extra-index-url` or as an
extra uv index next to PyPI: mixing indexes is the classic
dependency-confusion setup.

```ini
# pip.conf
[global]
index-url = https://registry.<tailnet>.ts.net/pypi/simple/
```

```toml
# pyproject.toml or uv.toml
[[tool.uv.index]]   # in uv.toml: [[index]]
name = "registry"
url = "https://registry.<tailnet>.ts.net/pypi/simple/"
default = true
```

Upload to a `storage` source with dummy credentials (tspackages ignores
them; the tailnet identity decides):

```sh
twine upload --repository-url https://registry.<tailnet>.ts.net/pypi/legacy/ \
  -u tailnet -p tailnet dist/*
uv publish --publish-url https://registry.<tailnet>.ts.net/pypi/legacy/ \
  --username tailnet --password tailnet
```

The name and version in the form, the filename and the metadata inside the
file must agree. Filenames longer than 148 bytes are rejected, and so are
wheel tags with characters other than letters, digits, `_` and `.`. An existing filename is rejected with `400 File already
exists`, even with identical bytes (`twine upload --skip-existing` copes), and
so is a second sdist, or a second wheel with the same tags, for a version
already published under another spelling.

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

A rule is `<ecosystem>:<pattern>` or `*`, for example
`pypi:acme-*`. Patterns use the ecosystem's claim grammar,
case-insensitively; a malformed rule grants nothing and is logged
when it leaves a request denied. `read` covers metadata and
downloads, `write` covers publishing. Capabilities from several grants are
unioned. The capability name is configurable (`tailscale.capability`).

## Development

```sh
make check         # golangci-lint, actionlint, zizmor, Vale, gofmt, vet, race tests
make integration   # end-to-end with real Composer, pip, uv and twine
make tailnet       # real tsnet nodes against an in-process control server
make vuln          # govulncheck, failing on reachable findings
```

S3 tests run when `TSP_TEST_S3_ENDPOINT` points at a MinIO. See
[CONTRIBUTING.md](CONTRIBUTING.md) before you send a change, and
[SECURITY.md](SECURITY.md) to report a vulnerability.

## License

Licensed under the [Apache License 2.0](LICENSE). tspackages isn't affiliated
with or endorsed by Tailscale Inc.

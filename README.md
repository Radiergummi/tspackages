# tspackages

A package registry that exists only on your Tailscale tailnet. One endpoint per
ecosystem speaks the ecosystem's native protocol; each endpoint is assembled
from sources (another registry, its own storage, or a git remote). Every
request is authorized by Tailscale identity, so clients hold no registry
credentials.

Composer, PyPI, Go, npm and Maven ship today. OCI follows. Read
[docs/security.md](docs/security.md) before you deploy, and
[docs/operations.md](docs/operations.md) for backups, upgrades and monitoring.

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
reported. `max_decompressed_bytes` applies to upload inspection. Each npm
`storage` source keeps at most 256MiB of rendered packuments in memory, and
each Maven `storage` source at most 32MiB of generated metadata; the least
recently read are rendered again when needed.

## PyPI sources

PyPI has the same three source types, a fourth that serves GitHub release
assets, and the same resolution rules. Names
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
| `github` | `url`, `app_id`, `installation_id`, `private_key`, `poll_interval`, `claims`, `fetch_hosts` (GitHub Enterprise Server only) | Serves the wheels and sdists attached to published GitHub releases, through a GitHub App. Nothing is hosted by tspackages. |

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
tree has more than 100,000 entries, a path over 4KiB or 256 levels or a
listing over 64MiB, or whose workspace has more than 1,000 members, is
refused as a whole; as no versions can be read from it, it doesn't block
later tags. Until every remote has been indexed since tspackages started and
every tag read, no new release is built (one may still be declared there),
and a name without a stored release answers `502` instead of moving on to
the next source. Files generated at build time but not committed aren't in
the sdist, and setuptools includes non-Python package data only if
`MANIFEST.in` or `package-data` lists it. Publish such packages through a
`storage` source.

The `github` source lists the wheel and sdist assets of the published
releases in every repository its GitHub App installation can see, and serves
them through the same index as any other source. CI keeps doing what it
does (`gh release upload`); only tspackages holds GitHub access. `claims`
are required, with the rules of a `storage` source's claims, and they must
not overlap an earlier source's. Each asset is verified against the SHA256
GitHub reports for it before it is cached or completed. The first
repository seen publishing a name owns it, and assets of that name in other
repositories are skipped and reported. Whoever can create a release in the
owning repository publishes that project, so grant the App only
repositories that publish packages, and claim narrowly. Setup, GitHub
Enterprise Server and the operating procedures are in
[docs/operations.md](docs/operations.md#pypi-release-assets).

## Go sources

`/go/` speaks the `GOPROXY` protocol, with a checksum database proxy for
sum.golang.org at `/go/sumdb/sum.golang.org/`. Go has `git` and `registry`
sources; it has no publish command, so there is no `storage` source.

```yaml
ecosystems:
  go:
    sources:
      - name: acme
        type: git
        claims: ["github.com/acme", "github.com/acme/*"]
        modules:
          github.com/acme/sdk: https://github.com/acme/sdk.git
          github.com/acme/mono/tools: {remote: https://github.com/acme/mono.git, dir: tools}
        branches: [main]                 # default: the remote's default branch
        token: ${env:GIT_TOKEN}
      - name: public
        type: registry
        url: https://proxy.golang.org
        fetch_hosts: [proxy.golang.org, sum.golang.org]
```

| Type | Keys | Does |
|------|------|------|
| `git` | `modules`, `branches`, `ssh_key`, `known_hosts`, `token`, `poll_interval` | Tags become versions of the listed modules, built once into module zips and kept. Allowlisted branches and commits reachable from them answer with pseudo-versions. |
| `registry` | `url` (`https://` only), `fetch_hosts` (must contain `sum.golang.org`), `metadata_ttl` | Pass-through to `proxy.golang.org`. Each `.mod` and `.zip` is checked against sum.golang.org before it is cached. |

Module paths are case-sensitive, but claims and `go:` rules match the
lowercase path, so `github.com/Acme/x` can't slip past `github.com/acme/*`.
A claim is `*` or `/`-separated segments of `[a-z0-9._~-]` and `*`. A `*`
inside a segment matches within that segment; a last segment of exactly `*`
matches one or more segments. A claim covers every major version of its
module (`github.com/acme/sdk` matches `github.com/acme/sdk/v2`), but
`github.com/acme/*` doesn't match `github.com/acme`: claim both with
`["github.com/acme", "github.com/acme/*"]`.

`modules` maps each module path, without a `/vN` suffix, to its remote, or
to `{remote, dir}` for a module in a subdirectory of the repository. An entry
serves its path and every `<path>/vN`; one remote may carry several modules.
Every key must match one of the source's claims. A `git` source's claims
become the clients' `GONOSUMDB`, so a claim that would cover public modules
fails validation: `*`, a wildcard in the host, and under `github.com`,
`gitlab.com` or `bitbucket.org` the bare host or a wildcard in the owner
segment. A claim of a whole host (`go.acme.dev/*`) is allowed with a warning
at startup. A `registry` source may not come before a `git` source whose
claims overlap its own. A path any `git` source claims is a miss on every
`registry` source, so a claimed `registry` after a `git` source never sends
it to its upstream or to sum.golang.org.

A tag is a version when it is a canonical semantic version (`v1.2.3`, not `v1.2` or
`1.2.3`), prefixed with the module's `dir` (`tools/v1.2.3`), and its major
version fits the path. For `<path>/v2`, the tagged commit holds a `go.mod`
declaring the `/v2` path either in the module's directory or in its `v2/`
subdirectory. A tag whose commit has no `go.mod` declaring exactly the
requested path is skipped and listed on the status page; there are no
`+incompatible` versions. A version's zip has the `h1:` hash that
`go mod download` computes from the repository, is built once and kept,
and a moved tag keeps serving it.

`@<branch>` (a branch the `branches` patterns allow, such as `@main`),
`@latest` for a module without tags, and `@<sha>` (7 to 64 hex digits,
reachable from an allowed branch or a stored tag) answer with the
pseudo-version the go command computes. Branch names containing `/`,
non-semver tag names and `HEAD` can't be queried; they answer `404`.
Refused modules and the size limits are in
[docs/operations.md](docs/operations.md#go).

## npm sources

`/npm/` speaks the npm registry protocol for npm and pnpm. npm has
`storage` and `registry` sources; there is no `git` source.

```yaml
ecosystems:
  npm:
    sources:
      - {name: hosted, type: storage, store: main, claims: ["@acme/*"]}
      - name: npmjs
        type: registry
        url: https://registry.npmjs.org/
        fetch_hosts: [registry.npmjs.org]
```

| Type | Keys | Does |
|------|------|------|
| `storage` | `store`, `claims` | Hosts packages published with `npm publish` or `pnpm publish`, and their dist-tags. |
| `registry` | `url` (`https://`, ending in `/`), `fetch_hosts`, `credentials`, `download_credentials`, `metadata_ttl` | Pass-through to `registry.npmjs.org`. Tarballs are checked against the declared `integrity` before they are cached. |

A claim is `*`, `@<scope>/<name>` or an unscoped `<name>`, with `[a-z0-9._-]`
and `*` in each part; a `*` matches within one part, so `acme*` doesn't
match `@acme/x`. Names are matched in lowercase. Prefer scoped names for
private packages. Names and versions are at most 156 bytes, and storage
accepts only strict semantic versions and lowercase names.

A version's metadata comes from the `package.json` inside its tarball, not
from the publish request. Publishing the same bytes again succeeds; other
bytes for an existing version are `409`. `latest` moves only to a higher
version on publish, and a package's first version is always `latest`.
Unpublish and deprecate answer `405`, and `npm audit` gets `404` (see
[docs/operations.md](docs/operations.md#npm-audit)).

## Maven sources

`/maven/` speaks the Maven 2 repository layout for Maven 3 and Gradle.
Maven has `storage` and `registry` sources; there is no `git` source.

```yaml
ecosystems:
  maven:
    sources:
      - {name: hosted, type: storage, store: main, claims: ["com.acme", "com.acme.*"]}
      - name: central
        type: registry
        url: https://repo.maven.apache.org/maven2/
        fetch_hosts: [repo.maven.apache.org]
```

| Type | Keys | Does |
|------|------|------|
| `storage` | `store`, `claims` | Hosts artifacts deployed with `mvn deploy` or Gradle's `maven-publish`, and generates their `maven-metadata.xml`. |
| `registry` | `url` (`https://`, ending in `/`), `fetch_hosts`, `credentials`, `download_credentials`, `metadata_ttl` | Pass-through to Maven Central or another Maven repository. Files are checked against the upstream's `.sha1` before they are cached. A release file's `.sha1` is fetched once; a SNAPSHOT file's and `maven-metadata.xml` again after `metadata_ttl`. |

A claim is `*`, `<group>` or `<group>:<artifact>`. The group is dotted
segments of `[a-z0-9_-]` whose last segment may be `*`, matching one or
more trailing segments, so `com.acme.*` doesn't match `com.acme`; claim
both. The artifact is `[a-z0-9._-]` with `*` wildcards. Claims match the
lowercased `groupId:artifactId`; coordinates are stored in their exact
case. Other public repositories (Google's, a company Nexus) are claimed
`registry` sources, since only one source may be unclaimed.

A release file is written once: the same bytes again succeed, other bytes
are `409`. A release version is listed in `maven-metadata.xml` once its POM
is stored. Timestamped SNAPSHOT files are written once too; other SNAPSHOT
files may be overwritten. SNAPSHOT files are kept without limit.
tspackages generates `.sha1`, `.md5`, `.sha256` and `.sha512` for every
file and checks the ones clients upload. Deleting answers `405`. See
[docs/operations.md](docs/operations.md#maven) for deploys, SNAPSHOT
versions and Gradle plugins.

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

### Go

```sh
go env -w GOPROXY=https://registry.<tailnet>.ts.net/go
go env -w GONOSUMDB=github.com/acme      # the status page prints the value
go env -u GOPRIVATE GONOPROXY
```

- Use tspackages as the only `GOPROXY` entry, without `,direct` or `|`. A
  `404` for a private module would fall through to VCS after `,direct`, and
  after `|` every error would.
- `GONOSUMDB` lists the `git` sources' claims and module paths; copy the
  value from the status page. Without it, the go command's checksum lookup
  for a private module answers `404` with `is private: add it to GONOSUMDB`,
  and the download fails. Private paths never reach sum.golang.org.
- Unset `GOPRIVATE`: it is the default for `GONOPROXY` and `GONOSUMDB`, and
  would send private modules past the proxy straight to VCS.
- Leave `GOSUMDB` at its default. The go command finds the checksum
  database at `/go/sumdb/sum.golang.org/` through `GOPROXY`, so public
  modules are verified as usual, also by `go mod verify`.

### npm and pnpm

In the project's `.npmrc` (or `~/.npmrc`):

```ini
registry=https://registry.<tailnet>.ts.net/npm/
//registry.<tailnet>.ts.net/npm/:_authToken=tailscale
```

The token is a placeholder: npm won't publish without one, and tspackages
ignores it. Don't add `@scope:registry=` lines that point elsewhere.
Lockfiles written against registry.npmjs.org install unchanged. Publish
with `npm publish` or `pnpm publish`, with `publishConfig.registry` set in
`package.json` (see [docs/operations.md](docs/operations.md#publishing-from-ci)).

### Maven and Gradle

tspackages must be the only repository: both clients try the next
repository after a `403`. In `~/.m2/settings.xml`, mirror everything to it:

```xml
<mirrors>
  <mirror>
    <id>tspackages</id>
    <mirrorOf>*</mirrorOf>
    <url>https://registry.<tailnet>.ts.net/maven/</url>
  </mirror>
</mirrors>
```

In Gradle, list it as the only repository:

```kotlin
repositories {
    maven { url = uri("https://registry.<tailnet>.ts.net/maven/") }
}
```

Neither needs a `<server>` entry or a `credentials` block, for reading or
deploying. The status page shows the full snippets, including SNAPSHOT
consumers, `distributionManagement` and Gradle's `publishing`; see also
[docs/operations.md](docs/operations.md#maven).

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
make maven-seed    # once: the plugins the mvn tests need, from Maven Central
make integration   # end-to-end with real Composer, pip, uv, twine, go, npm, pnpm, mvn and Gradle
make tailnet       # real tsnet nodes against an in-process control server
make vuln          # govulncheck, failing on reachable findings
```

S3 tests run when `TSP_TEST_S3_ENDPOINT` points at a MinIO. See
[CONTRIBUTING.md](CONTRIBUTING.md) before you send a change, and
[SECURITY.md](SECURITY.md) to report a vulnerability.

## License

Licensed under the [Apache License 2.0](LICENSE). tspackages isn't affiliated
with or endorsed by Tailscale Inc.

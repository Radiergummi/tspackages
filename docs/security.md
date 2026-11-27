# Security notes

tspackages authorizes by Tailscale identity and is only as strict as your
tailnet. Read this before you deploy.

## Threat model

- **Who is trusted.** Tailnet identities, for what the grants give them, and
  anyone who can push to a configured git remote, to publish code: they could
  publish anything anyway.
- **What holds regardless.** No push, accidental or malicious, may change
  the bytes of a published release, make served metadata disagree with the
  artifact it describes, or crash the process, run it out of memory or make
  it crash on every start. A push may make an index pass slow, within
  minutes, not hours.
- **How it holds.** Content that can't be served is refused, reported on the
  status page and remembered for the commit, never retried as if it were an
  outage. The caps behind this for `git` sources: trees of at most 100,000
  entries, paths of at most 4KiB and 256 levels and a tree listing of at
  most 64MiB, files read whole of at most 1MiB, a `pyproject.toml` of at
  most 64KiB whose table headers, `[`/`{` nesting and dotted keys nest at
  most 64 levels deep in all and whose key paths, which the TOML decoder
  stores in full for every key and dotted prefix, are at most 1KiB each and
  1MiB in all, at most 1,000 workspace members and globs (globs and member
  directories of at most 4KiB), no nested members, no path listed twice or
  as both file and directory, and git archives held in memory up to
  `max_artifact_bytes` (512MiB at most). Finding a version's earliest tag
  takes at most two ancestry checks per commit.

## Identity

- **Any process on a node has that node's rights.** A tagged CI node's
  capabilities are available to everything that runs on it, including a
  malicious `postinstall` script. This is why the examples give humans read
  access only and give each publishing repo its own CI tag with write on its
  own packages.
- **Subnet routers and shared proxy nodes carry their own identity.** Traffic
  through them is attributed to the router or proxy, so never grant such nodes
  registry capabilities. Requests whose `WhoIs` fails are denied.
- Being on the tailnet isn't enough: no matching capability means `403`.
- Client `Authorization` headers are stripped and never forwarded.
- `/`, `/readyz` and `/metrics` need at least one capability rule; only
  `/healthz` answers any tailnet identity. Metrics carry source names, never
  remote URLs, and the status page shows a git remote only to callers allowed
  to read the package that remote declares.
- tspackages must see the original connection, so it can't sit behind
  Tailscale Serve or a reverse proxy.

## Secrets and state

- **The tsnet state dir is a secret.** It holds the node and TLS keys;
  whoever has it can impersonate the registry. It is mode 0700 and separate
  from the cache, the state store and `storage.work_dir` (config validation
  enforces the separation). Enable Tailnet Lock.
- tsnet uploads its logs to Tailscale's log service by default. Set
  `TS_NO_LOGS_NO_SUPPORT=1` to disable that.
- `storage.work_dir` holds git mirrors and SSH key material, mode 0700, and is
  cleared of key files and of mirrors no longer configured at every start.
  Run **one instance per `work_dir` and per state dir**; there is no high
  availability. A second instance on the same `work_dir` waits up to 60 seconds
  for its lock (`<work_dir>/.lock`) and then exits; two instances sharing only
  a state dir aren't detected and fight over indexes.
- Tailscale credentials (`TS_AUTHKEY`, `TS_AUTH_KEY`, `TS_CLIENT_SECRET`,
  `TS_ID_TOKEN`) and every variable the config references via `${env:}` are
  removed from the environment once read, so git and ssh never inherit them
  (`PATH`, `HOME`, `USER`, `TMPDIR`, `LANG` and `LC_*` are kept).
- `fs` stores are owner-only: directories are created mode 0700 and files
  0600, since they hold private packages and audit records. Files written by
  earlier versions keep their modes; tighten them with
  `chmod -R go-rwx <path>`.
- Turn on **S3 versioning or Object Lock on the state bucket**. The state
  store holds tag pins, git-built archives and the audit records (one JSON
  record per publish: caller, node, time, package, version, digest). Without
  versioning those records can be silently rewritten.
- `download_credentials` must be **public-only tokens**. Upstream metadata
  decides which URLs are fetched with them, so give them no scope beyond what
  anonymous access allows (they exist to lift rate limits). Credentials are
  attached only to requests to their exact host and never after a redirect.

## Git sources

- Remotes must be **canonical URLs**: redirects aren't followed
  (`http.followRedirects=false`), so a moved repository must be updated in the
  config.
- Remotes must not embed credentials; use `token` (HTTPS, passed through
  `GIT_CONFIG_*`, never argv) or `ssh_key`. SSH remotes require `known_hosts`
  and use `StrictHostKeyChecking=yes`; the system's known hosts file is
  ignored, so only the configured host keys count. Prompts, `file`, `ext` and
  other transports are disabled.
- **Tag pinning is trust on first use.** The first time a tag is served, its
  commit is recorded in the state store and the tag resolves to that commit
  forever, even if it is force-pushed. A move is logged at warn and listed on
  the status page. If the first push of a tag was malicious, the pin keeps it.
  To accept a moved tag, delete its pin; a deleted pin is **re-pinned on next
  sight** to whatever the tag points at then.
- Archives built from git leave out symlinks, which uploads may not contain
  either; each one left out is logged at warn. Archives built earlier are kept
  as they are.
- Versions that were served stay served (and byte-identical, so Composer's
  `shasum` stays valid) even if the tag is deleted upstream. A remote that is
  unreachable at startup is indexed from its local mirror, or, without one (or
  with a broken `composer.json` on the default branch), its pinned tags are
  served from the stored archives; it shows as failing on the status page.
- Only branches matching the source's `branches` allowlist (default: the
  default branch) become `dev-*` versions; any branch push would otherwise
  publish to every reader. Archives built for dev branch heads accumulate in
  the state store: there is no garbage collection in v1.

## Resolution and artifacts

- Claimed names are resolved only from the sources that claim them, in order,
  with no fall-through. A source error is a `502`/`504`, never a lookup in
  another source. Claims and authorization rules support only `*` wildcards and
  match the lowercase name.
- Artifact URLs returned to clients point at tspackages and are opaque routes,
  never an encoded upstream URL. Upstream fetches go only to the source's
  `fetch_hosts` and never to private, loopback, link-local or CGNAT addresses.
- Upstream artifacts stream to clients while they download and are checked
  against the upstream-declared hash before they are cached. On a mismatch
  nothing is cached and the client's transfer is broken off, so it never
  looks like a complete file: the last byte is held back until the hash
  matched, for cached copies too. Packagist declares none for most
  GitHub archives, so the first SHA256 seen for a version and reference is
  kept in the provenance records. A later fetch with other bytes is still
  served, but logged at warn and listed on the status page.
- Composer `source` blocks are stripped from served metadata, so
  `--prefer-source` can't reach upstream VCS locations. Only dist archives are
  served. Dist `mirrors`, `transport-options` and `notification-url` are
  stripped too, so clients download and report installs only through
  tspackages.
- Uploads are inspected in memory: names in the URL and the zip's
  `composer.json` must agree, entries with `..`, absolute paths or symlinks are
  rejected, and size, decompressed size and entry count are capped. Hosted
  artifacts are immutable.

## PyPI

- Names are normalised (PEP 503) before claim matching, authorization and
  storage, so `Acme_Utils` can't slip past an `acme-*` claim. Claims and
  `pypi:` rules accept only `[a-z0-9-]` and `*`, with no leading, trailing or
  doubled `-` (no normalised name has one); anything else is a config
  error, or a rule that grants nothing. `acme-*` doesn't cover `acme`.
- Configure clients with tspackages as their **only** index. An extra index
  next to it (`--extra-index-url`, a second uv index) lets pip and uv pick a
  public package that shadows a private name.
- A published release never changes bytes: versions are compared by PEP 440
  equality (`1.0` is `1.0.0`), an upload of an existing filename, a second
  sdist or a second wheel with the same tags is rejected, and a git release
  that changed without a version bump keeps its first sdist. This keeps
  hash-pinned lock files (`uv.lock`, `pip --require-hashes`) valid.
- Uploads are content-bound: the form's name and version, the filename and
  the metadata inside the wheel or sdist must agree. Sdists get the same
  path, symlink, size and entry-count checks as zips.
- **Back up the state store.** It holds the sdists generated from git.
  Regenerating them after a loss reproduces the same bytes only while the
  generator's format is unchanged and the same tagged commit wins, so lock
  files pinned to the old hashes may break.
- The git source runs no repository code: it reads `pyproject.toml` and
  builds the sdist itself. Git LFS files, submodules and `readme` or
  `license` files outside the package directory make a release refused, not
  served broken. When several tags offer a release that isn't stored yet,
  the one whose commit is an ancestor of the others wins (commit times are
  author-controlled and ignored); on divergent histories the release is
  withheld until an operator removes the extra tags or maps them.
- Uploaded PEP 740 attestations are stored and recorded in provenance but
  not served: nothing verifies them yet, and unverified publisher claims
  could mislead the tools that read them. Provenance from the `registry`
  source is passed through.
- Upstream file entries without a SHA256 are dropped from served pages, so
  nothing upstream is served unverified.

## Go

- Module paths are case-sensitive, but claims and `go:` rules match the
  lowercase path, so `github.com/Acme/x` can't slip past a
  `github.com/acme/*` claim. Claims and rules accept `*` or `/`-separated
  segments of `[a-z0-9._~-]` and `*`; anything else is a config error, or a
  rule that grants nothing. A claim covers every major version of its
  module, and `github.com/acme/*` doesn't cover `github.com/acme`.
- A `git` source's claims become every client's `GONOSUMDB`, so claims that
  would turn off checksum verification for public modules are config
  errors: `*`, a wildcard in the host, and under `github.com`, `gitlab.com`
  or `bitbucket.org` the bare host or a wildcard in the owner segment. Every
  `modules` key must match a claim. A whole-host claim (`go.acme.dev/*`)
  is allowed with a warning at startup.
- **Tag versions are durable.** A tag version's zip is built once, stored
  in the state store with its `h1:` hashes and served from there for good,
  even after the tag moves or the remote is gone. A zip missing from the
  store is rebuilt from the recorded commit and kept only if its `h1:`
  equals the record's. The zip has the `h1:` that `go mod download` computes
  from the repository, so it matches `go.sum` files written without
  tspackages.
- Pseudo-versions are built into the cache on demand, and the first build
  records the commit and `h1:` in the state store; every rebuild must match
  the record. This is the one exception to "served git versions stay
  served": a pseudo-version whose commit is gone from the mirror becomes
  unavailable (`502`), even with its zip still cached.
- Only allowlisted branches and commits reachable from them or from a
  stored tag can be queried; any other commit answers `404`, even if it is
  in the mirror.
- Registry `.mod` and `.zip` files are verified against sum.golang.org
  before they are cached, and the zip's last byte is held back until its
  `h1:` matched. A cached zip is checked against its recorded SHA256 while
  it streams. The latest verified tree head is kept in the state store, so
  a rolled-back or forked database is detected across restarts, and from
  then on registry fetches fail closed until restart.
- **Private paths never reach sum.golang.org.** A checksum lookup for a path
  that any `git` source claims answers `404` with "add it to GONOSUMDB"
  without leaving the node; any other lookup is forwarded only for a path that
  resolves to a `registry` source. A `registry` source answers a path any
  `git` source claims with `404` before any request, so a git miss that falls
  through to a later claiming `registry` source reaches neither its upstream
  nor sum.golang.org.
- The git source runs no repository code: it reads `go.mod` and runs
  `git archive` with the module zip rules of the go command, with user and
  system git attributes turned off. Module roots over 100,000 files,
  archives over 500MiB, and `go.mod` or `LICENSE` files over 16MiB are
  refused and reported. Builds run in a queue of 2 workers with a 10-minute
  limit each, so a push can't block other modules.

## npm

- Names are lowercased before claim matching, authorization and routing,
  so `@Acme/x` can't slip past an `@acme/*` claim. Claims and `npm:` rules
  accept `*`, `@<scope>/<name>` or an unscoped `<name>` of `[a-z0-9._-]`
  and `*`; anything else is a config error, or a rule that grants nothing.
  A `*` inside a pattern matches within one part, so `acme*` doesn't cover
  `@acme/x`. Prefer scoped names for private packages: an unscoped private
  name is one typo away from a public one.
- Configure clients with tspackages as their only `registry=` and no
  `@scope:registry=` lines that point elsewhere. A scope sent to another
  registry is outside tspackages' claims.
- **Private names never reach registry.npmjs.org.** A claimed name is looked
  up only on its claiming sources. `npm audit` would send every dependency
  name, private ones included, so `/-/npm/v1/security/advisories/bulk`
  answers `404` instead of being forwarded.
- **Served metadata comes from the tarball.** A storage version's manifest
  is built from the `package/package.json` inside the published tarball,
  through an allowlist of fields; of the publish body, only `gitHead`,
  `_nodeVersion` and `_npmVersion` are kept. A publish whose URL, body and
  tarball names or versions disagree, or whose declared `integrity` or
  `shasum` doesn't match the tarball, is rejected.
- A published version never changes bytes. The same bytes published again
  succeed; other bytes for an existing version, or a version that differs
  from an existing one only in build metadata (`1.0.0+a`, `1.0.0+b`), are
  `409`. There is no unpublish and no deprecate (`405`).
- **No response is a `401`.** npm turns a `401` into a one-time password or
  web login prompt. A caller without a matching rule gets `403` with
  `forbidden: no npm:<name> read rule` (or `write`), and an upstream `401`
  becomes a `502`. The `_authToken` clients send is stripped and ignored.
- Upstream tarballs are checked against the version's declared `integrity`
  before they are cached, by SHA-512 when it declares one and otherwise by
  SHA-1 (an `integrity` with only `sha1`, or a hex `shasum`). Versions with neither
  are dropped from served packuments. Old versions that declare only SHA-1
  are therefore verified by SHA-1 alone, which trusts the upstream not to
  serve a crafted collision. A tarball whose SHA256 differs from the first
  one recorded for its version is served, logged at warn and listed on the
  status page.
- Tarball URLs from upstream must be on the source's `fetch_hosts`, or the
  version is dropped. Served `dist.tarball` URLs point at tspackages and
  carry no source.
- No package code runs on the server. Lifecycle scripts and
  `bundleDependencies` are stored as published. Publish-time provenance
  bundles (`--provenance`) are stored and recorded, not served; a
  `registry` source passes `dist.attestations` and the signing keys through.

Upstream packuments and publish bodies aren't held whole in memory: they
are parsed as streams, one version object at a time. A storage source's
packument is rendered in memory, full and abbreviated, once per change and
shared by concurrent reads; past 64MiB either way, reads of the package
fail and the status page names it. The caps:

| Parser | Input | Caps |
|---|---|---|
| Names and paths | request paths | names of at most 156 bytes (one escaped storage key segment), fixed segment counts |
| Versions | publish, request paths | strict SemVer 2.0.0, 156 bytes |
| dist-tags | publish body, `npm dist-tag` | 64 bytes of `[a-z0-9._-]`, not a version or range; 100 tags per package |
| Upstream packument | registry source | 256MiB, 200,000 versions, 4MiB per version, nesting 64, keys of 1KiB |
| Upstream `dist-tags`, `time` | registry source | `dist-tags` 2MiB and 1,000 entries, `time` 32MiB; over either, the packument fails |
| Storage packument | storage source | 64MiB rendered, full and abbreviated, 4MiB per version |
| Publish body | client | `max_upload_bytes` × 4/3 + 2MiB, one version, one tarball of at most `max_upload_bytes`, a provenance bundle of at most 1MiB |
| `package.json` | published tarball | 1MiB, nesting 64 |
| Tarball | publish | the `archive` limits of every upload |
| `integrity` | upstream, client | 1KiB, `sha512` and `sha1` only |

## Maven

- Coordinates are case-sensitive, but claims and `maven:` rules match the
  lowercased `groupId:artifactId`, so `com.Acme:lib` can't slip past a
  `com.acme` claim. Claims and rules accept `*`, `<group>` or
  `<group>:<artifact>`: the group dotted segments of `[a-z0-9_-]` whose
  last segment may be `*`, the artifact `[a-z0-9._-]` and `*`; anything
  else is a config error, or a rule that grants nothing. `com.acme.*`
  doesn't cover `com.acme`. A storage source refuses a deploy whose
  coordinates differ from an existing artifact's only in case (`409`).
- Configure clients with tspackages as their only repository (Maven
  `<mirrorOf>*</mirrorOf>`, a single Gradle `maven { }` repository, or
  `exclusiveContent` for private groups). Both clients try the next
  repository after a `403`, so a second repository with the same
  coordinates would serve a denied caller the public artifact.
- **Private coordinates never reach an upstream.** A claimed artifact is
  looked up only on its claiming sources, through files, POMs, checksums
  and metadata alike. A `maven-metadata.xml` path names either an
  artifact (`com/acme/lib`: `com.acme:lib`) or a group (`com.acme.lib`);
  it counts as claimed when either reading matches a claim, or when it
  sits in a version directory of a claimed artifact
  (`com/acme/lib/1.0/maven-metadata.xml` under a `com.acme:lib` claim).
  Group-level metadata lists a group's plugins, so reading it needs a rule
  for the whole group (`maven:com.acme.lib`, `maven:com.acme.lib:*`,
  `maven:com.acme.*`); when both readings are claimed, the group level's
  sources are asked only for a caller that may read the group too. An
  unclaimed path is granted by a rule for either reading. A one-segment
  group's `acme/maven-metadata.xml` has only the group reading. Upstream
  URLs are built only from a parsed and re-serialized path.
- **Checksums describe the bytes served.** tspackages generates `.sha1`,
  `.md5`, `.sha256`, `.sha512` and the `X-Checksum-Sha1`, `X-Checksum-Md5`
  and `ETag` headers from the bytes it stores or verified; uploaded
  checksums are compared with the file (`400` on a mismatch) and
  discarded. Uploaded `maven-metadata.xml` is checked for the deployed
  coordinates and discarded; tspackages serves metadata it generates from
  stored POMs. Checksums of uploaded metadata are checked for form only,
  since the metadata they describe is gone by the time they arrive.
- A release file never changes bytes. The same bytes deployed again
  succeed; other bytes are `409`. Timestamped SNAPSHOT files
  (`lib-1.0-20261123.101010-3.jar`) are served immutable, so they are
  written once the same way. Other SNAPSHOT files may be overwritten, and
  each overwrite is audited with the replaced SHA256. There is no delete
  (`405`).
- **Deployed POMs bind their coordinates.** A POM's `groupId`,
  `artifactId` and `version` (or its parent's) must equal the path's, and
  a `${…}` in them is refused. Elements with a namespace prefix or a
  namespace other than Maven's are refused, since Maven's own reader
  ignores them and could see other coordinates than tspackages. A
  `.module` file must name the same coordinates, and its files must be in
  the same version directory. Everything else (jars, sources, signatures)
  is stored as uploaded, without inspection.
- **No response is a `401`.** A caller without a matching rule gets `403`
  with `forbidden: no maven:<groupId>:<artifactId> read rule` (or `write`),
  and an upstream `401` becomes a `502`. Clients need no `<server>` entry or
  `credentials`, and any `Authorization` header is stripped. A deploy
  needs a read rule as well as a write rule, because both clients read
  `maven-metadata.xml` while they deploy; write still doesn't imply read.
- Upstream files are verified against the upstream's `<file>.sha1` by the
  relay before they are cached: by SHA-1 alone, which trusts the upstream
  not to serve a crafted collision. A file whose SHA256 differs from the
  first one recorded for it is served, logged at warn and listed on the
  status page. Without an upstream `.sha1`, a missing file is `404`, any
  other file `502`, except signatures (`.asc`, `.sigstore`,
  `.sigstore.json`), for which Maven Central often publishes no checksum,
  are streamed uncached and unverified, up to 64KiB, without
  checksum headers. A signature is checked by the client against its
  signer's key; tspackages can't vouch for one.
- No XML document can expand, recurse or load anything. POMs and
  `maven-metadata.xml`, uploaded or upstream, are refused with a DTD, an
  entity declaration or a processing instruction other than the XML
  declaration, before they are decoded. Upstream metadata is passed
  through byte for byte once it has been checked.
- No artifact code runs on the server, and no plugin or build either.

Uploads are spooled to disk before inspection, and XML and JSON are read
whole only up to their caps. The caps:

| Parser | Input | Caps |
|---|---|---|
| Paths | request paths | segments and coordinate parts of at most 156 bytes, a `groupId` of at most 156, classifiers 64, extensions 32 |
| Storage keys | deploys to a storage source | file names of at most 153 bytes, `groupId:artifactId` of at most 156 (each is one escaped key segment) |
| XML (POM, `maven-metadata.xml`) | deploys, upstream metadata | 1MiB uploaded, 4MiB upstream; depth 32, 10,000 elements, no DTD, entities or processing instructions |
| `.module` JSON | deploys | 1MiB, nesting 32 |
| Checksum files | deploys, upstream `.sha1` | 1KiB, first line |
| Signatures | deploys, upstream without `.sha1` | 64KiB |
| Other files | deploys, upstream | `max_upload_bytes`, `max_artifact_bytes` |
| Version ordering | generated metadata | versions of at most 156 bytes |

# Security notes

tspackages authorizes by Tailscale identity and is only as strict as your
tailnet. Read this before you deploy.

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
- Upstream artifacts are checked against the upstream-declared hash before
  they are cached; a mismatch is a `502`. Packagist declares none for most
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

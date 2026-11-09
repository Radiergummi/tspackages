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
- Being on the tailnet is not enough: no matching capability means `403`.
- Client `Authorization` headers are stripped and never forwarded.
- tspackages must see the original connection, so it cannot sit behind
  Tailscale Serve or a reverse proxy.

## Secrets and state

- **The tsnet state dir is a secret.** It holds the node and TLS keys;
  whoever has it can impersonate the registry. It is mode 0700 and separate
  from the cache, the state store and `storage.work_dir` (config validation
  enforces the separation). Enable Tailnet Lock.
- tsnet uploads its logs to Tailscale's log service by default. Set
  `TS_NO_LOGS_NO_SUPPORT=1` to disable that.
- `storage.work_dir` holds git mirrors and SSH key material, mode 0700, and is
  cleared of key files at every start. Run **one instance per work_dir and per
  state dir**; there is no high availability, and two instances overlapping
  beyond a brief restart will fight over mirrors and indexes.
- Turn on **S3 versioning or Object Lock on the state bucket**. The state
  store holds tag pins, git-built archives and the audit records (one JSON
  record per publish: caller, node, time, package, version, digest). Without
  versioning those records can be silently rewritten.
- `download_credentials` must be **public-only tokens**. Upstream metadata
  decides which URLs are fetched with them, so give them no scope beyond what
  anonymous access allows (they exist to lift rate limits). Credentials are
  attached only to requests to their exact host and never after a redirect.

## Git sources

- Remotes must be **canonical URLs**: redirects are not followed
  (`http.followRedirects=false`), so a moved repository must be updated in the
  config.
- Remotes must not embed credentials; use `token` (HTTPS, passed through
  `GIT_CONFIG_*`, never argv) or `ssh_key`. SSH remotes require `known_hosts`
  and use `StrictHostKeyChecking=yes`. Prompts, `file`, `ext` and other
  transports are disabled.
- **Tag pinning is trust on first use.** The first time a tag is served, its
  commit is recorded in the state store and the tag resolves to that commit
  forever, even if it is force-pushed. A move is logged at warn and listed on
  the status page. If the first push of a tag was malicious, the pin keeps it.
  To accept a moved tag, delete its pin; a deleted pin is **re-pinned on next
  sight** to whatever the tag points at then.
- Versions that were served stay served (and byte-identical, so Composer's
  `shasum` stays valid) even if the tag is deleted upstream.
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
  they are cached; a mismatch is a `502`.
- Composer `source` blocks are stripped from served metadata, so
  `--prefer-source` cannot reach upstream VCS locations. Only dist archives are
  served.
- Uploads are inspected in memory: names in the URL and the zip's
  `composer.json` must agree, entries with `..`, absolute paths or symlinks are
  rejected, and size, decompressed size and entry count are capped. Hosted
  artifacts are immutable.

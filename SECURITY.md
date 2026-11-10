# Security policy

tspackages decides who may read and publish packages from Tailscale grants,
and keeps private package names from resolving to public sources. Problems in
either boundary matter, and reports are welcome. For how to deploy it safely,
read [docs/security.md](docs/security.md).

## Reporting a vulnerability

Report vulnerabilities privately through [GitHub's private vulnerability reporting](https://github.com/Radiergummi/tspackages/security/advisories/new).
Please don't open a public issue, pull request or discussion for them.

A useful report says:

- what an attacker can do, and from where (any tailnet node, a node with a
  particular grant, an upstream registry or git host)
- the tspackages version (`tspackages -version`) and how it's configured
- the steps or a proof of concept that shows it

You'll get an answer within a week. Once the problem is confirmed, it's fixed
in a new release, and the advisory is published with credit to you unless
you'd rather not be named.

## Supported versions

Only the latest release gets security fixes.

## In scope

- Anything that lets a caller act beyond its grants: read or publish a package
  without the capability, or reach the status page or metrics without a rule.
- Dependency confusion: a claimed name resolving from a source that doesn't
  claim it, or from an upstream after a source error.
- Ways to make tspackages fetch from a host outside a source's `fetch_hosts`,
  or from a private, loopback, link-local or CGNAT address.
- Serving an upstream artifact that doesn't match its declared hash, or
  metadata that points clients somewhere other than tspackages.
- Escaping the git hardening (option or transport injection, hooks,
  credentials in argv or logs) or the upload inspection (path traversal,
  symlinks, archive bombs).
- A served git version changing its bytes, or a pinned tag silently moving.

## Out of scope

- Your tailnet policy. A grant that gives too much access is a configuration
  problem, not a tspackages vulnerability.
- Anything a process on a node with a capability can do with that capability;
  see [docs/security.md](docs/security.md).
- Denial of service by a caller who already holds a capability. Rate limits
  bound it; they don't prevent it.

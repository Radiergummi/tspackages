# Contributing to tspackages

Thanks for helping. Bug reports, fixes and improvements are all welcome. For a
larger change, open an issue first, to agree on the approach before you spend
time on it.

Report security problems privately, as described in [SECURITY.md](SECURITY.md),
not in an issue.

## Design

tspackages runs as one tsnet node and serves one endpoint per ecosystem in that
ecosystem's native protocol. Each endpoint is assembled from ordered sources,
and every request is authorized by Tailscale identity.
[docs/security.md](docs/security.md) lists the guarantees that follow from
that. A change must keep them, or update them in the same pull request:

- Tailscale is the only authentication. A caller without a matching capability
  gets `403`.
- A name a source claims is resolved only from the sources that claim it, in
  order. Only a definite miss moves on to the next source; any other error is
  a `502` or `504`.
- Upstream artifacts are verified against their declared hash before they're
  cached, and URLs returned to clients point at tspackages.
- Versions that were served stay served, byte for byte.

## Development

You need Go (the version in `go.mod`), git, and for the integration test
Composer 2.x. `make check` runs what CI runs, and needs
[golangci-lint](https://golangci-lint.run), [actionlint](https://github.com/rhysd/actionlint),
[zizmor](https://zizmor.sh) and [Vale](https://vale.sh):

```sh
make check         # lint, formatting, vet and the race-enabled tests
make integration   # end-to-end with real Composer
make tailnet       # real tsnet nodes against an in-process control server
make vuln          # govulncheck, failing on reachable findings (needs jq)
make fmt           # format the Go code
make cover         # cover.out and cover.html
make build         # ./tspackages, stamped with the version
```

The S3 driver tests run only with `TSP_TEST_S3_ENDPOINT` pointing at an
S3-compatible store, such as MinIO with its default credentials. CI builds a
pinned MinIO commit from source.

## Pull requests

- Add or update tests for what you change. Bug fixes come with a test that
  fails without the fix. Protocol behavior is tested against the real client
  where possible.
- Keep each pull request to one change, and match the style of the code
  around it. Comments state what the code does now, not its history.
- Write commit messages as a plain imperative sentence that says what the
  change does, for example `Refuse uploads that an earlier source shadows`.
  Commits are signed.
- Add a line under `Unreleased` in [CHANGELOG.md](CHANGELOG.md) for anything a
  user would notice.
- New dependencies need a good reason.
- GitHub Actions are pinned to a full commit SHA, with the version in a
  comment.

## License

By contributing, you agree that your contributions are licensed under the
[Apache License 2.0](LICENSE).

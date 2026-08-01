# Contributing to Cairn

Thanks for your interest. Cairn is early-stage; issues, discussion, and PRs are
welcome. This document covers how to build, test, and submit changes.

## Ground rules

- **Never commit secrets.** No keys, keytabs, certs, `.p12`, databases, or real
  `.mobileconfig` files. `gitleaks` runs in CI and is expected to stay green.
  Examples use `example.org`, never real hostnames.
- **MIT licensed.** By contributing you agree your contribution is under the
  [MIT license](LICENSE).
- Be excellent to each other — see [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## Building and testing

Pure Go, `CGO_ENABLED=0` (so it cross-compiles to FreeBSD without a C toolchain):

```sh
go build ./...
go test -race ./...
go vet ./...
CGO_ENABLED=0 GOOS=freebsd GOARCH=amd64 go build ./...   # release target must stay green
gofmt -l internal cmd                                     # must print nothing
```

The storage layer is verified against NanoMDM's own protocol test suite plus
Cairn's own tests. If you touch `internal/storage/sqlite`, run its tests and
keep the NanoMDM e2e suite passing.

## Architecture in one paragraph

A single binary. `cmd/cairn` is the CLI; `internal/server` mounts the HTTP
routes; `internal/mdmcore` embeds NanoMDM as a library (never a fork — we
implement its interfaces); `internal/storage/sqlite` is the pure-Go backend;
`internal/web` is the server-rendered console (html/template, no JS build).
NanoMDM/nano* dependencies are pinned and confined behind `internal/`.

## Submitting changes

- Branch, keep commits focused, and write a clear commit message that says what
  changed and why. Match the surrounding code's style; add tests for behavior.
- Comments state constraints the code can't show — not narration.
- Run the full check block above before opening a PR. CI runs tests + race +
  cross-compile matrix + gitleaks + govulncheck.
- Security-relevant changes (auth, enrollment, PKI, storage) get extra scrutiny;
  explain the threat model in the PR.

## Reporting security issues

Do **not** open a public issue for a vulnerability. See
[SECURITY.md](SECURITY.md) for the private reporting process.

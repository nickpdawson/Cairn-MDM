# Cairn

A single-binary, open-source Apple MDM server for homelabbers, small businesses,
non-profits, and families.

> A cairn is a small stack of stones that keeps travelers on the trail. One
> binary, one config file, one database — no container zoo required.

Cairn manages macOS and iOS/iPadOS devices: over-the-air enrollment, an embedded
(or external) SCEP certificate authority, configuration-profile delivery, and a
polished, Apple-HIG-inspired web console — all in a single Go binary that runs
natively on FreeBSD, Linux, and macOS, or in one container.

**Status: early development (v0, pre-alpha).** Not yet ready for production.
See [the design plan](docs/) for the roadmap.

## Why

Most self-hostable Apple MDMs are a stack of separately-deployed services
(an MDM server, a CA, a database, a reverse proxy, an admin app) wired together
by hand. Cairn embeds the MDM protocol server ([NanoMDM][nanomdm] via
[NanoHUB][nanohub]), an optional SCEP CA, and the admin UI into one process with
one config file and a SQLite database by default. The non-ABM path is
first-class: you do not need an Apple Business Manager account to use Cairn.

## Install

```sh
# One line: detect OS/arch, download the matching release, VERIFY its sha256, install.
curl -fsSL https://raw.githubusercontent.com/dzsec/cairn/main/packaging/install.sh | sh
```

Or grab a release tarball / `.deb` / `.rpm` from the releases page, or run the
container (`ghcr.io/dzsec/cairn`). Building from source: `go build ./cmd/cairn`
(pure Go, `CGO_ENABLED=0`).

## Quick start

```sh
# One command sets up config, the CA, and the admin account, and prints the
# enrollment URL. It never surfaces PKI decisions unless you opt into them.
cairn init --public-url https://mdm.example.org

# Then load an APNs push certificate (free via mdmcert.download) and serve:
cairn pushcert request -email you@example.org      # → decrypt → identity.apple.com → import
cairn serve
```

`packaging/cairn.example.toml` documents the full config surface. Health
endpoints: `GET /healthz` (liveness), `GET /readyz` (readiness), `GET /version`.

## Migrating from NanoMDM

`cairn import -from-mysql <dsn>` migrates an existing NanoMDM (MySQL) deployment
with **zero device re-enrollment** — it replays the stored check-in state through
Cairn's storage and verifies every enrollment is pushable and every certificate
association intact before declaring success. See
[docs/migrating-from-nanomdm.md](docs/migrating-from-nanomdm.md).

## Roadmap

- **v1.0** — redesigned OTA enrollment (one-time SCEP challenges, expiring
  links, QR, signed profiles), embedded + external CA, APNs cert wizard, device
  inventory, profile library, Kerberos SSO template.
- **v1.1** — Declarative Device Management (software-update enforcement, status
  subscriptions).
- **v1.2** — ABM/ADE automated enrollment (optional module).
- **v2.0** — account-driven enrollment, Platform SSO.

## License

[MIT](LICENSE). Cairn builds on the MicroMDM ecosystem
([NanoMDM][nanomdm], [NanoHUB][nanohub], and related projects); see `NOTICE` for
upstream attributions.

[nanomdm]: https://github.com/micromdm/nanomdm
[nanohub]: https://github.com/micromdm/nanohub

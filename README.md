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

## Quick start (development)

```sh
git clone https://github.com/dzsec/cairn && cd cairn
go build ./cmd/cairn
cp docs/examples/cairn.toml.example ./cairn.toml   # then edit public_url etc.
./cairn migrate -config ./cairn.toml               # create/upgrade the database
./cairn serve   -config ./cairn.toml               # run (proxy TLS mode for now)
```

Health checks: `GET /healthz` (liveness), `GET /readyz` (readiness), `GET /version`.

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

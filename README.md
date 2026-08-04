# Cairn-MDM

A single-binary, open-source Apple MDM server for homelabbers, small businesses,
non-profits, and families.

> A cairn is a small stack of stones that keeps travelers on the trail. One
> binary, one config file, one database — no container zoo required.

Cairn manages macOS and iOS/iPadOS devices: over-the-air enrollment, an embedded
(or external) SCEP certificate authority, configuration-profile delivery, and a
polished, Apple-HIG-inspired web console — all in a single Go binary that runs
natively on FreeBSD, Linux, and macOS, or in one container.

**Status: public beta (v0.x).** MIT-licensed and running its author's own fleet,
but pre-1.0 and at the operator's own risk — not production-ready for others yet
(`SECURITY.md` treats v0 as experimental with best-effort fixes only). The
config/API/schema may still change (migrations are provided), some features are
unfinished, and there is a **known pre-1.0 security gate in enrollment issuance
trust** — device certs are not yet authority-attested, so don't rely on them as a
network-access credential (EAP-TLS) until issuance is Cairn-controlled. See
`SECURITY.md`.

### Known limitations (beta)

- **Auth**: local + LDAP/AD + OIDC work; MFA and Kerberos/SPNEGO are not built.
- **Apple scope**: OTA enrollment, SCEP, and profile delivery are complete.
  Declarative Device Management (DDM) and ABM/ADE automated enrollment are on the
  roadmap, not yet implemented.
- **Console**: functional and server-rendered; not yet audited for mobile
  responsiveness or WCAG accessibility.
- **Scale**: SQLite (WAL) suits homelab/SMB fleets; MySQL/Postgres backends are
  planned. Command delivery is durable at this scale but the full outbox/retry
  design is a follow-up.

See [the design plan](docs/) for the roadmap and [SECURITY.md](SECURITY.md) for
the threat model and disclosure process.

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
curl -fsSL https://raw.githubusercontent.com/nickpdawson/Cairn-MDM/main/packaging/install.sh | sh
```

Or grab a release tarball / `.deb` / `.rpm` from the releases page, or run the
container (`ghcr.io/nickpdawson/cairn-mdm`). Building from source: `go build ./cmd/cairn`
(pure Go, `CGO_ENABLED=0`).

## Quick start

```sh
# One command sets up config, a CA (self-signed by default), and the admin
# account, and prints the enrollment URL. Note: running your own CA is a real
# security decision (offline root, rollover — see SECURITY.md); if you already
# have a PKI, prefer external mode so the signing key never lives on this host.
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

- **v1.0** — redesigned OTA enrollment with Cairn as the enrollment authority
  (one-time, key-bound issuance; reconstruct-don't-validate; broker in front of
  an external CA or embedded-issue with an offline root — see
  [docs/enrollment-authorization.md](docs/enrollment-authorization.md)), expiring
  links, QR, signed profiles, APNs cert wizard, device inventory, profile
  library, Kerberos SSO template.
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

# Cairn — build status

## Phase 0 — skeleton ✅
Single Go binary scaffold: `serve`/`migrate`/`version` CLI, TOML config with
env overrides and file/env-only secrets, pure-Go SQLite storage with an embedded
migration runner, `/healthz` `/readyz` `/version`, Makefile + goreleaser + CI
(cross-compile matrix incl. FreeBSD, gitleaks). MIT licensed.

## Phase 1 — minimal enroll + push ✅ (code) · ⏳ (real-device gate)
SQLite backend implementing NanoMDM's `AllStorage` (validated by NanoMDM's own
`test/e2e` suite), the MDM service chain on `/mdm`, embedded SCEP CA, enrollment
profile builder + PKCS7 signing, APNs push + push-cert loader, `/enroll`, and the
`pushcert`/`enqueue` CLIs. Remaining: the manual real-device gate (Apple hardware
+ real APNs cert + public TLS) — procedure below.

## Phase 2 — flexible PKI, one-command setup, admin console ✅
| Piece | Package | Validation |
|-------|---------|------------|
| CA modes: generate / import / external | `internal/ca`, `internal/config` | import chains to supplied CA; external delegates SCEP (no `/scep`); unit + live smoke |
| `cairn ca export` + `GET /ca` | `cmd/cairn`, `internal/server` | live smoke (out-of-band root trust) |
| `cairn init` one-command setup | `cmd/cairn/init.go` | live: init → serve boots, CA persisted, admin created |
| Local auth (argon2id) + explicit RBAC | `internal/auth` | create/authenticate/duplicate/first-run/role-ranking |
| ACME + files + proxy TLS | `cmd/cairn/tls.go` | files mode serves real HTTPS live; acme = autocert wiring |
| Event-driven device inventory | `internal/mdmcore/events.go`, `internal/storage/sqlite/devices.go` | full projection lifecycle (enroll/token/checkout/counts) |
| Admin console: sessions, login, RBAC, HIG UI | `internal/auth/session.go`, `internal/web` | login flow, RBAC redirect, dashboard/devices, 401; live smoke |
| Device detail + refresh action + APNs status card | `internal/web`, `internal/mdmcore` (Commander) | live: APNs expiry warning, detail 404, enqueue-from-UI |
| Profile library (upload/download/delete, signed-CMS aware) | `internal/profile/parse.go`, `internal/storage/sqlite/profiles.go`, `internal/web/profiles.go` | unit + web tests; upsert-by-PayloadIdentifier semantics |
| Command history (sent at enqueue, resolved at check-in) | `internal/mdmcore` (CommandRecorder), `internal/storage/sqlite/commands.go` | unit tests; device page shows status + ErrorChain summary |
| Groups + assignments + event-driven reconciler | `internal/assign`, `internal/storage/sqlite/groups.go` | full lifecycle test: push-once, ack→installed, re-upload re-arms, failed no-retry, pushable-only fan-out |
| Wi-Fi builder (PSK + EAP-TLS w/ SCEP identity + RADIUS anchors in one profile) | `internal/profile/payloads.go`, `internal/web/builders.go` | unit (UUID cross-refs) + web + live smoke |
| Kerberos SSO builder (com.apple.extensiblesso) | same | unit + web + live smoke |
| Session-cleanup job (hourly) | `cmd/cairn/serve.go` | — |

### PKI story (no PKI required)
- **generate** — self-signed CA on first boot (zero-PKI default; non-profits).
- **import** — embedded SCEP CA signing with an existing cert+key (Microsoft AD
  CS subordinate / bring-your-own); device certs chain to the corporate root.
- **external** — delegate to a third-party SCEP server (OpenXPKI, NDES).
Server TLS: built-in ACME (turnkey) / files / proxy. `cairn init` never surfaces
PKI decisions unless you opt into import/external.

### What the admin console does today
Sign in → dashboard (enrolled count, active-24h, APNs cert health with renewal
warning, enrollment URL) → device list → device detail (refresh action, group
memberships, command history with results) → profile library (upload a
.mobileconfig or build Wi-Fi/Kerberos-SSO profiles from forms) → groups
(assign profiles, add devices — assigned profiles push automatically when a
device enrolls or when assignments change; no polling). Light-first,
Apple-HIG-inspired, server-rendered, no JS build.

Deliberate policies: unassign/remove/delete never auto-remove installed
profiles (remote Wi-Fi removal can strand a device — removal is an explicit
RemoveProfile command); failed installs are not auto-retried (re-upload
re-arms them).

## Phase 1 real-device gate ✅ PASSED 2026-07-31
Production deployment (DZsec: PROD LXC, external SCEP → OpenXPKI, NPM+LE,
real mdmcert.download APNs cert via the new `pushcert request/decrypt`
wizard). MacBookPro17,1 on macOS **27.0 beta**: enrolled via `/enroll`,
SCEP issuance from the external CA, ~1s APNs push round-trips, and a
builder-made Kerberos SSO profile auto-pushed by the reconciler and
Acknowledged. Two strict-client findings fixed: profile SCEP URLs must be
https (ATS), and extensiblesso `Type` must be `Credential` (capitalized).

## Remaining
- **Phase 2 polish (optional)** — DB-backed audit log (mutations currently get
  structured slog entries with user attribution), live SSE command results,
  "install/remove profile now" one-off actions from the device page.
- **Phase 3+** — OIDC/LDAP/Kerberos providers, DZsec migration (`import --from-mysql`),
  DDM, ABM/ADE, packaging polish.

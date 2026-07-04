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

### PKI story (no PKI required)
- **generate** — self-signed CA on first boot (zero-PKI default; non-profits).
- **import** — embedded SCEP CA signing with an existing cert+key (Microsoft AD
  CS subordinate / bring-your-own); device certs chain to the corporate root.
- **external** — delegate to a third-party SCEP server (OpenXPKI, NDES).
Server TLS: built-in ACME (turnkey) / files / proxy. `cairn init` never surfaces
PKI decisions unless you opt into import/external.

### What the admin console does today
Sign in → dashboard (enrolled count, active-24h, APNs cert health with renewal
warning, enrollment URL) → device list → device detail with a working "Refresh
device info" action (queues DeviceInformation + APNs push). Light-first,
Apple-HIG-inspired, server-rendered, no JS build.

## Remaining
- **Phase 1 real-device gate** ⏳ — needs Apple hardware + real APNs cert +
  public TLS. Procedure: import the real push cert; run `cairn serve` behind
  public TLS (or `tls.mode=acme` with public DNS); install the profile from
  `GET /enroll` on a Mac/iPhone; confirm SCEP issuance + `/mdm` check-in + a
  device row; `cairn enqueue -id <UDID> -type InstallProfile -profile p.mobileconfig`.
- **Phase 2 remainder** — profile library + upload, group assignment + reconciler
  (auto-push on enroll), command-result history in the UI, session-cleanup job.
- **Phase 3+** — OIDC/LDAP/Kerberos providers, DZsec migration (`import --from-mysql`),
  DDM, ABM/ADE, packaging polish.

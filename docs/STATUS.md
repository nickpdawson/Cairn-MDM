# Cairn — build status

## Phase 0 — skeleton ✅
Single Go binary scaffold: `serve`/`migrate`/`version` CLI, TOML config with
env overrides and file/env-only secrets, pure-Go SQLite storage with an embedded
migration runner, `/healthz` `/readyz` `/version`, Makefile + goreleaser + CI
(cross-compile matrix incl. FreeBSD, gitleaks). MIT licensed.

## Phase 1 — minimal enroll + push ✅ (code) · ✅ (real-device gate, 2026-07-31)
SQLite backend implementing NanoMDM's `AllStorage` (validated by NanoMDM's own
`test/e2e` suite), the MDM service chain on `/mdm`, embedded SCEP CA, enrollment
profile builder + PKCS7 signing, APNs push + push-cert loader, `/enroll`, and the
`pushcert`/`enqueue` CLIs. The manual real-device gate (Apple hardware + real
APNs cert + public TLS) passed on 2026-07-31 — details below.

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

## Hardening sprint (2026-07-31/08-01) — third-party review + EAP-TLS plan

Full plan + status: `docs/remediation-plan.md` (source of truth). All deployed to
CT 226 + live-verified. Reference: `sol_mdmreview_20260731.md`.

- **Stage 0** ✅ — DB/WAL/SHM 0600, session tokens hashed at rest, HTTP security
  headers + no-store + timeouts + body limits + same-origin, no-echo password
  prompts, `ldap://`-without-TLS rejected, traceable build (version/commit/date),
  NOTICE + SECURITY.md.
- **Stage 1** ✅ — one-time enrollment grants (bare `/enroll` now 404;
  `/e/{token}` single-use, 410 on replay); per-device `%SerialNumber%` CN +
  owner rfc822 SAN; CMS-signed profiles via a dedicated LE cert (DNS-01,
  chains to ISRG → green "Verified"); login throttle/lockout + session
  idle/absolute limits + password-reset session revocation + min password length.
- **Stage 2** ✅ — fail-closed importer (fails on any skip/disable-failure/
  mismatch; exception-file with hash; non-mutating dry-run; `-force` DB guard;
  JSON evidence bundle; DSN off argv); per-topic APNs (validate before store;
  `apns_topics` table; dashboard per-topic expiry tiers; `pushcert check`).
- **Stage 3 core** ✅ — DeviceInformation ingestion (Refresh actually refreshes;
  proven on andesite); append-only audit log + /admin/activity; composite
  `(command_uuid, device_id)` command identity; device search/filter.
  Backup/restore runbook (`docs/backup-restore.md`).

New CLIs: `cairn admin add/passwd/list/del/testauth`, `cairn pushcert
request/decrypt/check`, `cairn import -from-mysql[-file]`.

Deferred follow-ups (documented, not cutover-blocking): full durable command
outbox (claim/lease/retry), one-off install/remove-profile UI, versioned
profiles + installed-vs-desired, per-serial migration tracker, `cairn backup` CLI.

## Production cutover ✅ DONE 2026-07-31 (DZsec, soaking)
Rehearsal (fail-closed importer) → live import into CT 226 (12 devices, 5 users,
17 enrollments, 33 cert associations, 1 APNs cert; verify passed) → NPM host
repoint → canary ping-all confirmed. Third-party post-cutover review (2026-08-03)
returned: conversion PASS, keep Cairn live. Runbook:
`~/Development/Notes/runbooks/cairn_dzsec_migration_20260731.md`. Migration
exception recorded: 257 queued-but-undelivered v1 commands were intentionally
abandoned (`-allow-pending`) — queued commands are not migrated by design; the
fleet re-derives desired state from assignments. Soak in progress; v1 nanomdm
held stopped-but-intact for rollback (repoint NPM back + `docker start nanomdm`).

## Post-cutover fixes (2026-08-03, third-party review follow-ups) ✅
- **DeviceInformation Queries** — Refresh now always sends a non-empty `Queries`
  array (default cross-platform set); fixes `CommandFormatError` on strict
  clients. `internal/mdmcore/commands.go`, test in `commands_test.go`.
- **Trusted-proxy client IP** — `trusted_proxies` is now consumed: login
  throttling and audit attribution resolve the real client via X-Forwarded-For
  from trusted peers only (untrusted peers can't spoof). `internal/web/proxy.go`,
  test in `proxy_test.go`.
- **Backup** — nightly in-guest `cairn backup` systemd timer on CT 226 (14-copy
  retention) + off-host copy; PBS job for CT 226 pending (Proxmox-side).

## Remaining
- **Open security gate — enrollment issuance trust (v1.0).** Grants gate profile
  delivery, not certificate *issuance*; in external mode the CA authenticates on
  its own SCEP challenge, so a device cert's subject/SAN is not yet
  authority-attested. **Cairn must own enrollment authorization** — embedded
  one-time issuance, or a SCEP **broker** in front of an external CA (Cairn
  validates the grant, stamps the SAN, relays with a server-side credential).
  Until then, do **not** trust device certs as a network-access credential
  (EAP-TLS). Design: `docs/enrollment-authorization.md` (reconstruct-don't-
  validate, atomic issuance-time grant consumption, broker vs embedded-issue, CA
  key ceremony, end-to-end fail-closed revocation). This is the v1.0 "one-time
  SCEP challenges" roadmap item, now scoped concretely; validate with an
  independent red/blue engagement before production.
- **Phase 2 polish (optional)** — live SSE command results, "install/remove
  profile now" one-off actions from the device page.
- **Soak wrap-up** — remaining migrated devices to first check-in or retire;
  then v1 teardown (secret rotation, lock down maverick MySQL 3306, stop
  mdm-admin :8081).
- **OIDC** — authorization-code flow implemented (`internal/auth/oidc`,
  `/auth/oidc/login` + `/callback`); live-verify against Authentik outstanding.
- **Phase 4+** — Kerberos/SPNEGO provider, MySQL/Postgres app storage,
  Prometheus metrics, DDM, ABM/ADE.

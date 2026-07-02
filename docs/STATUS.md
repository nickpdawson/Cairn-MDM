# Cairn — build status

## Phase 0 — skeleton ✅
Single Go binary scaffold: `serve`/`migrate`/`version` CLI, TOML config with
env overrides and file/env-only secrets, pure-Go SQLite storage with an embedded
migration runner, `/healthz` `/readyz` `/version`, Makefile + goreleaser + CI
(cross-compile matrix incl. FreeBSD, gitleaks). MIT licensed.

## Phase 1 — minimal enroll + push ✅ (code) · ⏳ (real-device gate)

Implemented and tested:

| Piece | Package | Validation |
|-------|---------|------------|
| SQLite `AllStorage` | `internal/storage/sqlite` | NanoMDM's upstream `test/e2e` suite passes (enroll, certauth, queue, bootstrap token, push cert, tally, migrate) |
| MDM service chain + `/mdm` | `internal/mdmcore` | signature middleware rejects unsigned (400, not 404); e2e above drives the full stack |
| Embedded SCEP CA + `/scep` | `internal/ca` | CA bootstrap/persist, real CSR issuance chains to CA, `GetCACert` HTTP path |
| Enrollment profile builder + PKCS7 sign | `internal/profile` | plist round-trips; MDM↔SCEP UUID linkage; signature verifies |
| APNs push + push-cert loader | `internal/push` | live smoke: topic extracted, expiry parsed, stored |
| `/enroll` handler | `internal/enroll` | 503 without cert; serves plutil-valid profile with topic |
| `pushcert import`, `enqueue` CLIs | `cmd/cairn` | live smoke end-to-end |

Design posture: NanoMDM/nanolib/scep are linked libraries behind `internal/`
packages (not forked); the SQLite `AllStorage` is additive and upstreamable.

### Remaining Phase 1 exit criterion — manual real-device gate ⏳
"A real device enrolls against a fresh binary and receives a pushed profile"
cannot be run in CI: it needs Apple hardware, a real APNs push certificate
(mdmcert.download or ABM), and public-trusted TLS. Procedure when hardware is
available:

1. Obtain a real APNs MDM push certificate; `cairn pushcert import -cert … -key …`.
2. Run `cairn serve` behind a reverse proxy terminating a publicly-trusted TLS
   cert for the `public_url` host (`tls.mode = proxy` today; built-in ACME lands
   in Phase 2).
3. On a Mac/iPhone, download the profile from `GET /enroll` and install it.
   Expect: SCEP issues a device identity from the embedded CA, the device
   enrolls at `/mdm`, and a row appears in storage.
4. `cairn enqueue -id <UDID> -type InstallProfile -profile <mobileconfig>` and
   confirm the device receives it (APNs push wakes it; result recorded).

## Next — Phase 2 (admin app)
Local auth + sessions + CSRF + RBAC, HIG design system, device inventory +
command console, profile library + assignments (event-driven reconciler),
`cairn init` wizard, built-in ACME TLS.

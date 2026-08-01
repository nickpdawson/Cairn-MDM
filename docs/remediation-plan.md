# Cairn remediation + EAP-TLS implementation plan

Consolidates the third-party review (sol_mdmreview_20260731.md) with the
EAP-TLS Wi-Fi change (runbooks/eap_tls_wifi_design_20260731.md). Ordered by
dependency and by what unblocks a safe DZsec cutover. Status posture stays
**experimental pre-alpha**; v1 stays recoverable; no DZsec cutover and no
internet-open enrollment until Stage 1 gates pass.

## The load-bearing insight

The **user-attributed one-time enrollment grant** is the keystone. It is
simultaneously:

- the review's #1 P0 security fix (kills the reusable public /enroll + static
  challenge), and
- the thing that puts a per-device serial + owner identity into the SCEP cert,
  which is the prerequisite for EAP-TLS live AD authorization.

So enrollment grants are built once and unblock both tracks. Everything
sequences around them.

---

## Stage 0 — quick wins ✅ DONE 2026-07-31 (commit 3c5423a)

Low-risk hardening that shrinks the live exposure immediately. None touch
device-facing behavior. Built by a 4-agent team, integrated + verified.

- **0.1 File modes** ✅ — `cairn.db`/`-wal`/`-shm` chmod 0600 on open + after
  migrate (`internal/storage/sqlite/sqlite.go`); verified live (0600). Systemd
  umask tightening applied at CT deploy. Startup-fail-on-unsafe deferred (chmod
  self-heals; add later). (MDM-SEC-002)
- **0.2 Session tokens hashed at rest** ✅ — SHA-256 before storage, raw token
  only in cookie (`internal/auth/session.go`); test asserts stored ≠ raw.
  (MDM-AUTH-001)
- **0.3 HTTP hardening** ✅ — CSP baseline + X-Content-Type-Options +
  Referrer-Policy + Permissions-Policy (HSTS only when TLS-local),
  `Cache-Control: no-store` on admin/login/enroll, full `http.Server` +
  ACME-server timeouts + `MaxHeaderBytes`, `MaxBytesReader` on all form POSTs,
  same-origin check on mutations, `/readyz` no longer leaks errors. Headers
  verified live. (MDM-WEB-001)
- **0.4 Secrets off argv** ✅ — `admin add/passwd`/`init` no-echo TTY prompts;
  scripted `-password` warns. (MDM-AUTH-001)
- **0.5 Traceable build** ✅ — Makefile ldflags stamp real version/commit/date;
  `cairn version` now shows `<commit>-dirty (...)` not dev/none/unknown.
  (MDM-REL-001)
- **0.6 LDAP transport** ✅ — config rejects plaintext `ldap://` without
  start_tls; ServerName pinned for hostname verification.
- **0.7 Repo hygiene** ✅ — NOTICE (nanomdm/scep MIT attribution) + SECURITY.md;
  private IP scrubbed from importer example. NOTE: license is **MIT**
  (consistent across LICENSE/README/STATUS/NOTICE) — the review's "Apache-2.0"
  was a reviewer error, no change needed.

Verification: full `go test` + `-race` green, FreeBSD cross-compile clean,
gofmt clean, secret-scan clean, live header/perms check passed, login still
works.

**Containment (operational, OPEN):** restrict `/enroll` to LAN/VPN at NPM until
Stage 1.1 ships. Not yet done — deferred pending the iOS enrollment test; do not
rely on URL secrecy. Owner decision.

## Stage 1 — enrollment + crypto trust (P0; before any internet exposure or public repo)

**Wave A ✅ DONE 2026-07-31 (commit a965090), deployed + live-verified:**
- **1.1 One-time enrollment grants** ✅ — `enrollment_grants` (sha256 token hash
  only; label/platform/owner/creator/expiry/max_uses/revoked/expected_serial),
  atomic redeem-and-consume (single UPDATE…RETURNING; race test: 1 of 12 wins),
  `GET /e/{token}` (invalid→410), bare `/enroll` **default-denied 404**,
  console create/list/revoke + one-time link + QR (data-URI, never logged).
  Live: bare /enroll=404, redeem=200, replay=410. (MDM-SEC-001 CLOSED for deploy)
  — this supersedes the `/enroll` NPM containment item (now denied in code).
  Note: per-grant one-use SCEP challenge is embedded-mode only; external mode
  (DZsec) gates the challenge behind the grant — documented in
  enrollment-grants-design.md.
- **1.2 Per-device + owner-bound certs** ✅ — SCEP CN `%SerialNumber%.devices.…`
  + owner rfc822 SubjectAltName; live-verified in the served profile.

**Wave B ✅ DONE 2026-07-31, deployed + live-verified:**
- **1.3 Signed enrollment profiles** ✅ (commit 5dabc43) — `[profile.signing]`
  cert/key config + validation; `profile.LoadSigner` verifies key↔cert match +
  validity (rejects expired/mismatched), fails boot on a bad cert, logs
  fingerprint. DZsec signing identity: a **dedicated Let's Encrypt cert for
  cairn.dzsec.net via DNS-01** (certbot dns-cloudflare on CT 226, auto-renew +
  deploy-hook copies to /etc/cairn/sign.* and reloads). Live: served profile is
  CMS/PKCS7-signed, signature verifies, chains cairn.dzsec.net→LE→ISRG (public
  → green "Verified"); on-device banner still to eyeball on hardware.
  (MDM-PKI-001 CLOSED for deploy)
- **1.4 Login abuse controls** ✅ (commit 334907d) — per user+IP throttle +
  lockout (429+Retry-After), session idle timeout + absolute-lifetime cap,
  DeleteByUsername (admin passwd revokes sessions), min password length.
  (MDM-AUTH-001)

**Gate: ✅ ALL PASS** — enrollment replay/expiry/revoke/exhaustion; no static
challenge without a grant; signed profile CMS-verifies + chains to a public
root; DB/key perms + restart (Stage 0). Only on-hardware "Verified" eyeball
remains (needs a physical device).

**Stage 1 COMPLETE.** Deployment now: grant-gated enrollment, per-device
owner-bound certs, publicly-signed profiles, throttled/bounded auth.

## Stage 2 — migration safety ✅ DONE 2026-08-01 (commit 37d002c), deployed + live-verified

- **2.1/2.2 Fail-closed importer** ✅ — `Report.Ok()` fails on any mismatch,
  disable-failure, or unaccepted skip (skips carry id/reason/accepted);
  `-allow-exceptions` file (sha256 in evidence) is the only way to accept a
  skip; user-channel enrollments disabled with the user request shape;
  `-dry-run` never opens the destination; `-force` required to import into a
  populated DB; JSON evidence bundle (counts by type/topic, exceptions+hash,
  mismatches, disable-failures, build commit) replaces "Safe to point DNS".
  Tests: skip/exception/disable-fail/user-disable/dry-run-no-write/evidence.
  (MDM-MIG-001, MDM-CUT-001)
- **2.3 Credentials** ✅ — `-from-mysql-file` (0600, perm-checked) preferred
  over argv DSN (warns); DSN defaults to `tls=preferred`; read-only account
  documented. Runbook still to drop LAN-3306 in favor of tunnel (doc edit).
  (MDM-MIG-002)
- **2.4 Per-topic APNs** ✅ — validate key↔cert + topic + validity before store
  (reject expired/mismatched); `apns_topics` table; `pushcert import` records
  per-topic metadata; `pushcert check` CLI; dashboard shows every topic with
  90/60/30/14/7-day tiers. Live: existing 108e30db topic backfilled + shows on
  the dashboard (363d, ok). NOTE: `pushcert check` is table-only (no live APNs
  socket — deferred). (MDM-APNS-001)

**Gate: ✅ PASS** — fixture with device+user channels, bootstrap tokens,
malformed/disable-fail rows all fail closed; per-topic expiry correct + live.

## Stage 3 — correctness + operability (P1/P2; before cutover)

- **3.1 DeviceInformation ingestion** — parse QueryResponses into a versioned
  inventory with per-field `observed_at`; Refresh actually refreshes.
  (MDM-INV-001)
- **3.2 Durable command/deploy state** — outbox/job tables, SQLite txns,
  claim/lease, bounded workers, retry+jitter+dead-letter, composite identity
  `(command_uuid, device_id)`, startup recovery; APNs push is a retryable
  consequence of a committed command, not the commit boundary. (MDM-REL-001)
- **3.3 Audit log** — immutable, secret-free, for login/user/role/grant/profile/
  group/command/cert/migration actions.
- **3.4 Console must-haves** — device search/filter/sort, per-serial migration
  tracker, one-off install/remove-profile, versioned profiles, installed-vs-
  desired state, group deployment status. (review "required before production")
- **3.5 Backup/restore** — checkpoint+backup+restore+integrity-check runbook,
  proven by a real restore into a disposable instance.

## Stage 4 — EAP-TLS Wi-Fi (parallel infra track; gated on 1.2)

Cairn-side (per-device + owner-SAN certs) lands in 1.2; the rest is DZsec infra
per `runbooks/eap_tls_wifi_design_20260731.md`:

- **4.1 svc-mdm-ldap** — create read-only account; swap it into Cairn LDAP bind,
  OpenXPKI `publishing.yaml`, retire `CN=services`; rotate old password
  (spread across ≥3 places). (also a review/plan security item)
- **4.2 OpenXPKI CRL issuance** — schedule the `crl_issuance` workflow
  (production realm); verify CRL publishes to the CDP; DC cron fetch + rehash +
  radiusd reload (daily).
- **4.3 mdm_device profile** — confirm `san:` copies request SAN; CN accepts
  per-device `%SerialNumber%` form.
- **4.4 FreeRADIUS EAP-TLS + AD-liveness** — enable `ldap` module (svc-mdm-ldap),
  EAP-TLS virtual server with `check_crl`, disabled-bit filter
  `(!(userAccountControl:1.2.840.113556.1.4.803:=2))`, optional wifi-access group.
- **4.5 Temp-SSID canary** → migrate `DZsec Secure`. Prove: cert-only auto-join;
  disable AD account → rejected next assoc (cert valid); revoke → CRL rejection.

## Stage 5 — DZsec cutover (only after Stage 1–3 gates + evidence)

Use the replacement sequence in the migration runbook (staging import →
per-topic APNs check → non-prod hostname validation → real-device canary matrix
→ signed acceptance → NPM repoint → monitored soak → documented rollback).
**Nick signs the checklist; a green import is not authorization.**

## Stage 6 — public beta readiness (P2)

Authentik OIDC + MFA + break-glass; production packaging (Dockerfile/systemd/
rc.d/install.sh) + least-priv service user; Prometheus + alerting (also chips at
the fleet-wide alert gap); SBOM + signed artifacts + SHA-pinned CI actions +
govulncheck/gosec/staticcheck + fake-Apple-device integration test; responsive/
a11y/dark-mode redesign with screenshot acceptance; contributor/disclosure docs.

## Stage 7 — product roadmap (P3, unchanged from the brief)

DDM + software-update enforcement (has the OS-27 deadline); FileVault/bootstrap-
token/Activation-Lock/supervision visibility; ADE/ABM + account-driven + Platform
SSO; managed apps/config.

---

## Recommended immediate order

1. Stage 0 quick wins + `/enroll` containment (fast, shrinks live risk).
2. Stage 1 enrollment grants (keystone — unblocks security *and* EAP-TLS).
3. Fork: Stage 2/3 (migration safety) and Stage 4 (EAP-TLS infra) proceed in
   parallel — different systems, no shared code path after 1.2.
4. Stage 5 cutover once gated.

svc-mdm-ldap (4.1) can be pulled forward anytime — it is pure infra and already
on the reminder list; doing it early also de-risks the CN=services spread.

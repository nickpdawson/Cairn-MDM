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

## Stage 0 — quick wins (days, no design needed)

Low-risk hardening that shrinks the live exposure immediately. None of these
touch device-facing behavior.

- **0.1 File modes** — enforce 0600 on `cairn.db`/`-wal`/`-shm`; set a
  restrictive umask in the systemd unit; fail startup on unsafe
  ownership/mode. (MDM-SEC-002)
- **0.2 Session tokens hashed at rest** — store `sha256(token)`, compare on
  lookup. (MDM-AUTH-001)
- **0.3 HTTP hardening** — secure headers (HSTS/CSP baseline/X-Content-Type-
  Options/Referrer-Policy/Permissions-Policy), `Cache-Control: no-store` on
  auth/admin/enroll, full `http.Server` timeouts + `MaxHeaderBytes`,
  `MaxBytesReader` on every form, Origin/Referer check on mutations. (MDM-WEB-001)
- **0.4 Secrets off argv** — `admin add/passwd` and `init` read passwords from
  TTY/stdin only; no-echo. (MDM-AUTH-001)
- **0.5 Traceable build** — ldflags version/commit/date wired in release;
  `/version` stops reporting dev/none/unknown. (MDM-REL-001 containment)
- **0.6 LDAP transport** — refuse `ldap://` without StartTLS; require TLS verify.
- **0.7 Repo hygiene** — add NOTICE, SECURITY.md; scrub the private IP from the
  importer example DSN; fix STATUS/README inconsistencies.

**Containment (operational, now):** restrict `/enroll` to LAN/VPN at NPM until
Stage 1.1 ships. Do not rely on URL secrecy.

## Stage 1 — enrollment + crypto trust (P0; before any internet exposure or public repo)

- **1.1 One-time enrollment grants** — grant table (hashed high-entropy token,
  platform/fleet, creator = authenticated AD user, created/expiry/used/revoked,
  use-limit, optional expected serial/UDID, audit). Serve `/e/{token}`, consume
  atomically, per-grant one-use SCEP challenge (never the shared external
  challenge). Console: create/list/revoke/QR. Default-deny bare `/enroll`.
  Concurrent-redemption tests. (MDM-SEC-001)
- **1.2 Per-device + owner-bound certs** — grant carries the redeeming user;
  SCEP subject CN = `%SerialNumber%.devices.…`, owner rfc822 SAN in the payload.
  (Feeds EAP-TLS Stage 4.) 
- **1.3 Signed enrollment profiles** — dedicated signing identity (reuse the LE
  cert or an embedded-CA signing cert); validate EKU/validity/chain at startup;
  sign every enrollment response; expose signer fingerprint in settings. Verify
  the green "Verified" banner on real hardware. (MDM-PKI-001)
- **1.4 Login abuse controls** — per-account/IP throttling + lockout + alert;
  minimum password policy; session invalidation on password/role change;
  short idle + bounded absolute session lifetime; periodic role revalidation so
  LDAP group removal takes effect. (MDM-AUTH-001)

**Gate:** enrollment replay/tamper tests pass; no static challenge anywhere in
config/logs/HTML/DB export; signed profile verifies and a tampered byte fails;
DB/key permission + restart test passes.

## Stage 2 — migration safety (P1; before the DZsec rehearsal)

- **2.1 Fail-closed importer** — any skipped/malformed/duplicate/disable-failed/
  unverifiable row → nonzero exit; `Report.Ok()` counts Skipped and real
  disable success; explicit operator exception manifest (hashed into the
  report). (MDM-MIG-001)
- **2.2 Phased + restartable** — separate extract/validate/stage/compare/commit/
  source-disable/post-verify; import into a **staging** DB, never the live sole
  copy; truly non-mutating `-dry-run`; correct enrollment-type request shape for
  user-channel disables; signed JSON/MD evidence bundle (counts by type/topic,
  exceptions, hashes, timestamps, snapshot coords, build commit). Remove "Safe
  to point DNS" from code — human runbook gate only. (MDM-MIG-001, MDM-CUT-001)
- **2.3 Credentials/network** — DSN from mode-0600 file/stdin, never argv;
  importer requires TLS + read-only account; runbook drops LAN 3306 publish in
  favor of localhost/socket or verified SSH tunnel. (MDM-MIG-002)
- **2.4 Per-topic APNs** — model push identities per topic; map enrollment→topic;
  validate cert/key match + UID topic + EKU + chain + validity before storage;
  reject mismatch/expired; dashboard shows every topic with 90/60/30/14/7-day
  alerts; non-destructive per-topic connectivity check. Directly fixes the
  runbook's two-topic blind spot (test 2027 vs fleet Nov-2026). (MDM-APNS-001)

**Gate:** migration fixture with device+user channels, bootstrap tokens, two
topics, malformed/duplicate/disable-fail rows — every anomaly fails closed;
per-topic expiry correct.

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

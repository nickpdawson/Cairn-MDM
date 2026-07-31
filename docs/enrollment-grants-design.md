# Stage 1 design — enrollment grants, owner-bound certs, signed profiles

The keystone. Replaces the reusable unauthenticated `/enroll` (MDM-SEC-001) and
produces the per-device + owner-bound cert EAP-TLS needs (feeds Stage 4).

## Enrollment grants (1.1)

A grant is a single-use, expiring authorization to enroll one device, created
by an authenticated operator/admin.

**Storage** (`enrollment_grants`): `token_hash` (sha256 hex — the raw token is
shown once at creation and never stored, same pattern as session tokens),
`label`, `platform` (any|macos|ios), `owner` (rfc822/UPN of the AD user the
device belongs to — flows into the cert SAN for EAP-TLS; optional), `created_by`,
`created_at`, `expires_at`, `max_uses` (default 1), `use_count`, `revoked_at`,
`expected_serial` (optional bind), `last_used_at`.

**Redemption is atomic** — the whole check-and-consume is one SQL UPDATE:

```sql
UPDATE enrollment_grants
   SET use_count = use_count + 1, last_used_at = datetime('now')
 WHERE token_hash = ?
   AND revoked_at IS NULL
   AND use_count < max_uses
   AND expires_at > datetime('now')
RETURNING id, platform, owner, expected_serial;
```

No row updated → the grant is expired/revoked/exhausted/unknown → `410 Gone`.
Concurrent redemptions can't double-spend because SQLite serializes the writer
(single-conn WAL). Test covers concurrent redemption of a max_uses=1 grant:
exactly one wins.

**Routes**:
- `GET /e/{token}` — hash token, redeem, build the profile (owner/platform
  applied), serve `application/x-apple-aspen-config`. Invalid → 410.
- Bare `GET /enroll` — **default deny** (404). Opt-in `enrollment.allow_open =
  true` for a zero-friction homelab that accepts the tradeoff. DZsec: deny.

**Console** (`/admin/enrollment`, new nav): list grants with status
(active/used/expired/revoked), create (platform, owner, expiry, max_uses,
label), show the one-time link + QR **once**, revoke. Operator+ creates; the
`user` self-service surface comes later.

## Owner-bound, per-device certs (1.2)

When a grant is redeemed, the served profile's SCEP payload gets:
- **CN** = `%SerialNumber%.devices.<prefix>` — Apple substitutes `%SerialNumber%`
  at install, so every device gets a unique subject (individually revocable).
- **SubjectAltName rfc822** = the grant's `owner` (a concrete address, no
  substitution) — the binding FreeRADIUS reads for the AD-liveness check.

Cairn-side only. The external CA (OpenXPKI `mdm_device`) must honor the requested
subject/SAN — coordination item tracked in the EAP-TLS runbook (Stage 4.3).

## The SCEP-challenge nuance (honest limitation)

The review wants a per-grant one-use SCEP challenge. Achievable **only in
embedded CA mode** (generate/import), where Cairn's own SCEP validates it —
follow-up within 1.1. In **external mode** (DZsec→OpenXPKI), OpenXPKI owns
challenge validation, so the profile must carry the challenge OpenXPKI expects.
The meaningful fix there is that the challenge is **no longer served
unauthenticated** — a valid one-time grant is required to obtain the profile at
all. Documented as a mode-dependent property, not hidden.

## Signed enrollment profiles (1.3)

Add `[profile.signing]` config: `cert_file` + `key_file` (operator-supplied
signing identity), or `reuse_tls = true` in files/acme mode to sign with the
serving cert. Validate chain/EKU/validity at startup; sign every enrollment
response; expose the signer fingerprint in settings. Devices then show
"Verified — <signer>" instead of "Not Signed".

DZsec (proxy+external, no local TLS cert): operator supplies a signing cert that
chains to DZsec Issuing CA (obtainable from OpenXPKI) — coordination item, not a
code blocker. Wiring + validation land in code now; the cert is dropped in when
available.

## Login abuse controls (1.4)

Per-account + per-IP throttling with progressive delay + lockout + log/alert;
minimum password length policy; invalidate a user's sessions on password/role
change; short idle timeout + bounded absolute session lifetime; periodic role
revalidation so an LDAP group change or local demotion takes effect within the
window.

## Build order

- **Wave A (now, authored directly — security-critical):** 1.1 grants + 1.2
  owner/serial cert binding. Storage, atomic redemption, `/e/{token}`,
  default-deny `/enroll`, console CRUD + QR, tests.
- **Wave B (agent team after A):** 1.3 signed profiles + 1.4 abuse controls —
  parallelizable, different files.

## Gate to leave Stage 1

Replay/expiry/revoke/exhaustion tests pass; no static challenge served without a
grant; a copied link fails after first use; signed profile verifies + a tampered
byte fails; abuse controls demonstrably throttle.

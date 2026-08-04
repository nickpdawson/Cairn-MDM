# Enrollment authorization — design (v1.0 security gate)

**Status: design, pre-implementation.** This is the design for the v1.0 roadmap
item "one-time SCEP challenges" and the security gate recorded in `STATUS.md` and
`SECURITY.md`. It extends `enrollment-grants-design.md` (Stage 1). Nothing here is
implemented yet; a device identity certificate must **not** be trusted as a
network-access credential (e.g. EAP-TLS) until it is.

## The problem it solves

A one-time enrollment grant gates delivery of the *enrollment profile*. It does
**not**, by itself, gate certificate *issuance*:

- In **external** CA mode the device does SCEP directly to the CA, which
  authorizes on its own challenge. A shared/static challenge is a weak,
  replayable, often widely-embedded secret; the grant doesn't protect the CA.
- Once a device certificate carries an identity used for **authorization**
  (an owner UPN for EAP-TLS network access, say), issuance of that identity must
  be controlled by an authenticated authority — otherwise anyone who can reach
  the CA and present the challenge can mint a certificate bearing **someone
  else's** identity and impersonate them.

**Whatever CA signs authorization-bearing client certs is effectively a root of
trust for whatever those certs authorize (e.g. network access).** That trust must
not rest on a shared secret at a reachable endpoint.

## Principle: Cairn owns enrollment authorization

The MDM server is the enrollment authority (as Intune/NDES and Jamf do). Two
rules:

### 1. Reconstruct, don't validate
The only trusted input from the device is its **public key + proof-of-possession**
(the CSR signature). The certificate's subject DN, **all** SANs, EKU, key usage,
validity, and extensions are **constructed from server-side policy + the grant** —
never copied from, or merely compared against, the CSR. Comparing
`CSR.SAN == expected` is insufficient: it leaves room for duplicate SANs,
`otherName` identities, extra extensions, encoding tricks, and alternate subjects.
Discard the device's requested fields.

### 2. Separate, atomic state transitions
Profile *delivery* and certificate *issuance* are distinct. **Consuming a grant at
profile download must not leave a reusable issuance credential.** The
authorization to *issue* is a separate, single-use token consumed atomically at
CSR time and **bound to the fingerprint of the presented public key** (so a
captured authorization can't be replayed with a different key). Exactly one
issuance wins a race; the result records the certificate serial, closing a
**grant → CSR → certificate** audit chain.

## Two modes

### External CA — broker (for deployments that already run a PKI)
The device does grant-gated SCEP **to Cairn**, not to the CA. Cairn validates the
grant, constructs the authorized subject/SAN from policy (rule 1), and relays to
the backend CA (OpenXPKI / NDES / etc.) over a restricted network with a strong,
renewable service credential. The backend CA's SCEP endpoint is **not exposed to
devices**. The **signing key never leaves the CA**; a compromised Cairn is bounded
by CA policy and is revocable without re-trusting devices. This is the
NDES+Intune-connector / Jamf-SCEP-proxy pattern.

The CA must **independently constrain every issuance** (defense in depth): a
dedicated profile + issuing CA, `clientAuth`-only EKU, `basicConstraints
CA:FALSE`, short fixed validity, namespace/name constraints, and preferably a
**policy OID** so consumers can *require* "broker-issued". The backend should
independently refuse a double/unauthorized issuance — e.g. via a Cairn-signed,
short-TTL, key-bound authorization token validated at the CA (stateless), or a
per-transaction record the CA burns.

> Name constraints bound the **namespace**; they do **not** stop a compromised
> broker from impersonating another identity *within* it. See operational
> controls below.

### Embedded CA — issue (for deployments with no PKI)
Cairn issues the certificate itself, validating its one-time grant in-process and
constructing fields from policy (rule 1). CA key custody is the crux:

- Use a **two-tier CA**: an **offline root** (born on an HSM/PIV token or via a
  genuine offline ceremony — *not* generated on the internet-facing host and
  "deleted later"; backups/snapshots/prior compromise can retain it) signing an
  **online issuing CA**. Only the issuing key is ever on the host.
- The root is the device trust anchor (long-lived). Rotating the **issuer**
  needs no device re-enroll; rotating the **root** is a planned, overlapping
  trust-anchor migration via MDM. If the online issuer is compromised, revoke it
  with the offline root and re-issue — devices, which trust the root, are
  unaffected.
- Same reconstruct-don't-validate and short-validity rules apply.

Prefer **broker over embedded** wherever a PKI exists — don't put a signing key on
an internet-adjacent MDM host. The embedded CA is a deliberate, security-load-
bearing choice, not a frictionless default.

## Cairn is a highly-privileged enrollment authority

Because a compromised authority can issue in-namespace identities (impersonation),
Cairn must be treated as tier-0 identity infrastructure:

- **MFA + strict RBAC on grant creation** — creating a grant for an owner is a
  privileged action; "authenticated" never implies "may issue for any owner".
- **Issuance rate limits** (per-owner + global) with anomaly throttling + alert.
- **Append-only / tamper-resistant audit** correlating grant → CSR (public-key
  fingerprint) → certificate serial → owner → the operator who created the grant.
- **Real-time alerting** on issuance and anomalies (independent of email/SMTP so
  it survives an outage of the very system it monitors).

## Revocation — end-to-end, fail-closed

"Revoked at the CA" is insufficient. The consumer must reject the certificate:
publish CRLs on a known cadence; configure the relying party (e.g. RADIUS) to
fetch **fresh** CRLs and **fail closed** if the CRL is missing/stale; and
**demonstrate** that a revoked certificate is rejected on next use, and that
revoking the broker's own credential stops issuance without breaking existing
devices.

## Honest scope

- **`%SerialNumber%` is device-asserted, not attestation.** This design binds a
  certificate to a *grant + an owner identity*, not to specific Apple hardware.
  True hardware binding requires Managed Device Attestation or ADE/ABM as a
  trusted bootstrap — separate, larger work.

## Gate

No EAP-TLS (or other network/service) authorization trusts these certificates
until: issuance is Cairn-controlled (broker or embedded-issue) per rules 1–2; the
CA independently constrains issuance; operational controls (MFA/RBAC, rate limit,
audit, alerting) are in place; and revocation is demonstrated end-to-end. Validate
with an independent red/blue engagement before production.

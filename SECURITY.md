# Security policy

## Supported versions

Cairn is **experimental, pre-alpha software (v0)**. It is not yet ready for
production and carries no stability or security-support guarantees. Only the
current `main` branch receives fixes; there are no maintained release branches
or backports yet. Once Cairn reaches a stable release, this section will list
the versions that receive security updates.

| Version | Supported          |
|---------|--------------------|
| `main`  | :white_check_mark: (best effort) |
| < 1.0   | :x: (pre-alpha, no support) |

## Reporting a vulnerability

Please report security issues privately. Do **not** open a public issue for a
suspected vulnerability.

- Preferred: open a private security advisory via GitHub
  ("Security" → "Report a vulnerability") on the Cairn repository.
- Alternatively, email **security@dzsec.net** with details and, if possible,
  a proof of concept.

Please include the affected component, the version or commit, reproduction
steps, and the impact you observed.

## Disclosure expectations

- We aim to acknowledge a report within a few business days.
- We will work with you on a fix and a coordinated disclosure timeline.
- Because Cairn is pre-alpha, fixes land on `main`; there is no embargoed
  release train yet.
- Please give us a reasonable opportunity to remediate before any public
  disclosure.

## Threat model (trust boundaries)

Cairn is security-critical infrastructure — it can push configuration and
commands to managed devices. The main boundaries it defends:

- **Admin console.** Authenticated (local argon2id, LDAP/AD, or OIDC) with
  explicit role assignment — there is no code path where "authenticated" implies
  "admin". Sessions are DB-backed with hashed tokens in a `__Host-` cookie;
  mutating routes require a CSRF token and same-origin; logins are throttled and
  rate-limited; all mutations are audited.
- **Device enrollment (profile delivery).** Delivery of the enrollment profile
  requires a single-use, expiring grant (`/e/{token}`); the bare `/enroll` is
  default-denied; profiles are CMS-signed. **Scope caveat:** a grant gates
  *profile delivery*, not certificate *issuance*. In the embedded CA modes Cairn
  signs the device cert itself and (target design) binds its identity to the
  grant. In **external** CA mode, issuance is delegated to your CA and
  authenticated by that CA's SCEP challenge — the grant does not itself gate the
  CA. Operators using external mode must protect and rotate the SCEP challenge
  and restrict the CA's SCEP endpoint. **Bound, one-time issuance (Cairn as the
  authorizing authority for each enrollment) is a v1.0 security gate.** Until
  issuance is Cairn-controlled (embedded-issue or a SCEP broker in front of an
  external CA), a device identity certificate should **not** be relied on as a
  network-access credential (e.g. EAP-TLS), because its subject/SAN is not yet
  guaranteed to be authority-attested.
- **Certificate authority (embedded modes).** Running `generate`/`import` means
  you are operating a CA. Best practice is a two-tier CA with the **root kept
  offline** (exported and stored off the host, ideally on an HSM/PIV token) and
  only an issuing key online; plan issuer/root rollover. The embedded CA is a
  deliberate, security-load-bearing choice, not a frictionless default — if you
  have an existing PKI, prefer external/broker so the signing key never lives on
  the MDM host.
- **Device check-in (`/mdm`).** Every request is authenticated by the device's
  identity certificate (SCEP-issued) via `Mdm-Signature`/mTLS; certauth binds
  each enrollment to its certificate hash(es).
- **Secrets at rest.** The SQLite database (CA key, APNs key, session tokens)
  is enforced to mode 0600; config secrets are file/env-only, never inlined.
- **Out of scope / operator responsibilities.** TLS termination and its cert
  (ACME/files/proxy), the APNs push certificate (Apple-issued), the external
  SCEP CA when used, host and network security, and physical device security.

Reports that cross these boundaries (enrollment without a grant, check-in without
a valid cert, privilege escalation in the console, secret exposure) are the
highest priority.

## Secrets must never be committed

Never commit secrets to this repository: APNs certificates and keys, SCEP
challenge passwords, CA private keys, database credentials, admin passwords,
session keys, or API tokens. Provide these through the config file (kept out of
version control), environment variables, or file/env-only secret references.
CI runs `gitleaks`; if you believe a secret has been committed, treat it as
compromised, rotate it immediately, and report it through the channel above.

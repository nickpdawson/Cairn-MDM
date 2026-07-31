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

## Secrets must never be committed

Never commit secrets to this repository: APNs certificates and keys, SCEP
challenge passwords, CA private keys, database credentials, admin passwords,
session keys, or API tokens. Provide these through the config file (kept out of
version control), environment variables, or file/env-only secret references.
CI runs `gitleaks`; if you believe a secret has been committed, treat it as
compromised, rotate it immediately, and report it through the channel above.

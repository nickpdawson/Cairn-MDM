# Backing up and restoring Cairn

Cairn's entire state is small and file-based. A correct backup is: the SQLite
database (captured consistently), the config, and the two on-disk certs. Losing
the database loses enrollments — treat it like the crown jewel it is.

## What to back up

| Item | Path (DZsec CT 226) | Why |
|---|---|---|
| Database | `/var/lib/cairn/cairn.db` (+ `-wal`, `-shm`) | Devices, enrollments, cert-auth associations, **APNs push cert/key**, embedded CA (generate/import mode), sessions, profiles, grants, audit |
| Config | `/etc/cairn/cairn.toml` | Wiring; references the cert/challenge files |
| Signing cert | `/etc/cairn/sign.crt` / `sign.key` | Profile-signing identity (re-issuable from LE, but back it up) |
| External SCEP chain / challenge | `/etc/cairn/dzsec-ca-chain.pem`, `/etc/cairn/scep-challenge` | External-mode enrollment trust + challenge |
| APNs push key (source) | `/var/lib/cairn/pushcert/push.key` | Only needed to re-import the APNs cert; the live cert is already in the DB |

The DB already contains the APNs cert+key and (in embedded modes) the CA key,
so the DB backup is confidential — store it encrypted, mode 0600.

## Consistent database backup (no downtime)

SQLite in WAL mode must not be copied with a plain `cp` while Cairn is running —
you can capture a torn state. Use one of:

**A. `VACUUM INTO` (preferred, online, no lock contention):**
```
sqlite3 /var/lib/cairn/cairn.db "VACUUM INTO '/var/backups/cairn-$(date +%F).db'"
```
Produces a single consistent file with no WAL/SHM sidecars.

**B. Stop-copy (simplest, brief downtime):**
```
systemctl stop cairn
cp /var/lib/cairn/cairn.db /var/backups/cairn-$(date +%F).db
systemctl start cairn
```

Then bundle the rest:
```
tar czf /var/backups/cairn-config-$(date +%F).tgz \
  /etc/cairn/cairn.toml /etc/cairn/sign.crt /etc/cairn/sign.key \
  /etc/cairn/dzsec-ca-chain.pem /etc/cairn/scep-challenge
chmod 600 /var/backups/cairn-*.db /var/backups/cairn-config-*.tgz
```

Copy both off-host. `sqlite3` is a separate package on the CT
(`apt-get install -y sqlite3`); `VACUUM INTO` also works via a tiny Go/`cairn`
one-liner if you prefer not to install it.

## Integrity check

```
sqlite3 /var/backups/cairn-YYYY-MM-DD.db "PRAGMA integrity_check;"   # expect: ok
```

## Restore (into a disposable instance first — always test)

1. Provision a scratch CT/dir; install the same `cairn` binary version.
2. Restore files:
   ```
   install -o cairn -g cairn -m 0600 cairn-YYYY-MM-DD.db /var/lib/cairn/cairn.db
   rm -f /var/lib/cairn/cairn.db-wal /var/lib/cairn/cairn.db-shm   # stale sidecars
   tar xzf cairn-config-YYYY-MM-DD.tgz -C /
   ```
3. `cairn migrate -config /etc/cairn/cairn.toml` (applies any newer schema; a
   same-version restore is a no-op).
4. Start, then verify: `cairn version`, `cairn pushcert check` (topics + expiry
   present), the dashboard device count matches, and a device Refresh round-trips.

**Restore invariants** (same as migration): the restored instance must answer at
the same public URL and keep the same APNs topic and device-identity trust, or
enrolled devices won't recognize it. A restore onto the *same* hostname with the
*same* DB satisfies all of these automatically.

## Upgrades

Cairn auto-applies embedded schema migrations on start (append-only; each runs
once). The safe upgrade is: back up (above) → replace the binary → restart →
verify. Roll back by restoring the binary and, only if a migration ran that the
old binary can't read, the pre-upgrade DB. Schema migrations are additive
(`ADD COLUMN`, new tables), so an older binary generally still reads a
newer DB, but back up first regardless.

## Schedule (recommendation)

Nightly `VACUUM INTO` + config tar to `/var/backups`, synced off-host (the
existing backup path / PBS). Keep ≥14 daily + ≥8 weekly. **Test a real restore
into a scratch instance quarterly** — an untested backup is a hope, not a backup.

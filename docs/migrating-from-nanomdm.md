# Migrating from NanoMDM (MySQL) to Cairn

`cairn import -from-mysql` moves an existing NanoMDM deployment into Cairn
with **zero device re-enrollment**. Devices keep checking in as if nothing
happened.

## The four invariants

Enrolled Apple devices pin four things at enrollment time. Break any one and
the whole fleet must re-enroll:

1. **APNs topic + push certificate.** The import copies your push cert/key.
   Renew it only as a renewal of the same certificate under the same Apple
   Account — a new cert means a new topic, which orphans every enrollment.
2. **The MDM server URL** (`ServerURL`/`CheckInURL` in the installed
   profiles). Cairn must be reachable at the exact same https URL after
   cutover — repoint DNS or your reverse proxy, never the devices.
3. **The device identity trust chain.** Run Cairn in the CA mode that matches
   how your devices got their certs (`external` pointing at the same SCEP
   server, or `import` with the same CA). The import copies the
   cert-hash associations that let existing certs authenticate.
4. **The SCEP renewal URL** baked into installed profiles — leave it serving.

## Procedure

1. **Freeze + drain.** Stop enqueueing commands on the old server and let
   devices drain the queue (the importer refuses a non-empty queue unless
   you pass `-allow-pending`, and queued commands are not migrated).
2. **Dry run** against the live source (read-only):

       cairn import -config cairn.toml -from-mysql 'nanomdm:pw@tcp(db:3306)/nanomdm' -dry-run

3. **Stop the old MDM server**, then run the real import:

       cairn import -config cairn.toml -from-mysql '...'

   The importer replays each device's stored Authenticate/TokenUpdate
   check-ins through Cairn's own storage — the same code path a live device
   takes — then **verifies**: every enabled enrollment's topic, push magic,
   and push token are re-read and compared to the source, and every
   certificate association is re-checked. Any mismatch fails the run with
   `DO NOT CUT OVER`.
4. **Repoint** the MDM hostname at Cairn.
5. **Prove it**: send a DeviceInformation to every device (ping-all) and
   watch for Acknowledged. Awake devices answer in seconds; sleeping ones
   within their next wake.
6. **Hold the old stack intact** (stopped) for your soak window. Rollback is
   repointing DNS back and starting it — the importer never writes to the
   source.

## What is not migrated

- Queued-but-undelivered commands (drain first).
- Command history and the old server's application state (users, web
  sessions, audit logs) — Cairn's console state starts fresh.

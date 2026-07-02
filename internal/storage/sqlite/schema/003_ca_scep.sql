-- 003_ca_scep: embedded SCEP certificate authority storage.
--
-- When ca.mode = embedded, Cairn runs its own SCEP CA and issues device
-- identity certificates. The CA key/cert live in the `ca` singleton row; issued
-- leaf certs and a monotonic serial counter live alongside. (In external-CA
-- mode these tables stay empty and enrollment points at a third-party SCEP
-- server such as OpenXPKI instead.)

CREATE TABLE ca (
    id         INTEGER PRIMARY KEY CHECK (id = 1),
    cert_pem   BLOB NOT NULL,
    key_pem    BLOB NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Autoincrement rowid gives monotonically increasing certificate serials.
CREATE TABLE scep_serials (
    serial     INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE scep_certs (
    serial     TEXT NOT NULL,
    name       TEXT NOT NULL,
    cert_pem   BLOB NOT NULL,
    not_after  TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (serial, name)
);

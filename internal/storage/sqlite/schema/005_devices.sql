-- 005_devices: the admin device inventory (a projection of check-in events).
--
-- NanoMDM's own storage holds the authoritative protocol state (tokens, certs,
-- queues). This table is a denormalized view for the admin UI, updated by the
-- EventService the moment a device enrolls, updates its token, checks in, or
-- checks out — so the console never polls devices or parses stored plists.

CREATE TABLE devices (
    id               TEXT PRIMARY KEY, -- enrollment ID (UDID on the device channel)
    udid             TEXT NOT NULL DEFAULT '',
    serial           TEXT NOT NULL DEFAULT '',
    name             TEXT NOT NULL DEFAULT '',
    model            TEXT NOT NULL DEFAULT '',
    product          TEXT NOT NULL DEFAULT '',
    os_version       TEXT NOT NULL DEFAULT '',
    build_version    TEXT NOT NULL DEFAULT '',
    enrolled_at      TEXT,
    last_seen        TEXT,
    token_updated_at TEXT,
    checked_out_at   TEXT
);

CREATE INDEX idx_devices_last_seen ON devices (last_seen);

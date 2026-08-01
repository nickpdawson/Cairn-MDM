-- 011_apns_topics: per-topic APNs push-certificate metadata (MDM-APNS-001).
--
-- NanoMDM already keys the stored push cert/key by APNs topic (StorePushCert),
-- but Cairn's layer used to model ONE global topic (cached in settings), so a
-- second fleet's certificate expiry was hidden behind whichever topic was
-- imported last. This table records one row per imported topic so the dashboard
-- can surface every fleet's expiry and renewal tier independently.
--
-- Rows are written by cmd/cairn/pushcert.go after push.LoadCert validates and
-- stores a certificate; the topic is the natural primary key, so re-importing a
-- renewed certificate for the same topic replaces the row (upsert).

CREATE TABLE apns_topics (
    topic     TEXT PRIMARY KEY,
    not_after TEXT NOT NULL,                        -- RFC3339 certificate expiry
    subject   TEXT,                                 -- certificate subject DN (informational)
    loaded_at TEXT DEFAULT (datetime('now')),
    loaded_by TEXT
);

-- 014_command_history_composite: fix command_history identity (MDM-REL-001).
--
-- 008 made command_uuid the sole PRIMARY KEY, but one command UUID is issued to
-- MANY devices. The recorder inserts one row per target device (all sharing the
-- UUID), so the ON CONFLICT dropped every row but the first, and result updates
-- could not tell which device a result belonged to. The identity is really the
-- pair (command_uuid, device_id).
--
-- SQLite cannot ALTER a PRIMARY KEY, so recreate the table preserving data.
-- Column order is kept identical to 008 so the SELECT * copy lines up. The
-- runner wraps this file in a transaction.

CREATE TABLE command_history_new (
    command_uuid TEXT NOT NULL,
    device_id    TEXT NOT NULL,
    request_type TEXT NOT NULL,
    status       TEXT NOT NULL DEFAULT 'Sent', -- Sent | Acknowledged | Error | NotNow | ...
    error        TEXT NOT NULL DEFAULT '',     -- first ErrorChain description, if any
    sent_at      TEXT NOT NULL DEFAULT (datetime('now')),
    result_at    TEXT,
    PRIMARY KEY (command_uuid, device_id)
);

INSERT INTO command_history_new SELECT * FROM command_history;

DROP TABLE command_history;

ALTER TABLE command_history_new RENAME TO command_history;

CREATE INDEX idx_command_history_device ON command_history (device_id, sent_at DESC);

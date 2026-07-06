-- 008_command_history: what was sent to which device and what came back.
--
-- Rows are written when the console/CLI enqueues a command and resolved when
-- the device reports results at check-in (via the EventService — no polling).
-- This is display/audit state; NanoMDM's queue remains the protocol source of
-- truth.

CREATE TABLE command_history (
    command_uuid TEXT PRIMARY KEY,
    device_id    TEXT NOT NULL,
    request_type TEXT NOT NULL,
    status       TEXT NOT NULL DEFAULT 'Sent', -- Sent | Acknowledged | Error | NotNow | ...
    error        TEXT NOT NULL DEFAULT '',     -- first ErrorChain description, if any
    sent_at      TEXT NOT NULL DEFAULT (datetime('now')),
    result_at    TEXT
);

CREATE INDEX idx_command_history_device ON command_history (device_id, sent_at DESC);

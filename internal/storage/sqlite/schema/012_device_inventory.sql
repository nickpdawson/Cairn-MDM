-- 012_device_inventory: ingest DeviceInformation query results (MDM-INV-001).
--
-- The console's "Refresh device info" button enqueues a DeviceInformation query,
-- but the returned QueryResponses were never parsed, so inventory only ever
-- reflected the Authenticate plist and went stale. The EventService now projects
-- QueryResponses onto the devices row; these columns record what it observed and
-- when.
--
-- inventory_at is the observed_at of the last DeviceInformation response and is
-- kept distinct from last_seen (any check-in) and token_updated_at. The two extra
-- columns surface the most-requested query values in the UI. All are additive —
-- existing columns are untouched (SQLite ALTER TABLE ADD COLUMN, no rewrite).

ALTER TABLE devices ADD COLUMN inventory_at TEXT;
ALTER TABLE devices ADD COLUMN available_capacity TEXT NOT NULL DEFAULT '';
ALTER TABLE devices ADD COLUMN battery TEXT NOT NULL DEFAULT '';

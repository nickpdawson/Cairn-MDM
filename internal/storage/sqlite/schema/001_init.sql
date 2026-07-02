-- 001_init: foundational app tables.
--
-- nanomdm/nanocmd/kmfddm/nanodep storage tables and Cairn's device/profile/
-- enrollment tables arrive in later migrations (Phase 1+). This first migration
-- establishes a key/value settings store used from Phase 0 onward (build stamp,
-- instance id, feature flags).

CREATE TABLE settings (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL,
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

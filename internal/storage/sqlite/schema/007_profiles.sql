-- 007_profiles: the configuration-profile library.
--
-- Profiles are stored as raw .mobileconfig bytes with the metadata the console
-- needs (parsed once at upload/build time). identifier is Apple's
-- PayloadIdentifier — the device-side primary key: installing a profile with an
-- existing identifier replaces it, which is what makes re-uploading a profile
-- an in-place update.

CREATE TABLE profiles (
    id            INTEGER PRIMARY KEY,
    identifier    TEXT NOT NULL UNIQUE, -- PayloadIdentifier
    uuid          TEXT NOT NULL,        -- PayloadUUID
    name          TEXT NOT NULL,        -- PayloadDisplayName
    organization  TEXT NOT NULL DEFAULT '',
    payload_types TEXT NOT NULL DEFAULT '', -- comma-joined inner PayloadTypes, for display
    source        TEXT NOT NULL DEFAULT 'upload', -- upload | builder:wifi | builder:kerberos-sso
    data          BLOB NOT NULL,
    created_at    TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at    TEXT NOT NULL DEFAULT (datetime('now'))
);

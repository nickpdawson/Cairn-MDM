-- 009_groups: device groups, profile assignments, and deploy tracking.
--
-- Assignment model: profiles are assigned to groups; devices are members of
-- groups; the effective profile set for a device is the union across its
-- groups. profile_deploys records what the reconciler has pushed where, so a
-- device is only sent a profile once per profile version (re-uploading a
-- profile bumps updated_at, which re-arms the deploy).

CREATE TABLE groups (
    id          INTEGER PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE COLLATE NOCASE,
    description TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE group_devices (
    group_id  INTEGER NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    device_id TEXT NOT NULL,
    PRIMARY KEY (group_id, device_id)
);
CREATE INDEX idx_group_devices_device ON group_devices (device_id);

CREATE TABLE group_profiles (
    group_id   INTEGER NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    profile_id INTEGER NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
    PRIMARY KEY (group_id, profile_id)
);

CREATE TABLE profile_deploys (
    device_id          TEXT NOT NULL,
    profile_id         INTEGER NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
    command_uuid       TEXT NOT NULL DEFAULT '',
    profile_updated_at TEXT NOT NULL DEFAULT '', -- profiles.updated_at captured at send time
    status             TEXT NOT NULL DEFAULT 'sent', -- sent | installed | failed
    updated_at         TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (device_id, profile_id)
);
CREATE INDEX idx_profile_deploys_command ON profile_deploys (command_uuid);

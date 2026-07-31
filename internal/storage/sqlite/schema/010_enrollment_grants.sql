-- 010_enrollment_grants: single-use, expiring authorizations to enroll a device.
--
-- Replaces the reusable unauthenticated /enroll. Only token_hash is stored
-- (sha256 hex); the raw token is shown once at creation, like session tokens.
-- Redemption is a single atomic UPDATE (see grants.go) so concurrent redeems
-- of a max_uses=1 grant cannot double-spend.

CREATE TABLE enrollment_grants (
    id              INTEGER PRIMARY KEY,
    token_hash      TEXT NOT NULL UNIQUE,
    label           TEXT NOT NULL DEFAULT '',
    platform        TEXT NOT NULL DEFAULT 'any',  -- any | macos | ios
    owner           TEXT NOT NULL DEFAULT '',     -- rfc822/UPN of the device's AD user; flows to cert SAN
    created_by      TEXT NOT NULL DEFAULT '',
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    expires_at      TEXT NOT NULL,
    max_uses        INTEGER NOT NULL DEFAULT 1,
    use_count       INTEGER NOT NULL DEFAULT 0,
    revoked_at      TEXT,
    expected_serial TEXT NOT NULL DEFAULT '',
    last_used_at    TEXT
);

CREATE INDEX idx_grants_expires ON enrollment_grants (expires_at);

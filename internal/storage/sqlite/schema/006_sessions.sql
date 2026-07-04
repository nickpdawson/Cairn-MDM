-- 006_sessions: server-side admin sessions.
--
-- Sessions are DB-backed (not signed cookies) so they can be revoked and so the
-- role is snapshotted server-side. The cookie carries only the opaque token.

CREATE TABLE app_sessions (
    token        TEXT PRIMARY KEY, -- opaque random session id (hex)
    username     TEXT NOT NULL,
    role         TEXT NOT NULL,
    display_name TEXT NOT NULL DEFAULT '',
    provider     TEXT NOT NULL DEFAULT 'local',
    csrf_token   TEXT NOT NULL,
    created_at   TEXT NOT NULL DEFAULT (datetime('now')),
    expires_at   TEXT NOT NULL
);

CREATE INDEX idx_sessions_expires ON app_sessions (expires_at);

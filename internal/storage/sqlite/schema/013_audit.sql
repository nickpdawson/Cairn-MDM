-- 013_audit: append-only audit log for security-sensitive admin actions.
--
-- The review flagged "no audit log for security-sensitive actions". Cairn's web
-- layer records one row here for every mutating admin request (POST/PUT/DELETE
-- under /admin, plus /login and /logout) via a middleware, AFTER the handler
-- runs. The table is treated as append-only: the app only ever INSERTs and
-- SELECTs — there is no update/delete path in code.
--
-- Deliberately narrow columns: the request PATH is stored as `target`, never the
-- query string and never the body, so no secrets (passwords, CSRF tokens,
-- profile payloads) land in the log.

CREATE TABLE audit_log (
    id       INTEGER PRIMARY KEY,
    at       TEXT NOT NULL DEFAULT (datetime('now')), -- UTC timestamp
    username TEXT,                                     -- actor (empty for anon/login)
    provider TEXT,                                     -- auth provider of the actor
    action   TEXT NOT NULL,                            -- HTTP method
    target   TEXT,                                     -- request path (no query, no body)
    result   TEXT,                                     -- response status code
    remote   TEXT                                      -- client IP (host of RemoteAddr)
);

-- The activity page lists newest first; index the timestamp descending.
CREATE INDEX idx_audit_log_at ON audit_log (at DESC);

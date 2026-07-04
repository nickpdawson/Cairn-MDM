-- 004_app_users: local administrator/operator/user accounts.
--
-- Roles are ALWAYS explicit — there is no code path where "authenticated"
-- implies "admin" (the structural fix for v1's any-Kerberos-user-is-admin bug).
-- External auth providers (OIDC/LDAP/Kerberos) map their groups to these same
-- roles in later phases; local accounts are the always-available break-glass path.

CREATE TABLE app_users (
    username      TEXT PRIMARY KEY,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL DEFAULT 'user',
    display_name  TEXT NOT NULL DEFAULT '',
    created_at    TEXT NOT NULL DEFAULT (datetime('now'))
);

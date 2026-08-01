-- 015_cert_auth: native multi-hash certificate-authentication associations.
--
-- NanoMDM's KV certauth backend stores only ONE hash per enrollment (each
-- AssociateCertHash overwrites the last). That is fine for live operation — a
-- device's current cert is always the most-recently-associated — but WRONG for
-- migrating a fleet: a device that renewed its SCEP cert carries several
-- historical hashes in the source, and ALL of them must stay valid or the
-- device fails to authenticate when it presents whichever cert it currently
-- holds. This table keeps every (enrollment, hash) pair; IsCertHashAssociated
-- becomes a set-membership test (see certauth.go).

CREATE TABLE cert_auth (
    enrollment_id TEXT NOT NULL,
    sha256        TEXT NOT NULL,
    created_at    TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (enrollment_id, sha256)
);
CREATE INDEX idx_cert_auth_hash ON cert_auth (sha256);

-- Backfill the single association each already-enrolled device has in the KV
-- bucket, so upgrading in place does not drop existing devices' auth. The KV
-- forward key is "<enrollment_id>.cert_hash" with the hash string as its value.
INSERT OR IGNORE INTO cert_auth (enrollment_id, sha256)
SELECT substr(k, 1, length(k) - length('.cert_hash')) AS enrollment_id,
       CAST(v AS TEXT)                                AS sha256
FROM nano_kv
WHERE bucket = 'certauth' AND k LIKE '%.cert_hash';

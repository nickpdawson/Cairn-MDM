-- 002_nano_kv: the key-value table backing NanoMDM's storage.
--
-- NanoMDM's storage/kv package implements the full AllStorage interface on top
-- of six key-value buckets. Rather than transliterate NanoMDM's MySQL queries
-- (and risk getting the subtle certauth/queue/NotNow semantics wrong), Cairn
-- backs those buckets with this one table and lets NanoMDM's own kv layer do
-- the protocol bookkeeping. This is the same shape as NanoLib's persistent
-- kvdiskv backend, just stored in SQLite instead of on disk.

CREATE TABLE nano_kv (
    bucket TEXT NOT NULL,
    k      TEXT NOT NULL,
    v      BLOB NOT NULL,
    PRIMARY KEY (bucket, k)
) WITHOUT ROWID;

-- The owner serializes canonical snapshot publication on this row before it
-- reads the decision graph. Version zero is a transaction-local bootstrap.
CREATE TABLE IF NOT EXISTS trust_profile_service.credential_authority_revisions (
    profile_id TEXT PRIMARY KEY REFERENCES trust_profile_service.trust_profiles(id) ON DELETE CASCADE,
    version BIGINT NOT NULL DEFAULT 0 CHECK (version BETWEEN 0 AND 4294967295),
    content_digest TEXT,
    observed_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CHECK (
        (version = 0 AND content_digest IS NULL)
        OR (version > 0 AND content_digest IS NOT NULL AND content_digest ~ '^sha256:[0-9a-f]{64}$')
    )
);

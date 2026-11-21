-- A distinct selected-profile revision namespace. Existing SD-JWT and wallet
-- authority contracts and their persisted revisions remain unchanged.
CREATE TABLE IF NOT EXISTS trust_profile_service.machine_jwt_vc_authority_revisions (
    profile_id TEXT PRIMARY KEY REFERENCES trust_profile_service.trust_profiles(id) ON DELETE CASCADE,
    version BIGINT NOT NULL DEFAULT 0 CHECK (version BETWEEN 0 AND 9007199254740991),
    content_digest TEXT,
    observed_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT machine_jwt_vc_authority_revision_content CHECK (
        (version = 0 AND content_digest IS NULL)
        OR (version > 0 AND content_digest IS NOT NULL AND content_digest ~ '^sha256:[0-9a-f]{64}$')
    )
);

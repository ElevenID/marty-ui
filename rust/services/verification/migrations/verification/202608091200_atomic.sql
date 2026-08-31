ALTER TABLE public.verification_sessions
    ADD COLUMN IF NOT EXISTS submission_sha256 VARCHAR(64);
ALTER TABLE public.verification_sessions
    ADD COLUMN IF NOT EXISTS processing_token_sha256 VARCHAR(64);
ALTER TABLE public.verification_sessions
    ADD COLUMN IF NOT EXISTS processing_started_at TIMESTAMP WITHOUT TIME ZONE;
ALTER TABLE public.verification_sessions
    ADD COLUMN IF NOT EXISTS processing_expires_at TIMESTAMP WITHOUT TIME ZONE;

UPDATE public.verification_sessions
SET submission_sha256 = lower(verification_evidence->>'presentation_sha256')
WHERE upper(status) IN ('VERIFIED', 'FAILED')
  AND verification_evidence->>'presentation_sha256' ~ '^[0-9A-Fa-f]{64}$';

-- Terminal decisions stay immutable; retire any historical terminal nonce.
UPDATE public.verification_sessions
SET nonce = NULL,
    processing_token_sha256 = NULL,
    processing_started_at = NULL,
    processing_expires_at = NULL
WHERE upper(status) IN ('VERIFIED', 'FAILED', 'EXPIRED');

UPDATE public.verification_sessions
SET status = 'EXPIRED',
    nonce = NULL,
    updated_at = clock_timestamp() AT TIME ZONE 'UTC',
    error_message = 'Verification session had no valid nonce during atomic migration'
WHERE upper(status) IN ('PENDING', 'IN_PROGRESS')
  AND (nonce IS NULL OR length(nonce) <> 43);

WITH duplicate_nonces AS (
    SELECT nonce
    FROM public.verification_sessions
    WHERE nonce IS NOT NULL
      AND upper(status) IN ('PENDING', 'IN_PROGRESS')
    GROUP BY nonce
    HAVING count(*) > 1
)
UPDATE public.verification_sessions AS sessions
SET status = 'EXPIRED',
    nonce = NULL,
    updated_at = clock_timestamp() AT TIME ZONE 'UTC',
    error_message = 'Verification session nonce was not unique during atomic migration'
FROM duplicate_nonces
WHERE sessions.nonce = duplicate_nonces.nonce
  AND upper(sessions.status) IN ('PENDING', 'IN_PROGRESS');

UPDATE public.verification_sessions
SET status = 'EXPIRED',
    nonce = NULL,
    processing_token_sha256 = NULL,
    processing_started_at = NULL,
    processing_expires_at = NULL,
    updated_at = clock_timestamp() AT TIME ZONE 'UTC',
    error_message = 'Verification session expired before atomic migration'
WHERE upper(status) IN ('PENDING', 'IN_PROGRESS')
  AND expires_at IS NOT NULL
  AND expires_at <= clock_timestamp() AT TIME ZONE 'UTC';

-- Legacy in-progress workers have no authenticated digest/token fence.
UPDATE public.verification_sessions
SET status = 'EXPIRED',
    nonce = NULL,
    processing_token_sha256 = NULL,
    processing_started_at = NULL,
    processing_expires_at = NULL,
    updated_at = clock_timestamp() AT TIME ZONE 'UTC',
    error_message = 'Verification interrupted before atomic session migration'
WHERE upper(status) = 'IN_PROGRESS';

DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'ck_verification_nonce_length' AND conrelid = 'public.verification_sessions'::regclass) THEN
        ALTER TABLE public.verification_sessions ADD CONSTRAINT ck_verification_nonce_length
            CHECK (nonce IS NULL OR length(nonce) = 43);
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'ck_verification_submission_digest' AND conrelid = 'public.verification_sessions'::regclass) THEN
        ALTER TABLE public.verification_sessions ADD CONSTRAINT ck_verification_submission_digest
            CHECK (submission_sha256 IS NULL OR submission_sha256 ~ '^[0-9a-f]{64}$');
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'ck_verification_processing_token_digest' AND conrelid = 'public.verification_sessions'::regclass) THEN
        ALTER TABLE public.verification_sessions ADD CONSTRAINT ck_verification_processing_token_digest
            CHECK (processing_token_sha256 IS NULL OR processing_token_sha256 ~ '^[0-9a-f]{64}$');
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'ck_verification_processing_lease' AND conrelid = 'public.verification_sessions'::regclass) THEN
        ALTER TABLE public.verification_sessions ADD CONSTRAINT ck_verification_processing_lease
            CHECK (processing_started_at IS NULL OR processing_expires_at > processing_started_at);
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'ck_verification_atomic_state' AND conrelid = 'public.verification_sessions'::regclass) THEN
        ALTER TABLE public.verification_sessions ADD CONSTRAINT ck_verification_atomic_state CHECK (
            (upper(status) = 'PENDING' AND nonce IS NOT NULL
             AND submission_sha256 IS NULL AND processing_token_sha256 IS NULL
             AND processing_started_at IS NULL AND processing_expires_at IS NULL)
            OR
            (upper(status) = 'IN_PROGRESS' AND nonce IS NOT NULL
             AND submission_sha256 IS NOT NULL AND processing_token_sha256 IS NOT NULL
             AND processing_started_at IS NOT NULL AND processing_expires_at IS NOT NULL)
            OR
            (upper(status) IN ('VERIFIED', 'FAILED') AND nonce IS NULL
             AND processing_token_sha256 IS NULL
             AND processing_started_at IS NULL AND processing_expires_at IS NULL)
            OR
            (upper(status) = 'EXPIRED' AND nonce IS NULL
             AND processing_token_sha256 IS NULL
             AND processing_started_at IS NULL AND processing_expires_at IS NULL)
        );
    END IF;
END $$;

CREATE UNIQUE INDEX IF NOT EXISTS ux_verification_sessions_live_nonce
    ON public.verification_sessions (nonce)
    WHERE nonce IS NOT NULL;

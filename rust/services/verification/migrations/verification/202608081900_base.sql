CREATE TABLE IF NOT EXISTS public.verification_sessions (
    id VARCHAR PRIMARY KEY,
    organization_id VARCHAR NOT NULL,
    verifier_did VARCHAR NOT NULL,
    presentation_definition JSONB NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'PENDING',
    required_credential_types JSONB,
    trusted_issuers JSONB,
    required_claims JSONB,
    presentation_data JSONB,
    verified_claims JSONB,
    verification_evidence JSONB NOT NULL DEFAULT '{}'::jsonb,
    verification_method VARCHAR(32),
    verified_at TIMESTAMP WITHOUT TIME ZONE,
    created_at TIMESTAMP WITHOUT TIME ZONE NOT NULL,
    updated_at TIMESTAMP WITHOUT TIME ZONE NOT NULL,
    expires_at TIMESTAMP WITHOUT TIME ZONE,
    error_message TEXT,
    request_uri VARCHAR,
    nonce VARCHAR
);

ALTER TABLE public.verification_sessions
    ADD COLUMN IF NOT EXISTS verification_evidence JSONB NOT NULL DEFAULT '{}'::jsonb;
UPDATE public.verification_sessions
    SET verification_evidence = '{}'::jsonb
    WHERE verification_evidence IS NULL;
ALTER TABLE public.verification_sessions
    ALTER COLUMN verification_evidence SET DEFAULT '{}'::jsonb;
ALTER TABLE public.verification_sessions
    ALTER COLUMN verification_evidence SET NOT NULL;
CREATE INDEX IF NOT EXISTS ix_verification_sessions_organization_id
    ON public.verification_sessions (organization_id);
CREATE INDEX IF NOT EXISTS ix_verification_sessions_nonce
    ON public.verification_sessions (nonce);

-- Raw credential-bearing presentations are irrecoverably minimized.
UPDATE public.verification_sessions
    SET presentation_data = NULL
    WHERE presentation_data IS NOT NULL;

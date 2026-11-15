-- Additive, opt-in state. NULL preserves every historical transaction.
ALTER TABLE issuance_service.issuance_transactions
    ADD COLUMN IF NOT EXISTS jwt_vc_profile jsonb,
    ADD COLUMN IF NOT EXISTS jwt_vc_signing_timing jsonb;

-- The check is one fixed call so read-only schema verification can bind
-- both its exact arguments and the complete predicate source.
CREATE OR REPLACE FUNCTION issuance_service.issuance_explicit_jwt_vc_profile_valid(
    jwt_vc_profile jsonb,
    jwt_vc_signing_timing jsonb,
    credential_payload_format text,
    credential_type text,
    credential_template_id text,
    application_id text,
    renewal_of_credential_id text,
    delivery_mode text,
    wallet_configs jsonb,
    renewable boolean,
    status text
) RETURNS boolean LANGUAGE plpgsql IMMUTABLE SECURITY INVOKER AS $profile_check$
BEGIN
    RETURN ((
                (jwt_vc_profile IS NULL AND jwt_vc_signing_timing IS NULL
                    AND credential_payload_format <> 'VC_JWT_DIRECT_V1')
                OR
                (credential_payload_format = 'VC_JWT_DIRECT_V1'
                    AND jsonb_typeof(jwt_vc_profile) = 'object'
                    AND jwt_vc_profile - ARRAY['contract', 'policy', 'credential_configuration_id', 'credential_format',
                        'credential_type', 'template_id', 'template_version', 'credential_validity_seconds', 'not_before_offset_seconds'] = '{}'::jsonb
                    AND jwt_vc_profile->>'contract' = 'marty.jwt-vc-issuance-selection/v1'
                    AND jwt_vc_profile->>'credential_format' = 'application/vc+jwt'
                    AND jwt_vc_profile->>'credential_type' = credential_type
                    AND jwt_vc_profile->>'template_id' = credential_template_id
                    AND jwt_vc_profile->>'credential_configuration_id' = credential_type || '#vc2-jose-2026-v1'
                    AND (jwt_vc_profile->>'template_version')::integer > 0
                    AND (jwt_vc_profile->>'credential_validity_seconds')::bigint BETWEEN 1 AND 94608000
                    AND (jwt_vc_profile->>'not_before_offset_seconds')::bigint BETWEEN -94608000 AND 94608000
                    AND jwt_vc_profile->'policy'->>'contract' = 'marty.jwt-vc-template-profile/v1'
                    AND jwt_vc_profile->'policy'->>'securing_profile' = 'w3c_vc2_jose_2026_v1'
                    AND (jwt_vc_profile->'policy'->>'signature_lifetime_seconds')::bigint BETWEEN 1 AND 31622400
                    AND (jwt_vc_profile->>'not_before_offset_seconds')::bigint < (jwt_vc_profile->'policy'->>'signature_lifetime_seconds')::bigint
                    AND (jwt_vc_profile->>'not_before_offset_seconds')::bigint + (jwt_vc_profile->>'credential_validity_seconds')::bigint > 0
                    AND application_id IS NULL AND renewal_of_credential_id IS NULL
                    AND delivery_mode = 'wallet_only' AND wallet_configs::jsonb = '[]'::jsonb AND NOT renewable
                    AND (
                        (jwt_vc_signing_timing IS NULL AND status NOT IN ('signing', 'issued'))
                        OR
                        (status NOT IN ('pending', 'authorized')
                            AND jsonb_typeof(jwt_vc_signing_timing) = 'object'
                            AND jwt_vc_signing_timing - ARRAY['signature_issued_at', 'signature_expires_at', 'credential_valid_from', 'credential_valid_until'] = '{}'::jsonb
                            AND (jwt_vc_signing_timing->>'signature_issued_at')::bigint > 0
                            AND (jwt_vc_signing_timing->>'signature_expires_at')::bigint =
                                (jwt_vc_signing_timing->>'signature_issued_at')::bigint + (jwt_vc_profile->'policy'->>'signature_lifetime_seconds')::bigint
                            AND jwt_vc_signing_timing->>'credential_valid_from' ~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]+)?(Z|[+-][0-9]{2}:[0-9]{2})$'
                            AND (jwt_vc_signing_timing->>'credential_valid_from')::timestamptz =
                                to_timestamp((jwt_vc_signing_timing->>'signature_issued_at')::bigint) + (jwt_vc_profile->>'not_before_offset_seconds')::bigint * interval '1 second'
                            AND jwt_vc_signing_timing->>'credential_valid_until' ~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]+)?(Z|[+-][0-9]{2}:[0-9]{2})$'
                            AND (jwt_vc_signing_timing->>'credential_valid_until')::timestamptz =
                                (jwt_vc_signing_timing->>'credential_valid_from')::timestamptz + (jwt_vc_profile->>'credential_validity_seconds')::bigint * interval '1 second')
                    ))
            ) IS TRUE);
END;
$profile_check$;

DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'ck_issuance_explicit_jwt_vc_profile'
        AND conrelid = 'issuance_service.issuance_transactions'::regclass) THEN
        ALTER TABLE issuance_service.issuance_transactions
            ADD CONSTRAINT ck_issuance_explicit_jwt_vc_profile CHECK (issuance_service.issuance_explicit_jwt_vc_profile_valid(jwt_vc_profile::jsonb, jwt_vc_signing_timing::jsonb, credential_payload_format::text, credential_type::text, credential_template_id::text, application_id::text, renewal_of_credential_id::text, delivery_mode::text, wallet_configs::jsonb, renewable, status::text) IS TRUE);
    END IF;
END $$;

CREATE OR REPLACE FUNCTION issuance_service.guard_explicit_jwt_vc_transaction()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'UPDATE' THEN
        IF OLD.jwt_vc_profile IS DISTINCT FROM NEW.jwt_vc_profile THEN
            RAISE EXCEPTION 'explicit JWT-VC selection is immutable';
        END IF;
        IF OLD.jwt_vc_signing_timing IS NOT NULL
            AND OLD.jwt_vc_signing_timing IS DISTINCT FROM NEW.jwt_vc_signing_timing THEN
            RAISE EXCEPTION 'explicit JWT-VC signing time is immutable';
        END IF;
        IF OLD.jwt_vc_signing_timing IS NULL AND NEW.jwt_vc_signing_timing IS NOT NULL
            AND NOT (OLD.status = 'authorized' AND NEW.status = 'signing') THEN
            RAISE EXCEPTION 'explicit JWT-VC time requires the signing claim';
        END IF;
    ELSIF NEW.jwt_vc_signing_timing IS NOT NULL THEN
        RAISE EXCEPTION 'explicit JWT-VC time cannot be supplied at reservation';
    END IF;
    -- Cover old code and already-created authorization sessions as well as
    -- current adapters. Pre-authorized issuance has no authorization session.
    IF NEW.access_token IS NOT NULL AND EXISTS (
        SELECT 1 FROM issuance_service.authorization_sessions session
        WHERE session.access_token = NEW.access_token
          AND (NEW.jwt_vc_profile IS NOT NULL OR EXISTS (
            SELECT 1 FROM jsonb_array_elements_text(session.credential_configuration_ids::jsonb) config(id)
            WHERE right(config.id, length('#vc2-jose-2026-v1')) = '#vc2-jose-2026-v1'))
    ) THEN
        RAISE EXCEPTION 'explicit JWT-VC authorization-code issuance is unsupported';
    END IF;
    RETURN NEW;
END;
$$;
DROP TRIGGER IF EXISTS guard_explicit_jwt_vc_transaction ON issuance_service.issuance_transactions;
CREATE TRIGGER guard_explicit_jwt_vc_transaction BEFORE INSERT OR UPDATE
ON issuance_service.issuance_transactions FOR EACH ROW
EXECUTE FUNCTION issuance_service.guard_explicit_jwt_vc_transaction();

CREATE OR REPLACE FUNCTION issuance_service.guard_explicit_jwt_vc_authorization()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF EXISTS (SELECT 1 FROM jsonb_array_elements_text(NEW.credential_configuration_ids::jsonb) config(id)
        WHERE right(config.id, length('#vc2-jose-2026-v1')) = '#vc2-jose-2026-v1')
        OR EXISTS (SELECT 1 FROM issuance_service.issuance_transactions tx
            WHERE tx.pre_auth_code = NEW.issuer_state AND tx.jwt_vc_profile IS NOT NULL) THEN
        RAISE EXCEPTION 'explicit JWT-VC requires pre-authorized issuance';
    END IF;
    RETURN NEW;
END;
$$;
DROP TRIGGER IF EXISTS guard_explicit_jwt_vc_authorization ON issuance_service.authorization_sessions;
CREATE TRIGGER guard_explicit_jwt_vc_authorization BEFORE INSERT OR UPDATE
ON issuance_service.authorization_sessions FOR EACH ROW
EXECUTE FUNCTION issuance_service.guard_explicit_jwt_vc_authorization();

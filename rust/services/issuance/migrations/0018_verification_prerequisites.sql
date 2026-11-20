-- The immutable intent exists before a Flow request or credential offer is
-- exposed. Legacy transactions remain NULL, unless their saved template has
-- explicitly selected the guarded lifecycle namespace.
ALTER TABLE issuance_service.issuance_transactions
    ADD COLUMN IF NOT EXISTS issuance_intent jsonb;

-- A continuation is acquired over the authenticated Flow owner channel and
-- inserted consumed in the same transaction as the signing claim. Public JSON
-- and digests cannot create the Rust acquisition capability. Keeping this
-- receipt immutable while usable makes retries reuse the original credential
-- reservation. Terminal, fully expired receipts may be removed by retention.
CREATE TABLE IF NOT EXISTS issuance_service.issuance_prerequisite_continuations (
    transaction_id text PRIMARY KEY REFERENCES issuance_service.issuance_transactions(id),
    organization_id text NOT NULL,
    intent_digest text NOT NULL UNIQUE CHECK (intent_digest ~ '^sha256:[0-9a-f]{64}$'),
    evidence_digest text NOT NULL UNIQUE CHECK (evidence_digest ~ '^sha256:[0-9a-f]{64}$'),
    flow_instance_id text NOT NULL UNIQUE,
    holder_key_thumbprint text NOT NULL CHECK (holder_key_thumbprint ~ '^[A-Za-z0-9_-]{43}$'),
    credential_id text NOT NULL UNIQUE,
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz NOT NULL,
    CHECK (created_at = consumed_at AND consumed_at < expires_at)
);

CREATE OR REPLACE FUNCTION issuance_service.guard_verification_prerequisite_transaction()
RETURNS trigger LANGUAGE plpgsql AS $prerequisite_transaction$
DECLARE
    saved_template jsonb;
    other_tenant_template jsonb;
    intent jsonb := NEW.issuance_intent;
    guarded boolean;
    continuation issuance_service.issuance_prerequisite_continuations%ROWTYPE;
BEGIN
    IF TG_OP = 'UPDATE' AND OLD.issuance_intent IS DISTINCT FROM intent THEN
        RAISE EXCEPTION 'issuing intent is immutable';
    END IF;
    -- Dynamic lookup lets an unconfigured legacy Issuance owner migrate before
    -- the template owner. A supplied intent always requires the saved owner row.
    -- FOR SHARE also serializes template edits with admission/signing.
    IF to_regclass('credential_template_service.credential_templates') IS NOT NULL THEN
        EXECUTE 'SELECT to_jsonb(template) FROM credential_template_service.credential_templates template
                 WHERE template.id::text=$1 AND template.organization_id::text=$2 FOR SHARE'
            INTO saved_template USING NEW.credential_template_id, NEW.organization_id;
        IF saved_template IS NULL THEN
            -- Template IDs are globally unique. An absent legacy reference can
            -- remain compatible, but a known guarded ID cannot evade its
            -- prerequisite by supplying a different tenant and omitting intent.
            EXECUTE 'SELECT to_jsonb(template) FROM credential_template_service.credential_templates template
                     WHERE template.id::text=$1 FOR SHARE'
                INTO other_tenant_template USING NEW.credential_template_id;
            IF COALESCE(other_tenant_template->>'status' LIKE 'prerequisite1_%', false)
                OR COALESCE(other_tenant_template->'verification_prerequisite' <> 'null'::jsonb, false) THEN
                RAISE EXCEPTION 'verification prerequisite template belongs to another organization';
            END IF;
        END IF;
    END IF;
    guarded := COALESCE(saved_template->>'status' LIKE 'prerequisite1_%', false)
        OR COALESCE(saved_template->'verification_prerequisite' <> 'null'::jsonb, false);
    IF intent IS NULL AND NOT guarded THEN
        RETURN NEW;
    END IF;
    IF intent IS NULL OR saved_template IS NULL
        OR saved_template->'verification_prerequisite' IS NULL
        OR saved_template->'verification_prerequisite' = 'null'::jsonb
        OR saved_template->>'status' NOT IN ('prerequisite1_active', 'prerequisite1_deprecated', 'prerequisite1_archived') THEN
        RAISE EXCEPTION 'saved verification prerequisite and issuing intent are required';
    END IF;
    IF (TG_OP = 'INSERT' OR NEW.status = 'signing')
        AND saved_template->>'status' <> 'prerequisite1_active' THEN
        RAISE EXCEPTION 'verification prerequisite template is not active';
    END IF;
    IF NOT ((
        jsonb_typeof(intent) = 'object' AND octet_length(intent::text) <= 16384
        AND intent ?& ARRAY['contract','organization_id','transaction_id','initiating_principal_id','applicant_id','application_id','subject_did',
            'credential_template_id','credential_template_version','credential_configuration_id','credential_payload_format','issuer_did','dataset_digest',
            'prerequisite','flow_instance_id','created_at_epoch_micros','expires_at_epoch_micros','intent_digest']
        AND intent - ARRAY['contract','organization_id','transaction_id','initiating_principal_id','applicant_id','application_id','subject_did',
            'credential_template_id','credential_template_version','credential_configuration_id','credential_payload_format','issuer_did','dataset_digest',
            'prerequisite','flow_instance_id','created_at_epoch_micros','expires_at_epoch_micros','intent_digest'] = '{}'::jsonb
        AND intent->>'contract' = 'marty.issuance-intent/v1'
        AND intent->>'organization_id' = NEW.organization_id
        AND intent->>'transaction_id' = NEW.id
        AND intent->>'credential_template_id' = NEW.credential_template_id
        AND jsonb_typeof(intent->'credential_template_version') = 'number'
        AND intent->'credential_template_version' = saved_template->'version'
        AND intent->'prerequisite' = saved_template->'verification_prerequisite'
        AND intent->>'credential_configuration_id' = NEW.credential_type || '#sd-jwt'
        AND intent->>'credential_payload_format' = 'SD_JWT_VC'
        AND NEW.credential_payload_format = 'SD_JWT_VC'
        AND saved_template->>'credential_payload_format' = 'SD_JWT_VC'
        AND saved_template->>'issuance_protocol' = 'OID4VCI_PRE_AUTH'
        AND intent->>'issuer_did' = NEW.issuer_did_override
        AND NEW.issuer_did_override = saved_template->>'issuer_did'
        AND (intent->>'applicant_id') IS NOT DISTINCT FROM NEW.applicant_id
        AND (intent->>'application_id') IS NOT DISTINCT FROM NEW.application_id
        AND (intent->>'subject_did') IS NOT DISTINCT FROM NEW.subject_did
        AND jsonb_typeof(intent->'created_at_epoch_micros') = 'number'
        AND (intent->>'created_at_epoch_micros')::numeric = extract(epoch FROM NEW.created_at) * 1000000
        AND jsonb_typeof(intent->'expires_at_epoch_micros') = 'number'
        AND (intent->>'expires_at_epoch_micros')::numeric = extract(epoch FROM NEW.expires_at) * 1000000
        AND NEW.expires_at > NEW.created_at
        AND NEW.expires_at <= NEW.created_at + (intent->'prerequisite'->>'ttl_seconds')::integer * interval '1 second'
        AND intent->>'dataset_digest' ~ '^sha256:[0-9a-f]{64}$'
        AND intent->>'intent_digest' ~ '^sha256:[0-9a-f]{64}$'
        AND jsonb_typeof(intent->'initiating_principal_id') = 'string'
        AND octet_length(intent->>'initiating_principal_id') BETWEEN 1 AND 255
        AND btrim(intent->>'initiating_principal_id') = intent->>'initiating_principal_id'
        AND (intent->>'initiating_principal_id') !~ '[[:cntrl:]]'
        AND jsonb_typeof(intent->'flow_instance_id') = 'string'
        AND octet_length(intent->>'flow_instance_id') BETWEEN 1 AND 255
        AND (intent->>'flow_instance_id') !~ '[[:cntrl:]]'
        AND NEW.application_id IS NULL AND NEW.renewal_of_credential_id IS NULL
        AND NEW.oid4vci_client_id IS NULL AND NOT NEW.renewable
        AND NEW.delivery_mode = 'wallet_only' AND NEW.wallet_configs::jsonb = '[]'::jsonb
        AND NEW.jwt_vc_profile IS NULL AND NEW.jwt_vc_signing_timing IS NULL
    ) IS TRUE) THEN
        RAISE EXCEPTION 'issuing intent does not match its saved template and transaction';
    END IF;
    IF NEW.access_token IS NOT NULL AND EXISTS (
        SELECT 1 FROM issuance_service.authorization_sessions session
        WHERE session.access_token = NEW.access_token
    ) THEN
        RAISE EXCEPTION 'verification prerequisite requires pre-authorized issuance';
    END IF;
    IF TG_OP = 'INSERT' THEN
        IF NEW.status <> 'pending' OR NEW.reserved_credential_id IS NOT NULL
            OR NEW.expires_at <= clock_timestamp() OR NEW.created_at > clock_timestamp() + interval '5 seconds' THEN
            RAISE EXCEPTION 'issuing intent requires a fresh pending reservation';
        END IF;
    ELSE
        IF (OLD.claims::jsonb - '_dpop_jkt') IS DISTINCT FROM (NEW.claims::jsonb - '_dpop_jkt')
            OR ROW(OLD.credential_type, OLD.selective_disclosure_claims::jsonb, OLD.zk_predicate_claims::jsonb,
                OLD.validity_days, OLD.revocation_profile_id, OLD.issuer_profile_id, OLD.issuer_mode,
                OLD.issuer_algorithm, OLD.signing_service_id, OLD.pre_auth_code,
                OLD.idempotency_key_hash, OLD.idempotency_request_hash)
            IS DISTINCT FROM ROW(NEW.credential_type, NEW.selective_disclosure_claims::jsonb, NEW.zk_predicate_claims::jsonb,
                NEW.validity_days, NEW.revocation_profile_id, NEW.issuer_profile_id, NEW.issuer_mode,
                NEW.issuer_algorithm, NEW.signing_service_id, NEW.pre_auth_code,
                NEW.idempotency_key_hash, NEW.idempotency_request_hash) THEN
            RAISE EXCEPTION 'issuing dataset and issuer selection are immutable';
        END IF;
        IF OLD.reserved_credential_id IS NOT NULL AND OLD.reserved_credential_id IS DISTINCT FROM NEW.reserved_credential_id THEN
            RAISE EXCEPTION 'prerequisite credential reservation is immutable';
        END IF;
        IF OLD.reserved_credential_id IS NOT NULL AND NEW.status IN ('pending', 'authorized') THEN
            RAISE EXCEPTION 'consumed verification continuation cannot return to an unclaimed state';
        END IF;
    END IF;
    IF NEW.status IN ('signing', 'issued') THEN
        SELECT * INTO continuation FROM issuance_service.issuance_prerequisite_continuations
            WHERE transaction_id = NEW.id AND organization_id = NEW.organization_id
                AND intent_digest = intent->>'intent_digest' AND flow_instance_id = intent->>'flow_instance_id'
                AND credential_id = NEW.reserved_credential_id;
        IF NOT FOUND OR continuation.consumed_at IS NULL THEN
            RAISE EXCEPTION 'signing requires the consumed verification continuation';
        END IF;
        IF NEW.status = 'signing' AND (TG_OP <> 'UPDATE' OR OLD.status NOT IN ('authorized', 'signing')
            OR continuation.expires_at <= clock_timestamp() OR NEW.expires_at <= clock_timestamp()) THEN
            RAISE EXCEPTION 'verification continuation has expired or cannot be reused';
        END IF;
        IF NEW.status = 'issued' AND (TG_OP <> 'UPDATE' OR OLD.status NOT IN ('signing', 'issued')) THEN
            RAISE EXCEPTION 'verification continuation requires its signing claim';
        END IF;
    END IF;
    RETURN NEW;
END;
$prerequisite_transaction$;
DROP TRIGGER IF EXISTS guard_verification_prerequisite_transaction ON issuance_service.issuance_transactions;
CREATE TRIGGER guard_verification_prerequisite_transaction BEFORE INSERT OR UPDATE
ON issuance_service.issuance_transactions FOR EACH ROW
EXECUTE FUNCTION issuance_service.guard_verification_prerequisite_transaction();

CREATE OR REPLACE FUNCTION issuance_service.guard_verification_prerequisite_continuation()
RETURNS trigger LANGUAGE plpgsql AS $prerequisite_continuation$
DECLARE
    transaction_row issuance_service.issuance_transactions%ROWTYPE;
    observed_at timestamptz;
BEGIN
    IF TG_OP = 'DELETE' THEN
        SELECT * INTO transaction_row FROM issuance_service.issuance_transactions
            WHERE id = OLD.transaction_id AND organization_id = OLD.organization_id FOR UPDATE;
        observed_at := clock_timestamp();
        IF NOT FOUND OR transaction_row.issuance_intent IS NULL
            OR transaction_row.status NOT IN ('issued', 'failed', 'expired', 'revoked')
            OR transaction_row.issuance_intent->>'intent_digest' IS DISTINCT FROM OLD.intent_digest
            OR transaction_row.issuance_intent->>'flow_instance_id' IS DISTINCT FROM OLD.flow_instance_id
            OR transaction_row.reserved_credential_id IS DISTINCT FROM OLD.credential_id
            OR OLD.expires_at > observed_at OR transaction_row.expires_at > observed_at
            OR NOT (((transaction_row.issuance_intent->>'expires_at_epoch_micros')::numeric
                = extract(epoch FROM transaction_row.expires_at) * 1000000
                AND (transaction_row.issuance_intent->>'expires_at_epoch_micros')::numeric
                    <= extract(epoch FROM observed_at) * 1000000) IS TRUE) THEN
            RAISE EXCEPTION 'retention requires a terminal and fully expired verification continuation';
        END IF;
        RETURN OLD;
    END IF;
    IF TG_OP <> 'INSERT' THEN
        RAISE EXCEPTION 'verification continuation is immutable and single-use';
    END IF;
    SELECT * INTO transaction_row FROM issuance_service.issuance_transactions
        WHERE id = NEW.transaction_id AND organization_id = NEW.organization_id FOR UPDATE;
    IF NOT FOUND OR transaction_row.issuance_intent IS NULL OR transaction_row.status <> 'authorized'
        OR transaction_row.reserved_credential_id IS NOT NULL
        OR transaction_row.issuance_intent->>'intent_digest' IS DISTINCT FROM NEW.intent_digest
        OR transaction_row.issuance_intent->>'flow_instance_id' IS DISTINCT FROM NEW.flow_instance_id
        OR NEW.expires_at > transaction_row.expires_at
        OR NEW.expires_at <= clock_timestamp()
        OR NEW.consumed_at < transaction_row.created_at
        OR NEW.consumed_at > clock_timestamp() + interval '1 second'
        OR NEW.consumed_at <> NEW.created_at THEN
        RAISE EXCEPTION 'verification continuation does not match the live issuing intent';
    END IF;
    RETURN NEW;
END;
$prerequisite_continuation$;
DROP TRIGGER IF EXISTS guard_verification_prerequisite_continuation ON issuance_service.issuance_prerequisite_continuations;
CREATE TRIGGER guard_verification_prerequisite_continuation BEFORE INSERT OR UPDATE OR DELETE
ON issuance_service.issuance_prerequisite_continuations FOR EACH ROW
EXECUTE FUNCTION issuance_service.guard_verification_prerequisite_continuation();

CREATE OR REPLACE FUNCTION issuance_service.guard_verification_prerequisite_authorization()
RETURNS trigger LANGUAGE plpgsql AS $prerequisite_authorization$
BEGIN
    IF EXISTS (SELECT 1 FROM issuance_service.issuance_transactions transaction
        WHERE transaction.issuance_intent IS NOT NULL
            AND ((NEW.issuer_state IS NOT NULL AND transaction.pre_auth_code = NEW.issuer_state)
                OR (NEW.access_token IS NOT NULL AND transaction.access_token = NEW.access_token))) THEN
        RAISE EXCEPTION 'verification prerequisite requires pre-authorized issuance';
    END IF;
    RETURN NEW;
END;
$prerequisite_authorization$;
DROP TRIGGER IF EXISTS guard_verification_prerequisite_authorization ON issuance_service.authorization_sessions;
CREATE TRIGGER guard_verification_prerequisite_authorization BEFORE INSERT OR UPDATE
ON issuance_service.authorization_sessions FOR EACH ROW
EXECUTE FUNCTION issuance_service.guard_verification_prerequisite_authorization();

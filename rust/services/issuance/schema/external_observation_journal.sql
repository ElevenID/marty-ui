-- SPDX-License-Identifier: AGPL-3.0-only
-- Candidate core-owned journal. NOT a startup migration or connector database.
-- Activate only with a qualified canonical authority adapter and role grants.
CREATE SCHEMA IF NOT EXISTS issuance_service;

-- Producer authorization is core-owned. The key foreign key points at the
-- canonical organization API-key record; there is no connector-side key mirror.
CREATE TABLE issuance_service.external_observation_producer_grants (
    id uuid PRIMARY KEY,
    organization_id uuid NOT NULL REFERENCES organization_service.organizations(id) ON DELETE CASCADE,
    source_id text NOT NULL CHECK (source_id ~ '^[A-Za-z0-9_-]{1,128}$'),
    api_key_id uuid NOT NULL REFERENCES organization_service.api_keys(id) ON DELETE CASCADE,
    active boolean NOT NULL DEFAULT false,
    revision bigint NOT NULL DEFAULT 1 CHECK (revision BETWEEN 1 AND 9007199254740991),
    expires_at timestamptz NOT NULL,
    created_by varchar(255) NOT NULL CHECK (btrim(created_by) <> ''),
    approved_by varchar(255) NOT NULL CHECK (btrim(approved_by) <> ''),
    approved_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (organization_id, source_id, api_key_id),
    UNIQUE (id, organization_id, source_id)
);

-- Binding authority is selected by core administrators, never by connector JSON.
-- It binds one external source to one existing application and exact subject.
CREATE TABLE issuance_service.external_observation_bindings (
    id text PRIMARY KEY CHECK (id ~ '^[A-Za-z0-9_-]{1,128}$'),
    organization_id uuid NOT NULL REFERENCES organization_service.organizations(id) ON DELETE CASCADE,
    source_id text NOT NULL CHECK (source_id ~ '^[A-Za-z0-9_-]{1,128}$'),
    application_id varchar NOT NULL REFERENCES issuance_service.applications(id) ON DELETE RESTRICT,
    subject_id text NOT NULL CHECK (octet_length(subject_id) BETWEEN 1 AND 1024),
    provider text NOT NULL CHECK (provider ~ '^[A-Za-z0-9_.:-]{1,128}$'),
    fact_type text NOT NULL CHECK (fact_type ~ '^[A-Za-z0-9_.:-]{1,128}$'),
    resource_scope jsonb NOT NULL CHECK (jsonb_typeof(resource_scope) = 'object'),
    claim_rules jsonb NOT NULL CHECK (jsonb_typeof(claim_rules) = 'object'),
    max_age_ms bigint NOT NULL CHECK (max_age_ms BETWEEN 1 AND 900000),
    max_clock_skew_ms bigint NOT NULL CHECK (max_clock_skew_ms BETWEEN 0 AND 30000),
    active boolean NOT NULL DEFAULT false,
    revision bigint NOT NULL DEFAULT 1 CHECK (revision BETWEEN 1 AND 9007199254740991),
    created_by varchar(255) NOT NULL CHECK (btrim(created_by) <> ''),
    updated_by varchar(255) NOT NULL CHECK (btrim(updated_by) <> ''),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (id, organization_id, source_id)
);

CREATE TABLE issuance_service.external_observation_grant_bindings (
    grant_id uuid NOT NULL,
    binding_id text NOT NULL,
    organization_id uuid NOT NULL,
    source_id text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (grant_id, binding_id),
    FOREIGN KEY (grant_id, organization_id, source_id)
        REFERENCES issuance_service.external_observation_producer_grants(id, organization_id, source_id)
        ON DELETE CASCADE,
    FOREIGN KEY (binding_id, organization_id, source_id)
        REFERENCES issuance_service.external_observation_bindings(id, organization_id, source_id)
        ON DELETE CASCADE
);

CREATE INDEX external_observation_grants_key_lookup
    ON issuance_service.external_observation_producer_grants(organization_id, api_key_id, source_id);
CREATE INDEX external_observation_bindings_application_lookup
    ON issuance_service.external_observation_bindings(organization_id, application_id);
CREATE INDEX external_observation_grant_bindings_binding_lookup
    ON issuance_service.external_observation_grant_bindings(organization_id, source_id, binding_id);

CREATE OR REPLACE FUNCTION issuance_service.bump_external_observation_revision()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    NEW.revision := OLD.revision + 1;
    NEW.updated_at := clock_timestamp();
    RETURN NEW;
END;
$$;

CREATE TRIGGER external_observation_grants_revision
    BEFORE UPDATE ON issuance_service.external_observation_producer_grants
    FOR EACH ROW EXECUTE FUNCTION issuance_service.bump_external_observation_revision();
CREATE TRIGGER external_observation_bindings_revision
    BEFORE UPDATE ON issuance_service.external_observation_bindings
    FOR EACH ROW EXECUTE FUNCTION issuance_service.bump_external_observation_revision();

-- Membership changes invalidate all prior grant fences. The admin path should
-- lock the grant row before editing membership; the trigger also serializes
-- any direct membership mutation with an admission transaction.
CREATE OR REPLACE FUNCTION issuance_service.bump_external_observation_grant_membership()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        UPDATE issuance_service.external_observation_producer_grants
           SET revision = revision + 1, updated_at = clock_timestamp()
         WHERE id = OLD.grant_id;
        RETURN OLD;
    END IF;
    UPDATE issuance_service.external_observation_producer_grants
       SET revision = revision + 1, updated_at = clock_timestamp()
     WHERE id = NEW.grant_id;
    RETURN NEW;
END;
$$;

CREATE TRIGGER external_observation_grant_binding_insert
    AFTER INSERT ON issuance_service.external_observation_grant_bindings
    FOR EACH ROW EXECUTE FUNCTION issuance_service.bump_external_observation_grant_membership();
CREATE TRIGGER external_observation_grant_binding_delete
    AFTER DELETE ON issuance_service.external_observation_grant_bindings
    FOR EACH ROW EXECUTE FUNCTION issuance_service.bump_external_observation_grant_membership();

-- Membership replacements must pass through DELETE/INSERT so both affected
-- grants receive revision fences. In-place updates would bypass those triggers.
CREATE OR REPLACE FUNCTION issuance_service.reject_external_observation_membership_update()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'external observation membership is immutable; delete and insert instead'
        USING ERRCODE = '23514';
END;
$$;

CREATE TRIGGER external_observation_grant_binding_immutable
    BEFORE UPDATE ON issuance_service.external_observation_grant_bindings
    FOR EACH ROW EXECUTE FUNCTION issuance_service.reject_external_observation_membership_update();

CREATE TABLE issuance_service.external_observation_receipts (
    receipt_id uuid PRIMARY KEY,
    organization_id text NOT NULL CHECK (organization_id ~ '^[A-Za-z0-9_-]{1,128}$'),
    source_id text NOT NULL CHECK (source_id ~ '^[A-Za-z0-9_-]{1,128}$'),
    api_key_id text NOT NULL CHECK (api_key_id ~ '^[A-Za-z0-9_-]{1,128}$'),
    binding_id text NOT NULL CHECK (binding_id ~ '^[A-Za-z0-9_-]{1,128}$'),
    binding_revision bigint NOT NULL CHECK (binding_revision BETWEEN 1 AND 9007199254740991),
    observation_id text NOT NULL CHECK (observation_id ~ '^[A-Za-z0-9_-]{1,128}$'),
    sequence bigint NOT NULL CHECK (sequence BETWEEN 1 AND 9007199254740991),
    received_at_ms bigint NOT NULL CHECK (received_at_ms BETWEEN 1 AND 9007199254740991),
    application_id text NOT NULL CHECK (application_id ~ '^[A-Za-z0-9_-]{1,128}$'),
    subject_id text NOT NULL CHECK (octet_length(subject_id) BETWEEN 1 AND 1024),
    provider text NOT NULL CHECK (provider ~ '^[A-Za-z0-9_.:-]{1,128}$'),
    fact_type text NOT NULL CHECK (fact_type ~ '^[A-Za-z0-9_.:-]{1,128}$'),
    resource_scope jsonb NOT NULL CHECK (jsonb_typeof(resource_scope) = 'object'),
    envelope jsonb NOT NULL CHECK (jsonb_typeof(envelope) = 'object'),
    CHECK (envelope ?& ARRAY['binding_id','binding_revision','observation_id','sequence',
                            'observed_at_ms','effective_at_ms','claims']),
    CHECK (envelope - ARRAY['binding_id','binding_revision','observation_id','sequence',
                           'observed_at_ms','effective_at_ms','claims'] = '{}'::jsonb),
    CHECK (envelope->'binding_id' = to_jsonb(binding_id)),
    CHECK (envelope->'observation_id' = to_jsonb(observation_id)),
    CHECK (envelope->'binding_revision' = to_jsonb(binding_revision)),
    CHECK (envelope->'sequence' = to_jsonb(sequence)),
    CHECK (jsonb_typeof(envelope->'claims') = 'object'),
    UNIQUE (organization_id, source_id, observation_id),
    UNIQUE (organization_id, source_id, binding_id, sequence),
    UNIQUE (organization_id, source_id, binding_id, sequence, receipt_id)
);

CREATE TABLE issuance_service.external_observation_heads (
    organization_id text NOT NULL,
    source_id text NOT NULL,
    binding_id text NOT NULL,
    sequence bigint NOT NULL CHECK (sequence BETWEEN 1 AND 9007199254740991),
    receipt_id uuid NOT NULL,
    PRIMARY KEY (organization_id, source_id, binding_id),
    FOREIGN KEY (organization_id, source_id, binding_id, sequence, receipt_id)
        REFERENCES issuance_service.external_observation_receipts
            (organization_id, source_id, binding_id, sequence, receipt_id)
);

-- Provenance is joined from the receipt, not duplicated in an inconsistent row.
CREATE TABLE issuance_service.external_observation_audit (
    receipt_id uuid PRIMARY KEY REFERENCES issuance_service.external_observation_receipts(receipt_id),
    event_type text NOT NULL CHECK (event_type = 'external_observation_admitted'),
    received_at_ms bigint NOT NULL CHECK (received_at_ms BETWEEN 1 AND 9007199254740991)
);

-- A committed receipt cannot be orphaned from its binding head or admission event.
-- Deferred checks allow the three inserts to happen in the same transaction.
ALTER TABLE issuance_service.external_observation_receipts
    ADD CONSTRAINT external_observation_requires_head
    FOREIGN KEY (organization_id, source_id, binding_id)
    REFERENCES issuance_service.external_observation_heads (organization_id, source_id, binding_id)
    DEFERRABLE INITIALLY DEFERRED;
ALTER TABLE issuance_service.external_observation_receipts
    ADD CONSTRAINT external_observation_requires_audit
    FOREIGN KEY (receipt_id) REFERENCES issuance_service.external_observation_audit (receipt_id)
    DEFERRABLE INITIALLY DEFERRED;

REVOKE ALL ON issuance_service.external_observation_receipts FROM PUBLIC;
REVOKE ALL ON issuance_service.external_observation_heads FROM PUBLIC;
REVOKE ALL ON issuance_service.external_observation_audit FROM PUBLIC;

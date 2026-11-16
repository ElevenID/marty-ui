-- SPDX-License-Identifier: AGPL-3.0-only
-- Candidate core-owned journal. NOT a startup migration or connector database.
-- Activate only with a qualified canonical authority adapter and role grants.
CREATE SCHEMA IF NOT EXISTS issuance_service;

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

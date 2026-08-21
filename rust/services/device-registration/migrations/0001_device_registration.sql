CREATE SCHEMA IF NOT EXISTS device_registration_service;

CREATE TABLE IF NOT EXISTS device_registration_service.device_registrations (
    id varchar(36) PRIMARY KEY,
    user_id varchar(255) NOT NULL,
    organization_id varchar(36),
    device_id varchar(255) NOT NULL,
    platform varchar(32) NOT NULL,
    fcm_token text NOT NULL,
    app_version varchar(64),
    os_version varchar(128),
    device_model varchar(255),
    preferences json NOT NULL DEFAULT '{}'::json,
    public_key_der text,
    public_key_kid varchar(255),
    key_valid_from timestamptz,
    key_valid_until timestamptz,
    key_version bigint,
    is_active boolean NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    last_seen_at timestamptz
);
ALTER TABLE device_registration_service.device_registrations ADD COLUMN IF NOT EXISTS key_version bigint;

DO $$ BEGIN
    IF EXISTS (
        SELECT 1 FROM device_registration_service.device_registrations
        WHERE (public_key_der IS NULL) <> (public_key_kid IS NULL)
    ) THEN
        RAISE EXCEPTION 'cannot migrate incomplete legacy device key projection';
    END IF;
END $$;

CREATE TABLE IF NOT EXISTS device_registration_service.device_registration_keys (
    id varchar(36) PRIMARY KEY,
    registration_id varchar(36) NOT NULL REFERENCES device_registration_service.device_registrations(id) ON DELETE RESTRICT,
    key_version bigint NOT NULL CONSTRAINT ck_device_key_version_range CHECK (key_version BETWEEN 1 AND 9007199254740991),
    public_key_der text NOT NULL CONSTRAINT ck_device_key_der_length CHECK (char_length(public_key_der) BETWEEN 1 AND 8192),
    public_key_kid varchar(43) NOT NULL CONSTRAINT ck_device_key_kid_length CHECK (char_length(public_key_kid) = 43),
    state varchar(16) NOT NULL CONSTRAINT ck_device_key_state CHECK (state IN ('CURRENT','RETIRING','RETIRED','REVOKED')),
    valid_from timestamptz NOT NULL,
    valid_until timestamptz,
    rotated_at timestamptz,
    retire_at timestamptz,
    revoked_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT uq_device_key_registration_version UNIQUE (registration_id, key_version),
    CONSTRAINT ck_device_key_retiring_deadline CHECK ((state = 'RETIRING' AND rotated_at IS NOT NULL AND retire_at IS NOT NULL) OR state <> 'RETIRING'),
    CONSTRAINT ck_device_key_revoked_at CHECK ((state = 'REVOKED' AND revoked_at IS NOT NULL) OR state <> 'REVOKED'),
    CONSTRAINT ck_device_key_validity_window CHECK (valid_until IS NULL OR valid_until > valid_from),
    CONSTRAINT ck_device_key_retirement_window CHECK (retire_at IS NULL OR rotated_at IS NULL OR retire_at >= rotated_at)
);

CREATE TABLE IF NOT EXISTS device_registration_service.device_key_transitions (
    id varchar(36) PRIMARY KEY,
    registration_id varchar(36) NOT NULL REFERENCES device_registration_service.device_registrations(id) ON DELETE RESTRICT,
    event varchar(32) NOT NULL CONSTRAINT ck_device_key_transition_event CHECK (event IN ('KEY_REGISTERED','KEY_ROTATED','KEYS_REVOKED')),
    from_version bigint,
    to_version bigint,
    committed_at timestamptz NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS ux_device_key_one_current ON device_registration_service.device_registration_keys(registration_id) WHERE state = 'CURRENT';
CREATE INDEX IF NOT EXISTS ix_device_key_registration_kid ON device_registration_service.device_registration_keys(registration_id, public_key_kid);
CREATE INDEX IF NOT EXISTS ix_device_key_transition_registration_time ON device_registration_service.device_key_transitions(registration_id, committed_at);
CREATE INDEX IF NOT EXISTS ix_device_registrations_user_id ON device_registration_service.device_registrations(user_id);
CREATE INDEX IF NOT EXISTS ix_device_registrations_organization_id ON device_registration_service.device_registrations(organization_id);
CREATE INDEX IF NOT EXISTS ix_device_registrations_device_id ON device_registration_service.device_registrations(device_id);
CREATE INDEX IF NOT EXISTS ix_device_registrations_user_org ON device_registration_service.device_registrations(user_id, organization_id);

INSERT INTO device_registration_service.device_registration_keys
    (id, registration_id, key_version, public_key_der, public_key_kid, state, valid_from, valid_until, revoked_at, created_at)
SELECT r.id, r.id, 1, r.public_key_der, r.public_key_kid,
       CASE WHEN r.is_active THEN 'CURRENT' ELSE 'REVOKED' END,
       COALESCE(r.key_valid_from, r.created_at), r.key_valid_until,
       CASE WHEN r.is_active THEN NULL ELSE r.updated_at END, r.created_at
FROM device_registration_service.device_registrations r
WHERE r.public_key_der IS NOT NULL
  AND NOT EXISTS (SELECT 1 FROM device_registration_service.device_registration_keys k WHERE k.registration_id = r.id);

UPDATE device_registration_service.device_registrations
SET key_version = 1, key_valid_from = COALESCE(key_valid_from, created_at)
WHERE public_key_der IS NOT NULL AND key_version IS NULL;

INSERT INTO device_registration_service.device_key_transitions
    (id, registration_id, event, from_version, to_version, committed_at)
SELECT r.id, r.id,
       CASE WHEN r.is_active THEN 'KEY_REGISTERED' ELSE 'KEYS_REVOKED' END,
       CASE WHEN r.is_active THEN NULL ELSE 1 END,
       CASE WHEN r.is_active THEN 1 ELSE NULL END,
       CASE WHEN r.is_active THEN r.created_at ELSE r.updated_at END
FROM device_registration_service.device_registrations r
WHERE r.key_version = 1
  AND NOT EXISTS (SELECT 1 FROM device_registration_service.device_key_transitions t WHERE t.registration_id = r.id);

UPDATE device_registration_service.device_registrations
SET public_key_der = NULL, public_key_kid = NULL, key_valid_from = NULL,
    key_valid_until = NULL, key_version = NULL
WHERE NOT is_active AND key_version IS NOT NULL;

DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'ck_device_registration_current_key_projection') THEN
        ALTER TABLE device_registration_service.device_registrations
        ADD CONSTRAINT ck_device_registration_current_key_projection CHECK (
            (public_key_der IS NULL AND public_key_kid IS NULL AND key_valid_from IS NULL AND key_valid_until IS NULL AND key_version IS NULL)
            OR (public_key_der IS NOT NULL AND public_key_kid IS NOT NULL AND key_valid_from IS NOT NULL AND key_version IS NOT NULL)
        );
    END IF;
END $$;

CREATE TABLE IF NOT EXISTS device_registration_service.alembic_version (
    version_num varchar(32) PRIMARY KEY
);
INSERT INTO device_registration_service.alembic_version(version_num)
VALUES ('20260809_0001')
ON CONFLICT (version_num) DO NOTHING;

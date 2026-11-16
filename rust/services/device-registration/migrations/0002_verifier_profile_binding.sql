-- Additive only: existing pairings have no verifier grant until explicitly re-paired.
ALTER TABLE device_registration_service.device_pairing_confirmations
    ADD COLUMN IF NOT EXISTS verifier_trust_profile_id varchar(36);

INSERT INTO device_registration_service.alembic_version(version_num)
VALUES ('20261116_0002')
ON CONFLICT (version_num) DO NOTHING;

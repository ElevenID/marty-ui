CREATE TABLE IF NOT EXISTS flow_service.rust_seed_versions (
    version varchar(64) PRIMARY KEY,
    applied_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

INSERT INTO flow_service.flow_definitions (
    id, organization_id, name, description, status, flow_type, steps, transitions,
    start_step_id, credential_template_id, application_template_id,
    presentation_policy_id, delivery_destination_profile_id, deployment_profile_id,
    deployment_profile_ids, trust_profile_id, approval_strategy, hooks, trigger,
    extension, preconditions, default_timeout_seconds, max_retries,
    retry_cooldown_minutes, enable_resume, version, created_at, updated_at
) VALUES (
    '71000000-0000-0000-0000-000000000001',
    '00000000-0000-0000-0000-000000000001',
    'Marty Open Badge Login Flow',
    'Default flow for Marty Open Badge credential-based login.',
    'ACTIVE', 'custom',
    $json$[
      {"id":"step-start","name":"Start Login Verification","description":"Initialize credential-login verification request","step_type":"start","config":{},"timeout_seconds":300,"conditions":[],"approval_strategy":null},
      {"id":"step-verify","name":"Verify Open Badge Membership Credential","description":"Evaluate holder credential against the OpenBadgeLogin policy","step_type":"verification","config":{"presentation_policy_id":"50000000-0000-0000-0000-000000000004","trust_profile_id":"60000000-0000-0000-0000-000000000001"},"timeout_seconds":300,"conditions":[],"approval_strategy":null},
      {"id":"step-end","name":"Login Complete","description":"Credential login completed","step_type":"end","config":{},"timeout_seconds":null,"conditions":[],"approval_strategy":null}
    ]$json$::json,
    $json$[
      {"id":"transition-1","from_step_id":"step-start","to_step_id":"step-verify","condition":"success","condition_expression":null},
      {"id":"transition-2","from_step_id":"step-verify","to_step_id":"step-end","condition":"success","condition_expression":null}
    ]$json$::json,
    'step-start', '50000000-0000-0000-0000-000000000040', NULL,
    '50000000-0000-0000-0000-000000000004', NULL,
    '70000000-0000-0000-0000-000000000001',
    '["70000000-0000-0000-0000-000000000001"]'::json,
    '60000000-0000-0000-0000-000000000001', 'AUTO', '{}'::json,
    '{"trigger_type":"API_CALL","config":{"event_type":"CREDENTIAL_LOGIN"}}'::json,
    $json${
      "extension_uri":"urn:elevenid:flow-extension:legacy-orchestration:v1",
      "extension_version":"1.0.0",
      "extends_flow_type":"oid4vp_presentation",
      "entry_step_id":"step_1",
      "steps":[
        {"step_id":"step_1","action":"start_login_verification","config":{},"description":"Initialize credential-login verification request","timeout_seconds":300},
        {"step_id":"step_2","action":"verify_open_badge_membership_credential","config":{"presentation_policy_id":"50000000-0000-0000-0000-000000000004","trust_profile_id":"60000000-0000-0000-0000-000000000001"},"description":"Evaluate holder credential against the OpenBadgeLogin policy","timeout_seconds":300},
        {"step_id":"step_3","action":"login_complete","config":{},"description":"Credential login completed"}
      ],
      "transitions":[
        {"from_step_id":"step_1","to_step_id":"step_2","outcome":"SUCCESS"},
        {"from_step_id":"step_2","to_step_id":"step_3","outcome":"SUCCESS"}
      ],
      "config":{"legacy_preconditions":["organization_membership_active"]}
    }$json$::json,
    '[]'::json, 600, 1, 5, true, 1,
    '2026-04-16T00:00:00Z'::timestamptz,
    '2026-05-05T00:00:00Z'::timestamptz
) ON CONFLICT (id) DO NOTHING;

WITH issuance_flows(id, credential_template_id, name, description) AS (
    VALUES
      ('72000000-0000-0000-0000-000000000010', '50000000-0000-0000-0000-000000000010', 'Marty Member Login Credential Issuance', 'Issues the legacy Marty Member Login Credential to an applicant wallet.'),
      ('72000000-0000-0000-0000-000000000040', '50000000-0000-0000-0000-000000000040', 'Marty Verified Member Badge Issuance', 'Issues the Marty Verified Member Badge to an applicant wallet.')
)
INSERT INTO flow_service.flow_definitions (
    id, organization_id, name, description, status, flow_type, steps, transitions,
    start_step_id, credential_template_id, application_template_id,
    presentation_policy_id, delivery_destination_profile_id, deployment_profile_id,
    deployment_profile_ids, trust_profile_id, approval_strategy, hooks, trigger,
    extension, preconditions, default_timeout_seconds, max_retries,
    retry_cooldown_minutes, enable_resume, version, created_at, updated_at
)
SELECT id, '00000000-0000-0000-0000-000000000001', name, description,
    'ACTIVE', 'custom',
    $json$[
      {"id":"step-check-preconditions","name":"Check Preconditions","description":"Confirm the applicant application is approved before issuing.","step_type":"approval","config":{"required_preconditions":["application_approved"],"auto_advance":true},"timeout_seconds":300,"conditions":[],"approval_strategy":"AUTO"},
      {"id":"step-create-offer","name":"Create Credential Offer","description":"Generate an OID4VCI pre-authorized credential offer.","step_type":"issuance","config":{"transport_method":"qr_code","offer_validity_minutes":15,"generate_qr":true},"timeout_seconds":60,"conditions":[],"approval_strategy":null},
      {"id":"step-await-wallet","name":"Await Wallet","description":"Wait for the applicant wallet to redeem the credential offer.","step_type":"wait","config":{"wait_for_event":"credential_requested","show_deep_link":true},"timeout_seconds":900,"conditions":[],"approval_strategy":null},
      {"id":"step-issue-credential","name":"Issue Credential","description":"Wallet requests and receives the signed credential.","step_type":"issuance","config":{"endpoint":"/api/issuance/credential","auto_advance":true},"timeout_seconds":60,"conditions":[],"approval_strategy":null},
      {"id":"step-complete","name":"Issuance Complete","description":"Credential issuance completed.","step_type":"end","config":{"emit_event":"credential_issued"},"timeout_seconds":null,"conditions":[],"approval_strategy":null}
    ]$json$::json,
    $json$[
      {"id":"transition-preconditions-offer","from_step_id":"step-check-preconditions","to_step_id":"step-create-offer","condition":"success","condition_expression":null},
      {"id":"transition-offer-await-wallet","from_step_id":"step-create-offer","to_step_id":"step-await-wallet","condition":"success","condition_expression":null},
      {"id":"transition-wallet-issue","from_step_id":"step-await-wallet","to_step_id":"step-issue-credential","condition":"success","condition_expression":null},
      {"id":"transition-issue-complete","from_step_id":"step-issue-credential","to_step_id":"step-complete","condition":"success","condition_expression":null}
    ]$json$::json,
    'step-check-preconditions', credential_template_id, NULL, NULL, NULL,
    '70000000-0000-0000-0000-000000000001',
    '["70000000-0000-0000-0000-000000000001"]'::json,
    NULL, 'AUTO', '{}'::json,
    '{"trigger_type":"WEBHOOK","config":{"event_type":"APPLICATION_APPROVED"}}'::json,
    $json${
      "extension_uri":"urn:elevenid:flow-extension:legacy-orchestration:v1",
      "extension_version":"1.0.0",
      "extends_flow_type":"oid4vci_pre_authorized",
      "entry_step_id":"step_1",
      "steps":[
        {"step_id":"step_1","action":"check_preconditions","config":{"required_preconditions":["application_approved"],"auto_advance":true},"description":"Confirm the applicant application is approved before issuing.","timeout_seconds":300},
        {"step_id":"step_2","action":"create_credential_offer","config":{"transport_method":"qr_code","offer_validity_minutes":15,"generate_qr":true},"description":"Generate an OID4VCI pre-authorized credential offer.","timeout_seconds":60},
        {"step_id":"step_3","action":"await_wallet","config":{"wait_for_event":"credential_requested","show_deep_link":true},"description":"Wait for the applicant wallet to redeem the credential offer.","timeout_seconds":900},
        {"step_id":"step_4","action":"issue_credential","config":{"endpoint":"/api/issuance/credential","auto_advance":true},"description":"Wallet requests and receives the signed credential.","timeout_seconds":60},
        {"step_id":"step_5","action":"issuance_complete","config":{"emit_event":"credential_issued"},"description":"Credential issuance completed."}
      ],
      "transitions":[
        {"from_step_id":"step_1","to_step_id":"step_2","outcome":"SUCCESS"},
        {"from_step_id":"step_2","to_step_id":"step_3","outcome":"SUCCESS"},
        {"from_step_id":"step_3","to_step_id":"step_4","outcome":"SUCCESS"},
        {"from_step_id":"step_4","to_step_id":"step_5","outcome":"SUCCESS"}
      ],
      "config":{"legacy_preconditions":["application_approved"]}
    }$json$::json,
    '[]'::json, 600, 3, 5, true, 1,
    '2026-07-10T00:00:00Z'::timestamptz,
    '2026-07-10T00:00:00Z'::timestamptz
FROM issuance_flows
ON CONFLICT (id) DO NOTHING;

INSERT INTO flow_service.flow_instances (
    id, flow_definition_id, organization_id, status, current_step_id, context,
    step_history, state_history, subject_id, subject_type, external_reference,
    application_flow_key_hash, started_at, completed_at, expires_at, result,
    error, created_at, updated_at
) VALUES (
    '71000000-0000-0000-0000-000000000101',
    '71000000-0000-0000-0000-000000000001',
    '00000000-0000-0000-0000-000000000001', 'completed', 'step-end',
    '{"seeded":true,"scenario":"bootstrap"}'::json,
    '[{"step_id":"step-start","status":"completed","timestamp":"2026-04-16T00:00:00Z"},{"step_id":"step-verify","status":"completed","timestamp":"2026-04-16T00:00:00Z"},{"step_id":"step-end","status":"completed","timestamp":"2026-04-16T00:00:00Z"}]'::json,
    '[]'::json, 'marty-bootstrap-user', 'applicant',
    'seed:marty-credential-login', NULL,
    '2026-04-16T00:00:00Z'::timestamptz,
    '2026-04-16T00:00:00Z'::timestamptz, NULL,
    '{"outcome":"success","seeded":true}'::json, NULL,
    '2026-04-16T00:00:00Z'::timestamptz,
    '2026-04-16T00:00:00Z'::timestamptz
) ON CONFLICT (id) DO NOTHING;

DO $$
BEGIN
    IF to_regclass('deployment_profile_service.deployment_profiles') IS NOT NULL THEN
        UPDATE deployment_profile_service.deployment_profiles
        SET enabled_flow_ids = CASE
            WHEN enabled_flow_ids::jsonb @> '["71000000-0000-0000-0000-000000000001"]'::jsonb
                THEN enabled_flow_ids::jsonb
            ELSE enabled_flow_ids::jsonb || '["71000000-0000-0000-0000-000000000001"]'::jsonb
        END
        WHERE id = '70000000-0000-0000-0000-000000000001';
    END IF;
END $$;

INSERT INTO flow_service.rust_seed_versions(version)
VALUES ('rust_flow_seed_0001') ON CONFLICT DO NOTHING;

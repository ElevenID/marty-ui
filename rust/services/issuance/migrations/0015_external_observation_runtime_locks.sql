-- SPDX-License-Identifier: AGPL-3.0-only
-- Core schema-owner installation only. These functions lock current canonical
-- rows in the caller's transaction; they never create authority or modify data.
-- Runtime receives EXECUTE explicitly from its owner, never canonical UPDATE.
CREATE FUNCTION issuance_service.external_observation_lock_organization(requested_organization uuid)
RETURNS TABLE(status text)
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
    SELECT o.status::text FROM organization_service.organizations o
    WHERE o.id=requested_organization FOR SHARE OF o;
$$;

CREATE FUNCTION issuance_service.external_observation_lock_api_keys(requested_organization uuid, requested_keys uuid[])
RETURNS TABLE(id uuid,organization_id uuid,scopes text[],scope_type text,deployment_profile_id uuid,
    status text,enabled boolean,expires_at timestamptz,updated_at timestamptz)
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
    SELECT k.id,k.organization_id,k.scopes,k.scope_type::text,k.deployment_profile_id,
        k.status::text,k.enabled,k.expires_at,k.updated_at
    FROM organization_service.api_keys k
    WHERE k.organization_id=requested_organization AND k.id=ANY(requested_keys)
    ORDER BY k.id FOR UPDATE OF k;
$$;

CREATE FUNCTION issuance_service.external_observation_lock_application(requested_application text, requested_organization text)
RETURNS TABLE(id text,organization_id text,applicant_identifier text,status text,updated_at timestamptz,expires_at timestamptz)
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
    SELECT a.id,a.organization_id,a.applicant_identifier,a.status::text,a.updated_at,a.expires_at
    FROM issuance_service.applications a
    WHERE a.id=requested_application AND a.organization_id=requested_organization FOR UPDATE OF a;
$$;

CREATE FUNCTION issuance_service.external_observation_lock_administrator(requested_organization uuid, requested_actor text)
RETURNS TABLE(id uuid)
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
    SELECT m.id FROM organization_service.organizations o
    JOIN organization_service.members m ON m.organization_id=o.id
    JOIN organization_service.member_roles mr ON mr.member_id=m.id
    JOIN organization_service.roles r ON r.id=mr.role_id AND r.organization_id=o.id
    JOIN organization_service.role_permissions rp ON rp.role_id=r.id
    JOIN organization_service.permissions p ON p.id=rp.permission_id
    WHERE o.id=requested_organization AND o.status='active' AND m.user_id=requested_actor AND m.status='active'
      AND p.resource='external-observation' AND p.action='manage'
    ORDER BY m.id,r.id,p.id FOR SHARE OF o,m,mr,r,rp,p;
$$;

-- Immutable receipts also need a row-lock privilege. The caller keeps SELECT
-- and INSERT only; this helper preserves replay locking without receipt UPDATE.
CREATE FUNCTION issuance_service.external_observation_lock_receipt(requested_organization text, requested_source text, requested_observation text)
RETURNS TABLE(receipt_id uuid,organization_id text,source_id text,api_key_id text,envelope jsonb)
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
    SELECT r.receipt_id,r.organization_id,r.source_id,r.api_key_id,r.envelope
    FROM issuance_service.external_observation_receipts r
    WHERE r.organization_id=requested_organization AND r.source_id=requested_source
      AND r.observation_id=requested_observation FOR SHARE OF r;
$$;

REVOKE ALL ON FUNCTION issuance_service.external_observation_lock_organization(uuid),
    issuance_service.external_observation_lock_api_keys(uuid,uuid[]),
    issuance_service.external_observation_lock_application(text,text),
    issuance_service.external_observation_lock_administrator(uuid,text),
    issuance_service.external_observation_lock_receipt(text,text,text) FROM PUBLIC;

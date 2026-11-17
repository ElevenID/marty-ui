-- SPDX-License-Identifier: AGPL-3.0-only
-- Canonical Core relationship. No provider claims or connector identity authority.
CREATE TABLE issuance_service.application_ownerships (
 organization_id uuid NOT NULL REFERENCES organization_service.organizations(id) ON DELETE RESTRICT,
 application_id varchar NOT NULL REFERENCES issuance_service.applications(id) ON DELETE RESTRICT,
 user_id text NOT NULL CHECK(user_id ~ '^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$'),
 subject_id text NOT NULL CHECK(octet_length(subject_id) BETWEEN 1 AND 1024),
 application_revision bigint NOT NULL CHECK(application_revision BETWEEN 1 AND 9007199254740991),
 status text NOT NULL CHECK(status IN ('proposed','confirmed','revoked')),
 revision bigint NOT NULL CHECK(revision BETWEEN 1 AND 9007199254740991),
 proposed_by text NOT NULL CHECK(proposed_by ~ '^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$'),
 confirmed_at timestamptz,
 updated_at timestamptz NOT NULL,
 CHECK((status='confirmed')=(confirmed_at IS NOT NULL)),
 PRIMARY KEY(organization_id,application_id)
);
CREATE TABLE issuance_service.application_ownership_operations (
 operation_id uuid PRIMARY KEY CHECK(operation_id<>'00000000-0000-0000-0000-000000000000'),
 organization_id uuid NOT NULL REFERENCES organization_service.organizations(id) ON DELETE RESTRICT,
 application_id varchar NOT NULL REFERENCES issuance_service.applications(id) ON DELETE RESTRICT,
 actor_id text NOT NULL CHECK(actor_id ~ '^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$'),
 action text NOT NULL CHECK(action IN ('propose','confirm','revoke')),
 intent jsonb NOT NULL CHECK(jsonb_typeof(intent)='object'),
 receipt jsonb NOT NULL CHECK(jsonb_typeof(receipt)='object'),
 created_at timestamptz NOT NULL
);
CREATE INDEX application_ownership_user_lookup ON issuance_service.application_ownerships(user_id,organization_id,application_id);
CREATE INDEX application_ownership_operation_lookup ON issuance_service.application_ownership_operations(organization_id,application_id,created_at,operation_id);

CREATE FUNCTION issuance_service.guard_application_ownership()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'Application ownership is retained' USING ERRCODE='23514'; END IF;
 IF NEW.organization_id IS DISTINCT FROM OLD.organization_id OR NEW.application_id IS DISTINCT FROM OLD.application_id
   OR NEW.revision IS DISTINCT FROM OLD.revision+1 OR NEW.updated_at<OLD.updated_at THEN
  RAISE EXCEPTION 'Invalid application ownership revision' USING ERRCODE='23514'; END IF;
 RETURN NEW;
END;
$$;
CREATE TRIGGER application_ownership_revision BEFORE UPDATE OR DELETE ON issuance_service.application_ownerships
 FOR EACH ROW EXECUTE FUNCTION issuance_service.guard_application_ownership();
CREATE FUNCTION issuance_service.keep_application_ownership_operation()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN RAISE EXCEPTION 'Application ownership history is immutable' USING ERRCODE='23514'; END;
$$;
CREATE TRIGGER application_ownership_operation_immutable BEFORE UPDATE OR DELETE ON issuance_service.application_ownership_operations
 FOR EACH ROW EXECUTE FUNCTION issuance_service.keep_application_ownership_operation();

-- New exact permission; existing evidence-management permission grants no ownership.
-- The schema owner installs this helper; runtime receives EXECUTE explicitly.
CREATE FUNCTION issuance_service.application_ownership_lock_administrator(org uuid,actor text)
RETURNS TABLE(id uuid) LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT m.id FROM organization_service.organizations o
 JOIN organization_service.members m ON m.organization_id=o.id
 JOIN organization_service.member_roles mr ON mr.member_id=m.id
 JOIN organization_service.roles r ON r.id=mr.role_id AND r.organization_id=o.id
 JOIN organization_service.role_permissions rp ON rp.role_id=r.id
 JOIN organization_service.permissions p ON p.id=rp.permission_id
 WHERE o.id=org AND o.status='active' AND m.user_id=actor AND m.status='active'
  AND p.resource='application' AND p.action='manage-ownership'
 ORDER BY m.id,r.id,p.id FOR SHARE OF o,m,mr,r,rp,p;
$$;

-- actor is authenticated by Core's session-only public Gateway transport, never
-- taken from JSON or a producer API key. Trusted runtime SQL is not a tenant sandbox.
CREATE FUNCTION issuance_service.mutate_application_ownership(org uuid,app text,actor text,op uuid,
 requested_action text,expected_revision bigint,expected_application_revision bigint,proposed_user text)
RETURNS jsonb LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE prior issuance_service.application_ownership_operations; before_row issuance_service.application_ownerships;
 saved issuance_service.application_ownerships; actual issuance_service.application_ownerships;
 canonical record; wanted_intent jsonb; answer jsonb; stamp timestamptz; org_status text;
BEGIN
 IF org IS NULL OR org='00000000-0000-0000-0000-000000000000' OR app IS NULL OR app !~ '^[A-Za-z0-9_-]{1,128}$' OR actor IS NULL
  OR actor !~ '^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$' OR op IS NULL OR op='00000000-0000-0000-0000-000000000000'
  OR requested_action IS NULL OR requested_action NOT IN ('propose','confirm','revoke')
  OR expected_revision IS NULL OR expected_revision NOT BETWEEN 0 AND 9007199254740990
  OR expected_application_revision IS NULL OR expected_application_revision NOT BETWEEN 1 AND 9007199254740991
  OR (requested_action='propose' AND (proposed_user IS NULL OR proposed_user !~ '^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$'))
  OR (requested_action<>'propose' AND proposed_user IS NOT NULL) THEN RETURN NULL; END IF;
 SELECT status INTO org_status FROM issuance_service.external_observation_lock_organization(org);
 IF org_status IS DISTINCT FROM 'active' THEN RETURN NULL; END IF;
 IF requested_action<>'confirm' AND NOT EXISTS(SELECT 1 FROM issuance_service.application_ownership_lock_administrator(org,actor))
  THEN RETURN NULL; END IF;
 wanted_intent:=jsonb_build_object('expected_revision',expected_revision,
  'expected_application_revision',expected_application_revision,'proposed_user',proposed_user);
 -- Serialize the original operation even when it races against another application.
 PERFORM pg_advisory_xact_lock(hashtextextended('application-ownership:'||op::text,0));
 SELECT * INTO prior FROM issuance_service.application_ownership_operations WHERE operation_id=op;
 IF FOUND THEN
  IF prior.organization_id=org AND prior.application_id=app AND prior.actor_id=actor
   AND prior.action=requested_action AND prior.intent=wanted_intent THEN RETURN prior.receipt; END IF;
  RETURN NULL;
 END IF;
 SELECT * INTO canonical FROM issuance_service.external_observation_lock_application(app,org::text);
 IF NOT FOUND THEN RETURN NULL; END IF;
 SELECT * INTO before_row FROM issuance_service.application_ownerships WHERE organization_id=org AND application_id=app FOR UPDATE;
 IF (FOUND AND before_row.revision<>expected_revision) OR (NOT FOUND AND (expected_revision<>0 OR requested_action<>'propose')) THEN RETURN NULL; END IF;
 IF requested_action<>'revoke' AND (canonical.applicant_identifier IS NULL OR octet_length(canonical.applicant_identifier) NOT BETWEEN 1 AND 1024
  OR canonical.status NOT IN ('pending','under_review') OR canonical.expires_at IS NULL OR canonical.expires_at<=clock_timestamp()
  OR (extract(epoch FROM canonical.updated_at)*1000000)::bigint<>expected_application_revision) THEN RETURN NULL; END IF;
 IF requested_action='confirm' AND (before_row.status IS DISTINCT FROM 'proposed' OR before_row.user_id IS DISTINCT FROM actor
  OR before_row.subject_id IS DISTINCT FROM canonical.applicant_identifier
  OR before_row.application_revision IS DISTINCT FROM expected_application_revision) THEN RETURN NULL; END IF;
 IF requested_action='revoke' AND before_row.revision IS NULL THEN RETURN NULL; END IF;
 stamp:=clock_timestamp();
 IF requested_action='propose' THEN
  INSERT INTO issuance_service.application_ownerships(organization_id,application_id,user_id,subject_id,application_revision,status,revision,proposed_by,confirmed_at,updated_at)
   VALUES(org,app,proposed_user,canonical.applicant_identifier,expected_application_revision,'proposed',expected_revision+1,actor,NULL,stamp)
   ON CONFLICT(organization_id,application_id) DO UPDATE SET user_id=EXCLUDED.user_id,subject_id=EXCLUDED.subject_id,
    application_revision=EXCLUDED.application_revision,status='proposed',revision=EXCLUDED.revision,proposed_by=EXCLUDED.proposed_by,confirmed_at=NULL,updated_at=stamp
   RETURNING * INTO saved;
 ELSE
  UPDATE issuance_service.application_ownerships SET status=CASE WHEN requested_action='confirm' THEN 'confirmed' ELSE 'revoked' END,
   revision=expected_revision+1,confirmed_at=CASE WHEN requested_action='confirm' THEN stamp ELSE NULL END,updated_at=stamp
   WHERE organization_id=org AND application_id=app RETURNING * INTO saved;
 END IF;
 IF saved.organization_id IS DISTINCT FROM org OR saved.application_id IS DISTINCT FROM app
  OR saved.revision IS DISTINCT FROM expected_revision+1 OR saved.updated_at IS DISTINCT FROM stamp
  OR (requested_action='propose' AND (saved.user_id IS DISTINCT FROM proposed_user OR saved.subject_id IS DISTINCT FROM canonical.applicant_identifier
    OR saved.application_revision IS DISTINCT FROM expected_application_revision OR saved.status IS DISTINCT FROM 'proposed'
    OR saved.proposed_by IS DISTINCT FROM actor OR saved.confirmed_at IS NOT NULL))
  OR (requested_action<>'propose' AND ((to_jsonb(saved)-ARRAY['status','revision','confirmed_at','updated_at']) IS DISTINCT FROM
    (to_jsonb(before_row)-ARRAY['status','revision','confirmed_at','updated_at'])
    OR saved.status IS DISTINCT FROM (CASE WHEN requested_action='confirm' THEN 'confirmed' ELSE 'revoked' END)
    OR saved.confirmed_at IS DISTINCT FROM (CASE WHEN requested_action='confirm' THEN stamp ELSE NULL::timestamptz END))) THEN
   RAISE EXCEPTION 'Application ownership postimage changed' USING ERRCODE='23514'; END IF;
 answer:=jsonb_build_object('operation_id',op,'application_id',app,'action',requested_action,
  'revision',saved.revision,'status',saved.status);
 INSERT INTO issuance_service.application_ownership_operations(operation_id,organization_id,application_id,actor_id,action,intent,receipt,created_at)
  VALUES(op,org,app,actor,requested_action,wanted_intent,answer,stamp);
 -- Recheck after audit triggers. No partial success or adoption of trigger rewrites.
 SELECT * INTO actual FROM issuance_service.application_ownerships WHERE organization_id=org AND application_id=app;
 SELECT * INTO prior FROM issuance_service.application_ownership_operations WHERE operation_id=op;
 IF to_jsonb(actual) IS DISTINCT FROM to_jsonb(saved) OR prior.organization_id IS DISTINCT FROM org OR prior.application_id IS DISTINCT FROM app
  OR prior.actor_id IS DISTINCT FROM actor OR prior.action IS DISTINCT FROM requested_action OR prior.intent IS DISTINCT FROM wanted_intent
  OR prior.receipt IS DISTINCT FROM answer OR prior.created_at IS DISTINCT FROM stamp THEN
   RAISE EXCEPTION 'Application ownership audit changed' USING ERRCODE='23514'; END IF;
 IF requested_action<>'revoke' AND NOT EXISTS(SELECT 1 FROM issuance_service.applications a WHERE a.id=app AND a.organization_id=org::text
  AND a.applicant_identifier=saved.subject_id AND (extract(epoch FROM a.updated_at)*1000000)::bigint=expected_application_revision
  AND a.status IN ('pending','under_review') AND a.expires_at>clock_timestamp()) THEN
   RAISE EXCEPTION 'Application ownership authority changed' USING ERRCODE='23514'; END IF;
 IF NOT EXISTS(SELECT 1 FROM issuance_service.external_observation_lock_organization(org) WHERE status='active') THEN
  RAISE EXCEPTION 'Application ownership organization changed' USING ERRCODE='23514'; END IF;
 IF requested_action<>'confirm' AND NOT EXISTS(SELECT 1 FROM issuance_service.application_ownership_lock_administrator(org,actor)) THEN
  RAISE EXCEPTION 'Application ownership administrator changed' USING ERRCODE='23514'; END IF;
 RETURN answer;
END;
$$;
-- Session actor only. A historical receipt and a fresh current-state read have
-- deliberately different shapes; receipts cannot be mistaken for authority.
CREATE FUNCTION issuance_service.read_application_ownership(org uuid,app text,actor text,requested_operation uuid)
RETURNS jsonb LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE saved issuance_service.application_ownerships; original issuance_service.application_ownership_operations;
 canonical record; administrator boolean;
BEGIN
 IF org IS NULL OR org='00000000-0000-0000-0000-000000000000' OR app IS NULL OR app !~ '^[A-Za-z0-9_-]{1,128}$'
  OR actor IS NULL OR actor !~ '^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$'
  OR requested_operation='00000000-0000-0000-0000-000000000000' THEN RETURN NULL; END IF;
 IF NOT EXISTS(SELECT 1 FROM issuance_service.external_observation_lock_organization(org) WHERE status='active') THEN RETURN NULL; END IF;
 IF requested_operation IS NOT NULL THEN
  SELECT * INTO original FROM issuance_service.application_ownership_operations WHERE operation_id=requested_operation
   AND organization_id=org AND application_id=app AND actor_id=actor;
  IF NOT FOUND OR (original.action<>'confirm' AND NOT EXISTS(SELECT 1 FROM issuance_service.application_ownership_lock_administrator(org,actor))) THEN RETURN NULL; END IF;
  RETURN jsonb_build_object('kind','receipt','receipt',original.receipt);
 END IF;
 administrator:=EXISTS(SELECT 1 FROM issuance_service.application_ownership_lock_administrator(org,actor));
 SELECT * INTO canonical FROM issuance_service.external_observation_lock_application(app,org::text);
 IF NOT FOUND THEN RETURN NULL; END IF;
 SELECT * INTO saved FROM issuance_service.application_ownerships WHERE organization_id=org AND application_id=app FOR SHARE;
 IF NOT FOUND THEN
  IF administrator THEN RETURN jsonb_build_object('kind','current','record',NULL); END IF;
  RETURN NULL;
 END IF;
 IF NOT administrator AND saved.user_id<>actor THEN RETURN NULL; END IF;
 RETURN jsonb_build_object('kind','current','record',jsonb_build_object('application_id',app,'user_id',saved.user_id,
  'revision',saved.revision,'status',saved.status,'application_revision',(extract(epoch FROM canonical.updated_at)*1000000)::bigint,
  'proposal_application_revision',saved.application_revision,
  'current',COALESCE(saved.status='confirmed' AND saved.subject_id=canonical.applicant_identifier
   AND saved.application_revision=(extract(epoch FROM canonical.updated_at)*1000000)::bigint
   AND canonical.status IN ('pending','under_review') AND canonical.expires_at>clock_timestamp(),false)));
END;
$$;
REVOKE ALL ON TABLE issuance_service.application_ownerships,issuance_service.application_ownership_operations FROM PUBLIC;
REVOKE ALL ON FUNCTION issuance_service.guard_application_ownership(),issuance_service.keep_application_ownership_operation(),
 issuance_service.application_ownership_lock_administrator(uuid,text),
 issuance_service.mutate_application_ownership(uuid,text,text,uuid,text,bigint,bigint,text),
 issuance_service.read_application_ownership(uuid,text,text,uuid) FROM PUBLIC;

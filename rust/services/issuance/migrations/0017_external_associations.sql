-- SPDX-License-Identifier: AGPL-3.0-only
-- Generic Core authority for approved producer attestations and learner consent.
-- No provider JWT, email, role, bearer token or browser code is stored here.
CREATE TABLE issuance_service.external_association_sources (
 id uuid PRIMARY KEY CHECK(id<>'00000000-0000-0000-0000-000000000000'),
 organization_id uuid NOT NULL REFERENCES organization_service.organizations(id) ON DELETE RESTRICT,
 source_id text NOT NULL CHECK(source_id ~ '^[A-Za-z0-9_-]{1,128}$'),
 api_key_id uuid NOT NULL REFERENCES organization_service.api_keys(id) ON DELETE RESTRICT,
 key_revision bigint NOT NULL CHECK(key_revision BETWEEN 1 AND 9007199254740991),
 active boolean NOT NULL DEFAULT false,
 revision bigint NOT NULL CHECK(revision BETWEEN 1 AND 9007199254740991),
 expires_at timestamptz NOT NULL,
 created_by text NOT NULL CHECK(created_by ~ '^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$'),
 approved_by text CHECK(approved_by ~ '^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$'),
 approved_at timestamptz,
 created_at timestamptz NOT NULL,
 updated_at timestamptz NOT NULL,
 CHECK((approved_by IS NULL)=(approved_at IS NULL)),
 CHECK(NOT active OR approved_by IS NOT NULL),
 UNIQUE(organization_id,source_id), UNIQUE(id,organization_id,source_id)
);
CREATE TABLE issuance_service.external_association_operations (
 operation_id uuid PRIMARY KEY CHECK(operation_id<>'00000000-0000-0000-0000-000000000000'),
 organization_id uuid NOT NULL REFERENCES organization_service.organizations(id) ON DELETE RESTRICT,
 actor_type text NOT NULL CHECK(actor_type IN ('user','api_key','system')),
 actor_id text NOT NULL CHECK(actor_id ~ '^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$'),
 resource_id uuid NOT NULL,
 action text NOT NULL CHECK(action IN ('source.create','source.approve','source.revoke','source.replace-key','source.change-expiry',
  'challenge.create','challenge.confirm','challenge.deny','challenge.abandon','challenge.expire','association.unlink')),
 intent jsonb NOT NULL CHECK(jsonb_typeof(intent)='object'),
 receipt jsonb NOT NULL CHECK(jsonb_typeof(receipt)='object'),
 created_at timestamptz NOT NULL
);
CREATE TABLE issuance_service.external_association_identities (
 id uuid PRIMARY KEY CHECK(id<>'00000000-0000-0000-0000-000000000000'),
 organization_id uuid NOT NULL,
 source_id text NOT NULL,
 provider_reference text COLLATE "C" NOT NULL CHECK(provider_reference ~ '^[a-f0-9]{64}$'),
 user_id text NOT NULL CHECK(user_id ~ '^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$'),
 active boolean NOT NULL,
 revision bigint NOT NULL CHECK(revision BETWEEN 1 AND 9007199254740991),
 created_at timestamptz NOT NULL, updated_at timestamptz NOT NULL,
 FOREIGN KEY(organization_id,source_id) REFERENCES issuance_service.external_association_sources(organization_id,source_id) ON DELETE RESTRICT,
 UNIQUE(organization_id,source_id,provider_reference), UNIQUE(id,organization_id,source_id)
);
CREATE TABLE issuance_service.external_association_challenges (
 id uuid PRIMARY KEY CHECK(id<>'00000000-0000-0000-0000-000000000000'),
 organization_id uuid NOT NULL,
 source_grant_id uuid NOT NULL, source_id text NOT NULL,
 source_revision bigint NOT NULL CHECK(source_revision BETWEEN 1 AND 9007199254740991),
 api_key_id uuid NOT NULL REFERENCES organization_service.api_keys(id) ON DELETE RESTRICT,
 key_revision bigint NOT NULL CHECK(key_revision BETWEEN 1 AND 9007199254740991),
 binding_id text NOT NULL,
 binding_revision bigint NOT NULL CHECK(binding_revision BETWEEN 1 AND 9007199254740991),
 application_id varchar NOT NULL REFERENCES issuance_service.applications(id) ON DELETE RESTRICT,
 application_revision bigint NOT NULL CHECK(application_revision BETWEEN 1 AND 9007199254740991),
 ownership_revision bigint NOT NULL CHECK(ownership_revision BETWEEN 1 AND 9007199254740991),
 user_id text NOT NULL CHECK(user_id ~ '^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$'),
 subject_id text NOT NULL CHECK(octet_length(subject_id) BETWEEN 1 AND 1024),
 provider_reference text COLLATE "C" NOT NULL CHECK(provider_reference ~ '^[a-f0-9]{64}$'),
 provider_revision bigint NOT NULL CHECK(provider_revision BETWEEN 1 AND 9007199254740991),
 code_hash text COLLATE "C" NOT NULL UNIQUE CHECK(code_hash ~ '^[a-f0-9]{64}$'),
 phase text NOT NULL CHECK(phase IN ('pending','confirmed','denied','abandoned','expired')),
 revision bigint NOT NULL CHECK(revision BETWEEN 1 AND 9007199254740991),
 created_at timestamptz NOT NULL, expires_at timestamptz NOT NULL, updated_at timestamptz NOT NULL,
 CHECK(expires_at>created_at AND expires_at<=created_at+interval '5minutes'),
 FOREIGN KEY(source_grant_id,organization_id,source_id) REFERENCES issuance_service.external_association_sources(id,organization_id,source_id) ON DELETE RESTRICT,
 FOREIGN KEY(binding_id,organization_id,source_id) REFERENCES issuance_service.external_observation_bindings(id,organization_id,source_id) ON DELETE RESTRICT
);
CREATE TABLE issuance_service.external_association_bindings (
 identity_id uuid NOT NULL, organization_id uuid NOT NULL, source_id text NOT NULL,
 binding_id text NOT NULL,
 binding_revision bigint NOT NULL CHECK(binding_revision BETWEEN 1 AND 9007199254740991),
 challenge_id uuid NOT NULL UNIQUE REFERENCES issuance_service.external_association_challenges(id) ON DELETE RESTRICT,
 active boolean NOT NULL,
 revision bigint NOT NULL CHECK(revision BETWEEN 1 AND 9007199254740991),
 created_at timestamptz NOT NULL, updated_at timestamptz NOT NULL,
 PRIMARY KEY(identity_id,binding_id),
 FOREIGN KEY(identity_id,organization_id,source_id) REFERENCES issuance_service.external_association_identities(id,organization_id,source_id) ON DELETE RESTRICT,
 FOREIGN KEY(binding_id,organization_id,source_id) REFERENCES issuance_service.external_observation_bindings(id,organization_id,source_id) ON DELETE RESTRICT
);
CREATE INDEX external_association_operations_resource ON issuance_service.external_association_operations(organization_id,resource_id,created_at,operation_id);
CREATE INDEX external_association_challenges_pending ON issuance_service.external_association_challenges(expires_at,id) WHERE phase='pending';

CREATE FUNCTION issuance_service.guard_external_association_source()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
 IF TG_OP='DELETE' OR (to_jsonb(NEW)-ARRAY['api_key_id','key_revision','active','revision','expires_at','approved_by','approved_at','updated_at']) IS DISTINCT FROM
  (to_jsonb(OLD)-ARRAY['api_key_id','key_revision','active','revision','expires_at','approved_by','approved_at','updated_at'])
  OR NEW.revision IS DISTINCT FROM OLD.revision+1 OR NEW.updated_at<OLD.updated_at THEN
  RAISE EXCEPTION 'Invalid association source revision' USING ERRCODE='23514'; END IF;
 RETURN NEW;
END;
$$;
CREATE TRIGGER external_association_source_revision BEFORE UPDATE OR DELETE ON issuance_service.external_association_sources
 FOR EACH ROW EXECUTE FUNCTION issuance_service.guard_external_association_source();
CREATE FUNCTION issuance_service.keep_external_association_operation()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN RAISE EXCEPTION 'Association operation history is immutable' USING ERRCODE='23514';END;
$$;
CREATE TRIGGER external_association_operation_immutable BEFORE UPDATE OR DELETE ON issuance_service.external_association_operations
 FOR EACH ROW EXECUTE FUNCTION issuance_service.keep_external_association_operation();

CREATE FUNCTION issuance_service.external_association_lock_administrator(org uuid,actor text)
RETURNS TABLE(id uuid) LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT m.id FROM organization_service.organizations o
 JOIN organization_service.members m ON m.organization_id=o.id
 JOIN organization_service.member_roles mr ON mr.member_id=m.id
 JOIN organization_service.roles r ON r.id=mr.role_id AND r.organization_id=o.id
 JOIN organization_service.role_permissions rp ON rp.role_id=r.id
 JOIN organization_service.permissions p ON p.id=rp.permission_id
 WHERE o.id=org AND o.status='active' AND m.user_id=actor AND m.status='active'
  AND p.resource='external-association' AND p.action='manage'
 ORDER BY m.id,r.id,p.id FOR SHARE OF o,m,mr,r,rp,p;
$$;

-- Source registration approves only identity attestations for currently active
-- canonical bindings of that source. It cannot create/activate a binding, change
-- ownership or obtain evidence:submit. Every later challenge must recheck all.
CREATE FUNCTION issuance_service.mutate_external_association_source(org uuid,actor text,op uuid,grant_id uuid,
 requested_action text,expected_revision bigint,definition jsonb)
RETURNS jsonb LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE before_row issuance_service.external_association_sources; saved issuance_service.external_association_sources;
 actual issuance_service.external_association_sources; history issuance_service.external_association_operations;
 key_row record; discovered_key uuid; target_key uuid; target_key_revision bigint; target_source text;
 target_expiry timestamptz; expiry_ms bigint; expected_intent jsonb; answer jsonb; stamp timestamptz;
 known boolean; fields text[];
BEGIN
 IF org IS NULL OR org='00000000-0000-0000-0000-000000000000' OR actor IS NULL
  OR actor !~ '^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$' OR op IS NULL OR op='00000000-0000-0000-0000-000000000000'
  OR grant_id IS NULL OR grant_id='00000000-0000-0000-0000-000000000000'
  OR requested_action IS NULL OR requested_action NOT IN ('create','approve','revoke','replace-key','change-expiry')
  OR expected_revision IS NULL OR expected_revision NOT BETWEEN 0 AND 9007199254740990
  OR definition IS NULL OR jsonb_typeof(definition)<>'object' THEN RETURN NULL; END IF;
 fields:=CASE requested_action WHEN 'create' THEN ARRAY['api_key_id','expires_at_ms','key_revision','source_id']
  WHEN 'replace-key' THEN ARRAY['api_key_id','key_revision'] WHEN 'change-expiry' THEN ARRAY['expires_at_ms'] ELSE ARRAY[]::text[] END;
 IF ARRAY(SELECT key FROM jsonb_object_keys(definition) key ORDER BY key COLLATE "C") IS DISTINCT FROM fields THEN RETURN NULL; END IF;
 IF requested_action IN ('create','replace-key') THEN
  IF jsonb_typeof(definition->'api_key_id') IS DISTINCT FROM 'string' OR definition->>'api_key_id' !~ '^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$'
   OR definition->>'api_key_id'='00000000-0000-0000-0000-000000000000'
   OR jsonb_typeof(definition->'key_revision') IS DISTINCT FROM 'number' OR definition->>'key_revision' !~ '^[0-9]{1,16}$'
   OR (definition->>'key_revision')::numeric NOT BETWEEN 1 AND 9007199254740991 THEN RETURN NULL; END IF;
  target_key:=(definition->>'api_key_id')::uuid;target_key_revision:=(definition->>'key_revision')::bigint;
 END IF;
 IF requested_action IN ('create','change-expiry') THEN
  IF jsonb_typeof(definition->'expires_at_ms') IS DISTINCT FROM 'number' OR definition->>'expires_at_ms' !~ '^[0-9]{1,16}$'
   OR (definition->>'expires_at_ms')::numeric NOT BETWEEN 1 AND 9007199254740991 THEN RETURN NULL; END IF;
  expiry_ms:=(definition->>'expires_at_ms')::bigint;
 END IF;
 IF requested_action='create' AND (jsonb_typeof(definition->'source_id') IS DISTINCT FROM 'string'
  OR definition->>'source_id' !~ '^[A-Za-z0-9_-]{1,128}$') THEN RETURN NULL; END IF;
 IF NOT EXISTS(SELECT 1 FROM issuance_service.external_observation_lock_organization(org) WHERE status='active')
  OR NOT EXISTS(SELECT 1 FROM issuance_service.external_association_lock_administrator(org,actor)) THEN RETURN NULL; END IF;
 expected_intent:=jsonb_build_object('expected_revision',expected_revision,'definition',definition);
 PERFORM pg_advisory_xact_lock(hashtextextended('external-association-operation:'||op::text,0));
 SELECT * INTO history FROM issuance_service.external_association_operations WHERE operation_id=op;
 IF FOUND THEN
  IF history.organization_id=org AND history.actor_type='user' AND history.actor_id=actor AND history.resource_id=grant_id
   AND history.action='source.'||requested_action AND history.intent=expected_intent THEN RETURN history.receipt; END IF;
  RETURN NULL;
 END IF;
 SELECT api_key_id INTO discovered_key FROM issuance_service.external_association_sources WHERE id=grant_id AND organization_id=org;
 known:=FOUND;
 -- Lock canonical keys before the source row, in the shared canonical key order.
 PERFORM 1 FROM issuance_service.external_observation_lock_api_keys(org,array_remove(ARRAY[discovered_key,target_key],NULL));
 SELECT * INTO before_row FROM issuance_service.external_association_sources WHERE id=grant_id AND organization_id=org FOR UPDATE;
 IF (FOUND AND (NOT known OR before_row.api_key_id IS DISTINCT FROM discovered_key OR before_row.revision<>expected_revision OR requested_action='create'))
  OR (NOT FOUND AND (known OR requested_action<>'create' OR expected_revision<>0)) THEN RETURN NULL; END IF;
 IF requested_action<>'create' THEN
  target_source:=before_row.source_id;
  IF requested_action<>'replace-key' THEN target_key:=before_row.api_key_id;target_key_revision:=before_row.key_revision;END IF;
  target_expiry:=before_row.expires_at;
 ELSE target_source:=definition->>'source_id'; END IF;
 IF requested_action IN ('create','change-expiry') THEN
  IF expiry_ms<=floor(extract(epoch FROM clock_timestamp())*1000)::bigint
   OR expiry_ms>floor(extract(epoch FROM clock_timestamp())*1000)::bigint+31536000000 THEN RETURN NULL; END IF;
  target_expiry:=to_timestamp(expiry_ms/1000.0);
 END IF;
 IF requested_action IN ('create','replace-key','approve') THEN
  SELECT * INTO key_row FROM issuance_service.external_observation_lock_api_keys(org,ARRAY[target_key]);
  IF NOT FOUND OR key_row.status IS DISTINCT FROM 'active' OR key_row.enabled IS DISTINCT FROM true
   OR key_row.scope_type IS DISTINCT FROM 'ORGANIZATION' OR key_row.deployment_profile_id IS NOT NULL
   OR NOT COALESCE('identity:attest'=ANY(key_row.scopes),false)
   OR key_row.updated_at IS NULL OR (extract(epoch FROM key_row.updated_at)*1000000)::bigint<>target_key_revision
   OR target_expiry<=clock_timestamp() OR (key_row.expires_at IS NOT NULL AND key_row.expires_at<target_expiry) THEN RETURN NULL; END IF;
 END IF;
 stamp:=clock_timestamp();
 IF requested_action='create' THEN
  INSERT INTO issuance_service.external_association_sources(id,organization_id,source_id,api_key_id,key_revision,active,revision,expires_at,
   created_by,approved_by,approved_at,created_at,updated_at)
  VALUES(grant_id,org,target_source,target_key,target_key_revision,false,1,target_expiry,actor,NULL,NULL,stamp,stamp) RETURNING * INTO saved;
 ELSE
  UPDATE issuance_service.external_association_sources SET api_key_id=target_key,key_revision=target_key_revision,
   active=requested_action='approve',revision=expected_revision+1,expires_at=target_expiry,
   approved_by=CASE WHEN requested_action='approve' THEN actor ELSE NULL END,
   approved_at=CASE WHEN requested_action='approve' THEN stamp ELSE NULL END,updated_at=stamp
   WHERE id=grant_id AND organization_id=org RETURNING * INTO saved;
 END IF;
 IF saved.id IS DISTINCT FROM grant_id OR saved.organization_id IS DISTINCT FROM org OR saved.source_id IS DISTINCT FROM target_source
  OR saved.api_key_id IS DISTINCT FROM target_key OR saved.key_revision IS DISTINCT FROM target_key_revision
  OR saved.revision IS DISTINCT FROM expected_revision+1 OR saved.expires_at IS DISTINCT FROM target_expiry
  OR saved.active IS DISTINCT FROM (requested_action='approve') OR saved.updated_at IS DISTINCT FROM stamp
  OR saved.approved_by IS DISTINCT FROM (CASE WHEN requested_action='approve' THEN actor ELSE NULL END)
  OR saved.approved_at IS DISTINCT FROM (CASE WHEN requested_action='approve' THEN stamp ELSE NULL::timestamptz END)
  OR (requested_action='create' AND (saved.created_by IS DISTINCT FROM actor OR saved.created_at IS DISTINCT FROM stamp))
  OR (requested_action<>'create' AND (saved.created_by IS DISTINCT FROM before_row.created_by OR saved.created_at IS DISTINCT FROM before_row.created_at)) THEN
  RAISE EXCEPTION 'Association source postimage changed' USING ERRCODE='23514'; END IF;
 answer:=jsonb_build_object('operation_id',op,'source_grant_id',grant_id,'action',requested_action,'revision',saved.revision,'active',saved.active);
 INSERT INTO issuance_service.external_association_operations(operation_id,organization_id,actor_type,actor_id,resource_id,action,intent,receipt,created_at)
  VALUES(op,org,'user',actor,grant_id,'source.'||requested_action,expected_intent,answer,stamp);
 SELECT * INTO actual FROM issuance_service.external_association_sources WHERE id=grant_id;
 SELECT * INTO history FROM issuance_service.external_association_operations WHERE operation_id=op;
 IF to_jsonb(actual) IS DISTINCT FROM to_jsonb(saved) OR history.organization_id IS DISTINCT FROM org
  OR history.actor_type IS DISTINCT FROM 'user' OR history.actor_id IS DISTINCT FROM actor OR history.resource_id IS DISTINCT FROM grant_id
  OR history.action IS DISTINCT FROM 'source.'||requested_action OR history.intent IS DISTINCT FROM expected_intent
  OR history.receipt IS DISTINCT FROM answer OR history.created_at IS DISTINCT FROM stamp THEN
  RAISE EXCEPTION 'Association source audit changed' USING ERRCODE='23514'; END IF;
 IF NOT EXISTS(SELECT 1 FROM issuance_service.external_association_lock_administrator(org,actor)) THEN
  RAISE EXCEPTION 'Association source administrator changed' USING ERRCODE='23514'; END IF;
 IF requested_action='approve' AND NOT EXISTS(SELECT 1 FROM issuance_service.external_observation_lock_api_keys(org,ARRAY[target_key]) k
  WHERE k.status='active' AND k.enabled AND k.scope_type='ORGANIZATION' AND k.deployment_profile_id IS NULL
   AND 'identity:attest'=ANY(k.scopes) AND (extract(epoch FROM k.updated_at)*1000000)::bigint=target_key_revision
   AND (k.expires_at IS NULL OR k.expires_at>=target_expiry) AND target_expiry>clock_timestamp()) THEN
  RAISE EXCEPTION 'Association source key changed' USING ERRCODE='23514'; END IF;
 RETURN answer;
END;
$$;
REVOKE ALL ON TABLE issuance_service.external_association_sources,issuance_service.external_association_operations,
 issuance_service.external_association_identities,issuance_service.external_association_challenges,issuance_service.external_association_bindings FROM PUBLIC;
REVOKE ALL ON FUNCTION issuance_service.guard_external_association_source(),issuance_service.keep_external_association_operation(),
 issuance_service.external_association_lock_administrator(uuid,text),
 issuance_service.mutate_external_association_source(uuid,text,uuid,uuid,text,bigint,jsonb) FROM PUBLIC;

-- Historical recovery never represents current delegation. Only the original
-- authenticated administrator may recover its receipt; current administration
-- is checked independently before either read. No producer identity is accepted.
CREATE FUNCTION issuance_service.read_external_association_source(org uuid,actor text,grant_id uuid,original_operation uuid)
RETURNS jsonb LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE saved issuance_service.external_association_sources; discovered_key uuid;
 history issuance_service.external_association_operations; key_row record; usable boolean;
BEGIN
 IF org IS NULL OR org='00000000-0000-0000-0000-000000000000' OR actor IS NULL
  OR actor !~ '^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$' OR grant_id IS NULL
  OR grant_id='00000000-0000-0000-0000-000000000000'
  OR original_operation='00000000-0000-0000-0000-000000000000' THEN RETURN NULL; END IF;
 IF NOT EXISTS(SELECT 1 FROM issuance_service.external_observation_lock_organization(org) WHERE status='active')
  OR NOT EXISTS(SELECT 1 FROM issuance_service.external_association_lock_administrator(org,actor)) THEN RETURN NULL; END IF;
 IF original_operation IS NOT NULL THEN
  SELECT * INTO history FROM issuance_service.external_association_operations WHERE operation_id=original_operation;
  IF NOT FOUND OR history.organization_id<>org OR history.resource_id<>grant_id
   OR history.actor_type<>'user' OR history.actor_id<>actor OR history.action NOT IN
    ('source.create','source.approve','source.revoke','source.replace-key','source.change-expiry') THEN RETURN NULL; END IF;
  RETURN jsonb_build_object('kind','receipt','receipt',history.receipt);
 END IF;
 SELECT api_key_id INTO discovered_key FROM issuance_service.external_association_sources WHERE id=grant_id AND organization_id=org;
 IF NOT FOUND THEN RETURN NULL; END IF;
 -- Match mutation ordering and reject a source replaced after discovery.
 SELECT * INTO key_row FROM issuance_service.external_observation_lock_api_keys(org,ARRAY[discovered_key]);
 SELECT * INTO saved FROM issuance_service.external_association_sources WHERE id=grant_id AND organization_id=org FOR SHARE;
 IF NOT FOUND OR saved.api_key_id IS DISTINCT FROM discovered_key THEN RETURN NULL; END IF;
 usable:=COALESCE(saved.active AND saved.approved_by IS NOT NULL AND saved.expires_at>clock_timestamp()
  AND key_row.id=saved.api_key_id AND key_row.status='active' AND key_row.enabled
  AND key_row.scope_type='ORGANIZATION' AND key_row.deployment_profile_id IS NULL
  AND 'identity:attest'=ANY(key_row.scopes)
  AND (extract(epoch FROM key_row.updated_at)*1000000)::bigint=saved.key_revision
  AND (key_row.expires_at IS NULL OR key_row.expires_at>=saved.expires_at),false);
 RETURN jsonb_build_object('kind','current','record',jsonb_build_object('source_grant_id',saved.id,
  'source_id',saved.source_id,'api_key_id',saved.api_key_id,'key_revision',saved.key_revision,
  'revision',saved.revision,'active',saved.active,'current',usable,
  'expires_at_ms',floor(extract(epoch FROM saved.expires_at)*1000)::bigint));
END;
$$;
REVOKE ALL ON FUNCTION issuance_service.read_external_association_source(uuid,text,uuid,uuid) FROM PUBLIC;

-- Canonical rows remain Core-owned. This owner-installed helper only locks and
-- reads current authority; a producer can supply neither subject nor user.
CREATE FUNCTION issuance_service.external_association_lock_context(org uuid,producer uuid,grant_id uuid,
 expected_source_revision bigint,binding text,expected_binding_revision bigint)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE source issuance_service.external_association_sources; key_row record; bound record; app record;
 ownership issuance_service.application_ownerships;
BEGIN
 IF NOT EXISTS(SELECT 1 FROM issuance_service.external_observation_lock_organization(org) WHERE status='active') THEN RETURN NULL; END IF;
 SELECT * INTO key_row FROM issuance_service.external_observation_lock_api_keys(org,ARRAY[producer]);
 IF NOT FOUND OR key_row.status IS DISTINCT FROM 'active' OR key_row.enabled IS DISTINCT FROM true
  OR key_row.scope_type IS DISTINCT FROM 'ORGANIZATION' OR key_row.deployment_profile_id IS NOT NULL
  OR NOT COALESCE('identity:attest'=ANY(key_row.scopes),false) THEN RETURN NULL; END IF;
 SELECT * INTO source FROM issuance_service.external_association_sources
  WHERE id=grant_id AND organization_id=org AND api_key_id=producer FOR SHARE;
 IF NOT FOUND OR NOT source.active OR source.approved_by IS NULL OR source.revision IS DISTINCT FROM expected_source_revision
  OR source.expires_at<=clock_timestamp() OR key_row.updated_at IS NULL
  OR (extract(epoch FROM key_row.updated_at)*1000000)::bigint<>source.key_revision
  OR (key_row.expires_at IS NOT NULL AND key_row.expires_at<source.expires_at) THEN RETURN NULL; END IF;
 SELECT * INTO bound FROM issuance_service.external_observation_bindings
  WHERE id=binding AND organization_id=org AND source_id=source.source_id FOR SHARE;
 IF NOT FOUND OR bound.active IS DISTINCT FROM true OR bound.revision IS DISTINCT FROM expected_binding_revision THEN RETURN NULL; END IF;
 SELECT * INTO app FROM issuance_service.external_observation_lock_application(bound.application_id,org::text);
 IF NOT FOUND OR app.status NOT IN ('pending','under_review') OR app.applicant_identifier IS NULL
  OR app.applicant_identifier IS DISTINCT FROM bound.subject_id OR app.expires_at IS NULL OR app.expires_at<=clock_timestamp()
  OR app.updated_at IS NULL THEN RETURN NULL; END IF;
 SELECT * INTO ownership FROM issuance_service.application_ownerships
  WHERE organization_id=org AND application_id=app.id FOR SHARE;
 IF NOT FOUND OR ownership.status<>'confirmed' OR ownership.subject_id IS DISTINCT FROM app.applicant_identifier
  OR ownership.application_revision IS DISTINCT FROM (extract(epoch FROM app.updated_at)*1000000)::bigint THEN RETURN NULL; END IF;
 RETURN jsonb_build_object('source_id',source.source_id,'source_revision',source.revision,'key_revision',source.key_revision,
  'binding_revision',bound.revision,'application_id',app.id,
  'application_revision',ownership.application_revision,'ownership_revision',ownership.revision,
  'user_id',ownership.user_id,'subject_id',ownership.subject_id,
  'source_expires_at_ms',floor(extract(epoch FROM source.expires_at)*1000)::bigint,
  'application_expires_at_ms',floor(extract(epoch FROM app.expires_at)*1000)::bigint);
END;
$$;

CREATE FUNCTION issuance_service.guard_external_association_challenge()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
 IF TG_OP='DELETE' OR OLD.phase<>'pending' OR NEW.phase='pending'
  OR NEW.revision IS DISTINCT FROM OLD.revision+1 OR NEW.updated_at<OLD.updated_at
  OR (to_jsonb(NEW)-ARRAY['phase','revision','updated_at']) IS DISTINCT FROM
     (to_jsonb(OLD)-ARRAY['phase','revision','updated_at']) THEN
  RAISE EXCEPTION 'Invalid association challenge transition' USING ERRCODE='23514'; END IF;
 RETURN NEW;
END;
$$;
CREATE TRIGGER external_association_challenge_revision BEFORE UPDATE OR DELETE ON issuance_service.external_association_challenges
 FOR EACH ROW EXECUTE FUNCTION issuance_service.guard_external_association_challenge();

-- producer is a Gateway-authenticated canonical API-key ID. The original random
-- code is retained by the connector; only its SHA256 reaches this transaction.
CREATE FUNCTION issuance_service.create_external_association_challenge(org uuid,producer uuid,op uuid,challenge uuid,
 grant_id uuid,expected_source_revision bigint,binding text,expected_binding_revision bigint,
 external_reference text,external_revision bigint,proof_hash text,expires_at_ms bigint)
RETURNS jsonb LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE context jsonb; intent jsonb; answer jsonb; stamp timestamptz; key_row record;
 history issuance_service.external_association_operations; expected_history issuance_service.external_association_operations;
 wanted issuance_service.external_association_challenges; saved issuance_service.external_association_challenges;
 actual issuance_service.external_association_challenges;
BEGIN
 IF org IS NULL OR org='00000000-0000-0000-0000-000000000000' OR producer IS NULL OR producer='00000000-0000-0000-0000-000000000000'
  OR op IS NULL OR op='00000000-0000-0000-0000-000000000000' OR challenge IS NULL OR challenge='00000000-0000-0000-0000-000000000000'
  OR grant_id IS NULL OR grant_id='00000000-0000-0000-0000-000000000000'
  OR expected_source_revision IS NULL OR expected_source_revision NOT BETWEEN 1 AND 9007199254740991
  OR binding IS NULL OR binding !~ '^[A-Za-z0-9_-]{1,128}$'
  OR expected_binding_revision IS NULL OR expected_binding_revision NOT BETWEEN 1 AND 9007199254740991
  OR external_reference IS NULL OR external_reference !~ '^[a-f0-9]{64}$'
  OR external_revision IS NULL OR external_revision NOT BETWEEN 1 AND 9007199254740991
  OR proof_hash IS NULL OR proof_hash !~ '^[a-f0-9]{64}$'
  OR expires_at_ms IS NULL OR expires_at_ms NOT BETWEEN 1 AND 9007199254740991 THEN RETURN NULL; END IF;
 IF NOT EXISTS(SELECT 1 FROM issuance_service.external_observation_lock_organization(org) WHERE status='active') THEN RETURN NULL; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('external-association-operation:'||op::text,0));
 SELECT * INTO key_row FROM issuance_service.external_observation_lock_api_keys(org,ARRAY[producer]);
 IF NOT FOUND OR key_row.status IS DISTINCT FROM 'active' OR key_row.enabled IS DISTINCT FROM true
  OR key_row.scope_type IS DISTINCT FROM 'ORGANIZATION' OR key_row.deployment_profile_id IS NOT NULL
  OR NOT COALESCE('identity:attest'=ANY(key_row.scopes),false)
  OR (key_row.expires_at IS NOT NULL AND key_row.expires_at<=clock_timestamp()) THEN RETURN NULL; END IF;
 intent:=jsonb_build_object('source_grant_id',grant_id,'expected_source_revision',expected_source_revision,
  'binding_id',binding,'expected_binding_revision',expected_binding_revision,'provider_reference',external_reference,
  'provider_revision',external_revision,'code_hash',proof_hash,'expires_at_ms',expires_at_ms);
 SELECT * INTO history FROM issuance_service.external_association_operations WHERE operation_id=op;
 IF FOUND THEN
  IF history.organization_id=org AND history.actor_type='api_key' AND history.actor_id=producer::text
   AND history.resource_id=challenge AND history.action='challenge.create' AND history.intent=intent THEN RETURN history.receipt; END IF;
  RETURN NULL;
 END IF;
 context:=issuance_service.external_association_lock_context(org,producer,grant_id,expected_source_revision,binding,expected_binding_revision);
 IF context IS NULL THEN RETURN NULL; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('external-association-challenge:'||challenge::text,0));
 IF EXISTS(SELECT 1 FROM issuance_service.external_association_challenges WHERE id=challenge) THEN RETURN NULL; END IF;
 stamp:=clock_timestamp();
 IF expires_at_ms<=floor(extract(epoch FROM stamp)*1000)::bigint OR expires_at_ms>floor(extract(epoch FROM stamp)*1000)::bigint+300000
  OR expires_at_ms>(context->>'source_expires_at_ms')::bigint OR expires_at_ms>(context->>'application_expires_at_ms')::bigint THEN RETURN NULL; END IF;
 wanted:=jsonb_populate_record(NULL::issuance_service.external_association_challenges,jsonb_build_object(
  'id',challenge,'organization_id',org,'source_grant_id',grant_id,'source_id',context->>'source_id',
  'source_revision',expected_source_revision,'api_key_id',producer,'key_revision',(context->>'key_revision')::bigint,
  'binding_id',binding,'binding_revision',expected_binding_revision,'application_id',context->>'application_id',
  'application_revision',(context->>'application_revision')::bigint,'ownership_revision',(context->>'ownership_revision')::bigint,
  'user_id',context->>'user_id','subject_id',context->>'subject_id','provider_reference',external_reference,
  'provider_revision',external_revision,'code_hash',proof_hash,'phase','pending','revision',1,
  'created_at',stamp,'expires_at',to_timestamp(expires_at_ms/1000.0),'updated_at',stamp));
 INSERT INTO issuance_service.external_association_challenges SELECT wanted.* RETURNING * INTO saved;
 IF to_jsonb(saved) IS DISTINCT FROM to_jsonb(wanted) THEN
  RAISE EXCEPTION 'Association challenge postimage changed' USING ERRCODE='23514'; END IF;
 answer:=jsonb_build_object('operation_id',op,'challenge_id',challenge,'action','create','revision',1,'phase','pending');
 expected_history:=jsonb_populate_record(NULL::issuance_service.external_association_operations,jsonb_build_object(
  'operation_id',op,'organization_id',org,'actor_type','api_key','actor_id',producer::text,
  'resource_id',challenge,'action','challenge.create','intent',intent,'receipt',answer,'created_at',stamp));
 INSERT INTO issuance_service.external_association_operations SELECT expected_history.*;
 SELECT * INTO actual FROM issuance_service.external_association_challenges WHERE id=challenge;
 SELECT * INTO history FROM issuance_service.external_association_operations WHERE operation_id=op;
 IF to_jsonb(actual) IS DISTINCT FROM to_jsonb(saved) OR to_jsonb(history) IS DISTINCT FROM to_jsonb(expected_history)
  OR context IS DISTINCT FROM issuance_service.external_association_lock_context(org,producer,grant_id,expected_source_revision,binding,expected_binding_revision)
  OR saved.expires_at<=clock_timestamp() THEN
  RAISE EXCEPTION 'Association challenge authority or audit changed' USING ERRCODE='23514'; END IF;
 RETURN answer;
END;
$$;
REVOKE ALL ON FUNCTION issuance_service.external_association_lock_context(uuid,uuid,uuid,bigint,text,bigint),
 issuance_service.guard_external_association_challenge(),
 issuance_service.create_external_association_challenge(uuid,uuid,uuid,uuid,uuid,bigint,text,bigint,text,bigint,text,bigint) FROM PUBLIC;

CREATE FUNCTION issuance_service.guard_external_association_identity()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
 IF TG_OP='DELETE' OR NEW.revision IS DISTINCT FROM OLD.revision+1 OR NEW.updated_at<OLD.updated_at
  OR (to_jsonb(NEW)-ARRAY['active','revision','updated_at']) IS DISTINCT FROM
     (to_jsonb(OLD)-ARRAY['active','revision','updated_at']) THEN
  RAISE EXCEPTION 'Invalid association identity transition' USING ERRCODE='23514'; END IF;
 RETURN NEW;
END;
$$;
CREATE TRIGGER external_association_identity_revision BEFORE UPDATE OR DELETE ON issuance_service.external_association_identities
 FOR EACH ROW EXECUTE FUNCTION issuance_service.guard_external_association_identity();
CREATE FUNCTION issuance_service.guard_external_association_binding()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
 IF TG_OP='DELETE' OR NEW.revision IS DISTINCT FROM OLD.revision+1 OR NEW.updated_at<OLD.updated_at
  OR (to_jsonb(NEW)-ARRAY['binding_revision','challenge_id','active','revision','updated_at']) IS DISTINCT FROM
     (to_jsonb(OLD)-ARRAY['binding_revision','challenge_id','active','revision','updated_at']) THEN
  RAISE EXCEPTION 'Invalid association binding transition' USING ERRCODE='23514'; END IF;
 RETURN NEW;
END;
$$;
CREATE TRIGGER external_association_binding_revision BEFORE UPDATE OR DELETE ON issuance_service.external_association_bindings
 FOR EACH ROW EXECUTE FUNCTION issuance_service.guard_external_association_binding();

-- actor is a session-authenticated Core user, never an API-key identity. A
-- producer-created pending challenge cannot create this canonical relationship.
CREATE FUNCTION issuance_service.mutate_external_association_consent(org uuid,actor text,op uuid,challenge uuid,
 requested_action text,expected_revision bigint,proof_hash text)
RETURNS jsonb LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE discovered issuance_service.external_association_challenges; before_row issuance_service.external_association_challenges;
 wanted issuance_service.external_association_challenges; saved issuance_service.external_association_challenges;
 actual issuance_service.external_association_challenges; history issuance_service.external_association_operations;
 expected_history issuance_service.external_association_operations; identity_row issuance_service.external_association_identities;
 identity_actual issuance_service.external_association_identities; edge issuance_service.external_association_bindings;
 expected_edge issuance_service.external_association_bindings; actual_edge issuance_service.external_association_bindings;
 context jsonb; intent jsonb; answer jsonb; stamp timestamptz;
BEGIN
 IF org IS NULL OR org='00000000-0000-0000-0000-000000000000' OR actor IS NULL
  OR actor !~ '^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$' OR op IS NULL OR op='00000000-0000-0000-0000-000000000000'
  OR challenge IS NULL OR challenge='00000000-0000-0000-0000-000000000000'
  OR requested_action IS NULL OR requested_action NOT IN ('confirm','deny')
  OR expected_revision IS NULL OR expected_revision NOT BETWEEN 1 AND 9007199254740990
  OR proof_hash IS NULL OR proof_hash !~ '^[a-f0-9]{64}$' THEN RETURN NULL; END IF;
 IF NOT EXISTS(SELECT 1 FROM issuance_service.external_observation_lock_organization(org) WHERE status='active') THEN RETURN NULL; END IF;
 intent:=jsonb_build_object('expected_revision',expected_revision,'code_hash',proof_hash);
 PERFORM pg_advisory_xact_lock(hashtextextended('external-association-operation:'||op::text,0));
 SELECT * INTO history FROM issuance_service.external_association_operations WHERE operation_id=op;
 IF FOUND THEN
  IF history.organization_id=org AND history.actor_type='user' AND history.actor_id=actor
   AND history.resource_id=challenge AND history.action='challenge.'||requested_action AND history.intent=intent THEN RETURN history.receipt; END IF;
  RETURN NULL;
 END IF;
 SELECT * INTO discovered FROM issuance_service.external_association_challenges WHERE id=challenge AND organization_id=org AND user_id=actor;
 IF NOT FOUND THEN RETURN NULL; END IF;
 IF requested_action='confirm' THEN
  context:=issuance_service.external_association_lock_context(org,discovered.api_key_id,discovered.source_grant_id,
   discovered.source_revision,discovered.binding_id,discovered.binding_revision);
  IF context IS NULL OR context->>'source_id' IS DISTINCT FROM discovered.source_id
   OR (context->>'key_revision')::bigint IS DISTINCT FROM discovered.key_revision
   OR context->>'application_id' IS DISTINCT FROM discovered.application_id
   OR (context->>'application_revision')::bigint IS DISTINCT FROM discovered.application_revision
   OR (context->>'ownership_revision')::bigint IS DISTINCT FROM discovered.ownership_revision
   OR context->>'user_id' IS DISTINCT FROM actor OR context->>'subject_id' IS DISTINCT FROM discovered.subject_id THEN RETURN NULL; END IF;
 END IF;
 SELECT * INTO before_row FROM issuance_service.external_association_challenges WHERE id=challenge AND organization_id=org FOR UPDATE;
 IF NOT FOUND OR to_jsonb(before_row) IS DISTINCT FROM to_jsonb(discovered) OR before_row.phase<>'pending'
  OR before_row.revision<>expected_revision OR before_row.code_hash<>proof_hash
  OR (requested_action='confirm' AND before_row.expires_at<=clock_timestamp()) THEN RETURN NULL; END IF;
 stamp:=clock_timestamp();
 IF requested_action='confirm' THEN
  PERFORM pg_advisory_xact_lock(hashtextextended('external-association-identity:'||org::text||':'||before_row.source_id||':'||before_row.provider_reference,0));
  SELECT * INTO identity_row FROM issuance_service.external_association_identities
   WHERE organization_id=org AND source_id=before_row.source_id AND provider_reference=before_row.provider_reference FOR UPDATE;
  IF FOUND THEN
   IF identity_row.user_id<>actor OR NOT identity_row.active THEN RETURN NULL; END IF;
  ELSE
   identity_row:=jsonb_populate_record(NULL::issuance_service.external_association_identities,jsonb_build_object(
    'id',gen_random_uuid(),'organization_id',org,'source_id',before_row.source_id,'provider_reference',before_row.provider_reference,
    'user_id',actor,'active',true,'revision',1,'created_at',stamp,'updated_at',stamp));
   INSERT INTO issuance_service.external_association_identities SELECT identity_row.*;
  END IF;
  SELECT * INTO edge FROM issuance_service.external_association_bindings WHERE identity_id=identity_row.id AND binding_id=before_row.binding_id FOR UPDATE;
  IF FOUND THEN
   expected_edge:=edge;expected_edge.binding_revision:=before_row.binding_revision;expected_edge.challenge_id:=challenge;
   expected_edge.active:=true;expected_edge.revision:=edge.revision+1;expected_edge.updated_at:=stamp;
   UPDATE issuance_service.external_association_bindings SET binding_revision=expected_edge.binding_revision,
    challenge_id=challenge,active=true,revision=expected_edge.revision,updated_at=stamp
    WHERE identity_id=identity_row.id AND binding_id=before_row.binding_id;
  ELSE
   expected_edge:=jsonb_populate_record(NULL::issuance_service.external_association_bindings,jsonb_build_object(
    'identity_id',identity_row.id,'organization_id',org,'source_id',before_row.source_id,'binding_id',before_row.binding_id,
    'binding_revision',before_row.binding_revision,'challenge_id',challenge,'active',true,'revision',1,'created_at',stamp,'updated_at',stamp));
   INSERT INTO issuance_service.external_association_bindings SELECT expected_edge.*;
  END IF;
 END IF;
 wanted:=before_row;wanted.phase:=CASE WHEN requested_action='confirm' THEN 'confirmed' ELSE 'denied' END;
 wanted.revision:=expected_revision+1;wanted.updated_at:=stamp;
 UPDATE issuance_service.external_association_challenges SET phase=wanted.phase,revision=wanted.revision,updated_at=stamp
  WHERE id=challenge RETURNING * INTO saved;
 IF to_jsonb(saved) IS DISTINCT FROM to_jsonb(wanted) THEN
  RAISE EXCEPTION 'Association consent postimage changed' USING ERRCODE='23514'; END IF;
 answer:=jsonb_build_object('operation_id',op,'challenge_id',challenge,'action',requested_action,'revision',saved.revision,'phase',saved.phase);
 expected_history:=jsonb_populate_record(NULL::issuance_service.external_association_operations,jsonb_build_object(
  'operation_id',op,'organization_id',org,'actor_type','user','actor_id',actor,'resource_id',challenge,
  'action','challenge.'||requested_action,'intent',intent,'receipt',answer,'created_at',stamp));
 INSERT INTO issuance_service.external_association_operations SELECT expected_history.*;
 SELECT * INTO actual FROM issuance_service.external_association_challenges WHERE id=challenge;
 SELECT * INTO history FROM issuance_service.external_association_operations WHERE operation_id=op;
 IF to_jsonb(actual) IS DISTINCT FROM to_jsonb(saved) OR to_jsonb(history) IS DISTINCT FROM to_jsonb(expected_history) THEN
  RAISE EXCEPTION 'Association consent audit changed' USING ERRCODE='23514'; END IF;
 IF requested_action='confirm' THEN
  SELECT * INTO identity_actual FROM issuance_service.external_association_identities WHERE id=identity_row.id;
  SELECT * INTO actual_edge FROM issuance_service.external_association_bindings WHERE identity_id=identity_row.id AND binding_id=before_row.binding_id;
  IF to_jsonb(identity_actual) IS DISTINCT FROM to_jsonb(identity_row) OR to_jsonb(actual_edge) IS DISTINCT FROM to_jsonb(expected_edge)
   OR context IS DISTINCT FROM issuance_service.external_association_lock_context(org,discovered.api_key_id,discovered.source_grant_id,
    discovered.source_revision,discovered.binding_id,discovered.binding_revision) OR saved.expires_at<=clock_timestamp() THEN
   RAISE EXCEPTION 'Association consent identity or authority changed' USING ERRCODE='23514'; END IF;
 END IF;
 RETURN answer;
END;
$$;
REVOKE ALL ON FUNCTION issuance_service.guard_external_association_identity(),issuance_service.guard_external_association_binding(),
 issuance_service.mutate_external_association_consent(uuid,text,uuid,uuid,text,bigint,text) FROM PUBLIC;

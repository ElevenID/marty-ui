#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Disposable real-PG source-grant lifecycle; no public identity/consent claim."""
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
import json,os,subprocess,sys,time,uuid
ROOT=Path(__file__).resolve().parents[1]
IMAGE='postgres:16-alpine@sha256:16bc17c64a573ef34162af9298258d1aec548232985b33ed7b1eac33ba35c229'
ORG='10000000-0000-4000-8000-000000000001'
OTHER='10000000-0000-4000-8000-000000000002'
def q(value):return 'NULL' if value is None else "'"+str(value).replace("'","''")+"'"
def main():
 assert sys.argv[1:] in ([],['--rust-contract'])
 rust_contract=sys.argv[1:]==['--rust-contract']
 name='external-association-source-'+uuid.uuid4().hex
 network=['--publish','127.0.0.1::5432'] if rust_contract else ['--network','none']
 subprocess.run(['docker','run','--detach','--name',name,*network,'--label','elevenid.owner=codex-external-association',
  '--env','POSTGRES_PASSWORD=synthetic-only',IMAGE],check=True,stdout=subprocess.DEVNULL)
 try:
  def sql(statement,role=False,fail=False):
   cmd=['docker','exec','-i']
   if role:cmd+=['--env','PGPASSWORD=synthetic-association-only']
   cmd+=[name,'psql','-X','-q','-A','-t','-h','127.0.0.1','-U','association_runtime' if role else 'postgres','-d','postgres','-v','ON_ERROR_STOP=1']
   r=subprocess.run(cmd,input=statement,text=True,capture_output=True,timeout=30)
   if fail:assert r.returncode!=0,'expected SQL rejection';return
   assert r.returncode==0,r.stderr or r.stdout
   return r.stdout.strip()
  for _ in range(100):
   if subprocess.run(['docker','exec',name,'pg_isready','-h','127.0.0.1','-U','postgres'],capture_output=True).returncode==0:break
   time.sleep(.1)
  else:raise AssertionError('local PostgreSQL not ready')
  sql('''CREATE SCHEMA issuance_service;CREATE SCHEMA organization_service;
   CREATE TABLE organization_service.organizations(id uuid PRIMARY KEY,status text);
   CREATE TABLE organization_service.members(id uuid PRIMARY KEY,organization_id uuid,user_id text,status text);
   CREATE TABLE organization_service.roles(id uuid PRIMARY KEY,organization_id uuid);
   CREATE TABLE organization_service.member_roles(member_id uuid,role_id uuid);
   CREATE TABLE organization_service.permissions(id uuid PRIMARY KEY,resource text,action text);
   CREATE TABLE organization_service.role_permissions(role_id uuid,permission_id uuid);
   CREATE TABLE organization_service.api_keys(id uuid PRIMARY KEY,organization_id uuid,scopes text[],scope_type text,
    deployment_profile_id uuid,status text,enabled boolean,expires_at timestamptz,updated_at timestamptz);
   CREATE TABLE issuance_service.applications(id varchar PRIMARY KEY,organization_id text,applicant_identifier text,status text,updated_at timestamptz,expires_at timestamptz);
   CREATE TABLE issuance_service.external_observation_bindings(id text PRIMARY KEY,organization_id uuid,source_id text,
    application_id varchar,subject_id text,active boolean,revision bigint,UNIQUE(id,organization_id,source_id));
   CREATE ROLE association_runtime LOGIN PASSWORD 'synthetic-association-only' NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE;
   GRANT USAGE ON SCHEMA issuance_service TO association_runtime;''')
  locks=(ROOT/'rust/services/issuance/migrations/0015_external_observation_runtime_locks.sql').read_text()
  for signature in ['external_observation_lock_organization','external_observation_lock_api_keys','external_observation_lock_application']:
   start=locks.index('CREATE FUNCTION issuance_service.'+signature+'(');end=locks.index('$$;',start)+3
   sql(locks[start:end])
  sql('REVOKE EXECUTE ON FUNCTION issuance_service.external_observation_lock_organization(uuid),issuance_service.external_observation_lock_api_keys(uuid,uuid[]),issuance_service.external_observation_lock_application(text,text) FROM PUBLIC;')
  sql((ROOT/'rust/services/issuance/migrations/0016_application_ownership.sql').read_text())
  sql((ROOT/'rust/services/issuance/migrations/0017_external_associations.sql').read_text())
  member,role,permission,key,foreign_key,other_key=[str(uuid.uuid4()) for _ in range(6)]
  sql(f"""INSERT INTO organization_service.organizations VALUES('{ORG}','active'),('{OTHER}','active');
   INSERT INTO organization_service.members VALUES('{member}','{ORG}','admin-one','active');
   INSERT INTO organization_service.roles VALUES('{role}','{ORG}');
   INSERT INTO organization_service.member_roles VALUES('{member}','{role}');
   INSERT INTO organization_service.permissions VALUES('{permission}','external-association','manage');
   INSERT INTO organization_service.role_permissions VALUES('{role}','{permission}');
   INSERT INTO organization_service.api_keys VALUES
    ('{key}','{ORG}',ARRAY['identity:attest'],'ORGANIZATION',NULL,'active',true,clock_timestamp()+interval '1hour',clock_timestamp()),
    ('{foreign_key}','{OTHER}',ARRAY['identity:attest'],'ORGANIZATION',NULL,'active',true,clock_timestamp()+interval '1hour',clock_timestamp()),
    ('{other_key}','{ORG}',ARRAY['identity:attest'],'ORGANIZATION',NULL,'active',true,clock_timestamp()+interval '1hour',clock_timestamp());
   GRANT SELECT,INSERT ON issuance_service.external_association_sources,issuance_service.external_association_operations TO association_runtime;
   GRANT UPDATE(api_key_id,key_revision,active,revision,expires_at,approved_by,approved_at,updated_at) ON issuance_service.external_association_sources TO association_runtime;
   GRANT EXECUTE ON FUNCTION issuance_service.external_observation_lock_organization(uuid),issuance_service.external_observation_lock_api_keys(uuid,uuid[]),
    issuance_service.external_association_lock_administrator(uuid,text),issuance_service.mutate_external_association_source(uuid,text,uuid,uuid,text,bigint,jsonb),
    issuance_service.read_external_association_source(uuid,text,uuid,uuid) TO association_runtime;""")
  keyrev=lambda selected=key:int(sql(f"SELECT (extract(epoch FROM updated_at)*1000000)::bigint FROM organization_service.api_keys WHERE id='{selected}';"))
  future=int(sql("SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint+600000;"))
  grant=str(uuid.uuid4());initial={'api_key_id':key,'key_revision':keyrev(),'source_id':'synthetic-source','expires_at_ms':future}
  def mutate(action,revision,definition=None,op=None,actor='admin-one',resource=grant,org=ORG):
   raw=sql('SELECT issuance_service.mutate_external_association_source('+','.join(map(q,[org,actor,op or str(uuid.uuid4()),resource,action,revision]))+','+q(json.dumps(definition or {}))+'::jsonb);',True)
   return json.loads(raw) if raw else None
  def inspect(op=None,actor='admin-one',resource=grant,org=ORG):
   raw=sql('SELECT issuance_service.read_external_association_source('+','.join(map(q,[org,actor,resource,op]))+');',True)
   return json.loads(raw) if raw else None
  assert mutate('create',0,initial,actor='learner-one') is None
  assert mutate('create',0,{**initial,'subject_id':'forged-core-subject'}) is None
  assert mutate('create',0,{**initial,'api_key_id':foreign_key,'key_revision':keyrev(foreign_key)}) is None
  for scopes in ["ARRAY['evidence:submit']","ARRAY['*','identity:*','admin:full']"]:
   sql(f"UPDATE organization_service.api_keys SET scopes={scopes} WHERE id='{key}';")
   assert mutate('create',0,initial) is None,'other scopes cannot authorize identity attestation'
  sql(f"UPDATE organization_service.api_keys SET scopes=ARRAY['identity:attest'] WHERE id='{key}';")
  sql("UPDATE organization_service.permissions SET resource='external-observation';")
  assert mutate('create',0,initial) is None,'evidence administrator has no implicit association authority'
  sql("UPDATE organization_service.permissions SET resource='external-association';")
  create_op=str(uuid.uuid4())
  with ThreadPoolExecutor(max_workers=8) as executor:
   results=list(executor.map(lambda _:mutate('create',0,initial,op=create_op),range(8)))
  assert all(value==results[0] for value in results) and results[0]['active'] is False
  assert int(sql('SELECT count(*) FROM issuance_service.external_association_operations;'))==1
  assert inspect()['record']['current'] is False
  assert inspect(create_op)=={'kind':'receipt','receipt':results[0]}
  assert inspect(create_op,actor='learner-one') is None
  assert inspect(create_op,org=OTHER) is None
  assert inspect(create_op,resource=str(uuid.uuid4())) is None
  assert mutate('create',0,{**initial,'source_id':'changed'},op=create_op) is None
  assert mutate('approve',0) is None
  sql(f"UPDATE organization_service.api_keys SET updated_at=updated_at+interval '1second' WHERE id='{key}';")
  assert mutate('approve',1) is None,'key drift cannot be silently approved'
  assert mutate('replace-key',1,{'api_key_id':key,'key_revision':keyrev()})['revision']==2
  approve_op=str(uuid.uuid4())
  with ThreadPoolExecutor(max_workers=8) as executor:
   approved=list(executor.map(lambda _:mutate('approve',2,op=approve_op),range(8)))
  assert all(value==approved[0] for value in approved) and approved[0]['active'] is True
  assert inspect()['record']['current'] is True
  sql(f"UPDATE organization_service.api_keys SET scopes=ARRAY['evidence:submit'] WHERE id='{key}';")
  assert inspect()['record']['active'] is True and inspect()['record']['current'] is False
  assert inspect(approve_op)=={'kind':'receipt','receipt':approved[0]}
  sql(f"UPDATE organization_service.api_keys SET scopes=ARRAY['identity:attest'] WHERE id='{key}';")
  sql(f"UPDATE organization_service.api_keys SET updated_at=updated_at+interval '1second' WHERE id='{key}';")
  assert inspect()['record']['current'] is False,'even restored scope cannot override key revision drift'
  sql(f"UPDATE organization_service.api_keys SET updated_at=updated_at-interval '1second' WHERE id='{key}';")
  assert inspect()['record']['current'] is True
  assert mutate('revoke',3)['active'] is False
  assert mutate('approve',2,op=approve_op)==approved[0]
  assert sql('SELECT active FROM issuance_service.external_association_sources;')=='f','historical approval cannot restore delegation'
  assert inspect()['record']['current'] is False
  assert mutate('change-expiry',4,{'expires_at_ms':1}) is None
  assert mutate('change-expiry',4,{'expires_at_ms':future+31600000000}) is None
  # A BEFORE UPDATE rewrite must roll back, with no new immutable actor operation.
  before=sql('SELECT row_to_json(s) FROM issuance_service.external_association_sources s;')
  count=sql('SELECT count(*) FROM issuance_service.external_association_operations;')
  sql(f"""CREATE FUNCTION issuance_service.test_source_rewrite() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN NEW.api_key_id:='{other_key}';RETURN NEW;END;$$;
   CREATE TRIGGER zz_test_source_rewrite BEFORE UPDATE ON issuance_service.external_association_sources FOR EACH ROW EXECUTE FUNCTION issuance_service.test_source_rewrite();""")
  try:mutate('approve',4);raise AssertionError('accepted source postimage rewrite')
  except AssertionError as error:assert 'postimage changed' in str(error)
  assert sql('SELECT row_to_json(s) FROM issuance_service.external_association_sources s;')==before
  assert sql('SELECT count(*) FROM issuance_service.external_association_operations;')==count
  sql('DROP TRIGGER zz_test_source_rewrite ON issuance_service.external_association_sources;')
  # An audit trigger can change canonical key authority in the same transaction;
  # the final key fence must reject and roll back that fault as well as approval.
  revision_before=keyrev()
  sql(f"""CREATE FUNCTION issuance_service.test_source_key_drift() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $$BEGIN
    UPDATE organization_service.api_keys SET scopes=ARRAY['evidence:submit'],updated_at=updated_at+interval '1second' WHERE id='{key}';RETURN NEW;END;$$;
   CREATE TRIGGER zz_test_source_key_drift AFTER INSERT ON issuance_service.external_association_operations FOR EACH ROW EXECUTE FUNCTION issuance_service.test_source_key_drift();""")
  try:mutate('approve',4);raise AssertionError('accepted audit-time key drift')
  except AssertionError as error:assert 'key changed' in str(error)
  assert keyrev()==revision_before
  assert sql('SELECT row_to_json(s) FROM issuance_service.external_association_sources s;')==before
  assert sql('SELECT count(*) FROM issuance_service.external_association_operations;')==count
  sql('DROP TRIGGER zz_test_source_key_drift ON issuance_service.external_association_operations;')
  for statement in ['DELETE FROM issuance_service.external_association_sources;',
   'UPDATE issuance_service.external_association_operations SET actor_id=actor_id;',
   "UPDATE organization_service.api_keys SET scopes=ARRAY['identity:attest'];"]:
   sql(statement,True,fail=True)
  print('Actual restricted-LOGIN PostgreSQL association source grant: exact independent permission/scope, inactive creation, key-revision fencing,8-way original replay, explicit approval/revocation, historical receipt separation and trigger rollback PASS')
  # New challenge authority is distinct from the source grant exercised above.
  challenge_grant=str(uuid.uuid4())
  assert mutate('create',0,{**initial,'source_id':'challenge-source','key_revision':keyrev()},resource=challenge_grant)['active'] is False
  assert mutate('approve',1,resource=challenge_grant)['active'] is True
  sql(f"""INSERT INTO issuance_service.applications VALUES('application-one','{ORG}','canonical-subject','pending',clock_timestamp(),clock_timestamp()+interval '1hour');
   INSERT INTO issuance_service.application_ownerships
    SELECT '{ORG}',id,'learner-one',applicant_identifier,(extract(epoch FROM updated_at)*1000000)::bigint,'confirmed',2,'admin-one',clock_timestamp(),clock_timestamp()
    FROM issuance_service.applications WHERE id='application-one';
   INSERT INTO issuance_service.external_observation_bindings VALUES('binding-one','{ORG}','challenge-source','application-one','canonical-subject',true,1);
   GRANT SELECT,INSERT ON issuance_service.external_association_challenges TO association_runtime;
   GRANT SELECT,INSERT ON issuance_service.external_association_identities,issuance_service.external_association_bindings TO association_runtime;
   GRANT UPDATE(phase,revision,updated_at) ON issuance_service.external_association_challenges TO association_runtime;
   GRANT UPDATE(active,consent_generation,revision,updated_at) ON issuance_service.external_association_identities TO association_runtime;
   GRANT UPDATE(binding_revision,challenge_id,active,revision,updated_at) ON issuance_service.external_association_bindings TO association_runtime;
   GRANT EXECUTE ON FUNCTION issuance_service.external_association_lock_context(uuid,uuid,uuid,bigint,text,bigint),
    issuance_service.create_external_association_challenge(uuid,uuid,uuid,uuid,uuid,bigint,text,bigint,text,bigint,text,bigint),
    issuance_service.mutate_external_association_consent(uuid,text,uuid,uuid,text,bigint,text,bigint),
    issuance_service.read_external_association_challenge(uuid,text,text,uuid,uuid),
    issuance_service.close_external_association_challenge(uuid,uuid,uuid,uuid,text,bigint),
    issuance_service.unlink_external_association(uuid,text,uuid,uuid,bigint),
    issuance_service.read_external_association_unlink_receipt(uuid,text,uuid,uuid) TO association_runtime;""")
  challenge=str(uuid.uuid4());challenge_op=str(uuid.uuid4())
  challenge_expiry=int(sql("SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint+120000;"))
  def create_challenge(op=challenge_op,resource=challenge,selected_key=key,source_revision=2,binding_revision=1,proof='a'*64,expiry=challenge_expiry,selected_binding='binding-one'):
   raw=sql('SELECT issuance_service.create_external_association_challenge('+','.join(map(q,[ORG,selected_key,op,resource,challenge_grant,source_revision,selected_binding,binding_revision,'b'*64,1,proof,expiry]))+');',True)
   return json.loads(raw) if raw else None
  assert create_challenge(selected_key=foreign_key) is None
  assert create_challenge(source_revision=1) is None
  assert create_challenge(binding_revision=2) is None
  assert create_challenge(expiry=challenge_expiry+600000) is None
  sql("UPDATE issuance_service.application_ownerships SET status='proposed',confirmed_at=NULL,revision=3;")
  assert create_challenge() is None,'unconfirmed ownership cannot become an identity challenge'
  sql("UPDATE issuance_service.application_ownerships SET status='confirmed',confirmed_at=clock_timestamp(),revision=4;")
  with ThreadPoolExecutor(max_workers=8) as executor:
   challenge_results=list(executor.map(lambda _:create_challenge(),range(8)))
  assert all(v==challenge_results[0] for v in challenge_results) and challenge_results[0]['phase']=='pending'
  assert sql('SELECT user_id||\':\'||subject_id FROM issuance_service.external_association_challenges;')=='learner-one:canonical-subject'
  assert int(sql('SELECT count(*) FROM issuance_service.external_association_identities;'))==0,'challenge creation is not learner consent'
  assert create_challenge(op=str(uuid.uuid4())) is None,'a new operation cannot adopt an existing challenge'
  assert create_challenge(proof='c'*64) is None,'original operation intent is immutable'
  # A code hash is one-use globally, even under another original operation.
  try:create_challenge(op=str(uuid.uuid4()),resource=str(uuid.uuid4()));raise AssertionError('reused challenge proof hash')
  except AssertionError as error:assert 'duplicate key' in str(error)
  def consent(action='confirm',op=None,resource=challenge,actor='learner-one',proof='a'*64,revision=1,identity_revision=None):
   raw=sql('SELECT issuance_service.mutate_external_association_consent('+','.join(map(q,[ORG,actor,op or str(uuid.uuid4()),resource,action,revision,proof,identity_revision]))+');',True)
   return json.loads(raw) if raw else None
  assert consent(actor='admin-one') is None
  assert consent(actor=key) is None,'producer key is not a learner identity'
  assert consent(proof='f'*64) is None
  assert consent(revision=2) is None
  sql("UPDATE issuance_service.external_observation_bindings SET revision=2;")
  assert consent() is None,'binding revisions must still match at consent'
  sql("UPDATE issuance_service.external_observation_bindings SET revision=1;")
  # Audit-time canonical authority changes roll back challenge, identity, edge,
  # audit and the injected change together, rather than returning partial success.
  sql(f"""CREATE FUNCTION issuance_service.test_consent_key_drift() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $$BEGIN
    UPDATE organization_service.api_keys SET scopes=ARRAY['evidence:submit'] WHERE id='{key}';RETURN NEW;END;$$;
   CREATE TRIGGER zz_test_consent_key_drift AFTER INSERT ON issuance_service.external_association_operations
    FOR EACH ROW WHEN(NEW.action='challenge.confirm') EXECUTE FUNCTION issuance_service.test_consent_key_drift();""")
  try:consent();raise AssertionError('accepted audit-time consent authority drift')
  except AssertionError as error:assert 'identity or authority changed' in str(error)
  assert int(sql('SELECT count(*) FROM issuance_service.external_association_identities;'))==0
  assert int(sql('SELECT count(*) FROM issuance_service.external_association_bindings;'))==0
  assert sql('SELECT phase FROM issuance_service.external_association_challenges;')=='pending'
  assert sql(f"SELECT scopes::text FROM organization_service.api_keys WHERE id='{key}';")=='{identity:attest}'
  sql('DROP TRIGGER zz_test_consent_key_drift ON issuance_service.external_association_operations;')
  consent_op=str(uuid.uuid4())
  with ThreadPoolExecutor(max_workers=8) as executor:
   confirmed=list(executor.map(lambda _:consent(op=consent_op),range(8)))
  assert all(v==confirmed[0] for v in confirmed) and confirmed[0]['phase']=='confirmed'
  assert int(sql('SELECT count(*) FROM issuance_service.external_association_identities;'))==1
  assert int(sql('SELECT count(*) FROM issuance_service.external_association_bindings;'))==1
  assert consent() is None,'consumed challenge cannot authorize another operation'
  assert consent('deny') is None,'terminal challenge cannot be rewritten'
  assert consent(op=consent_op,proof='e'*64) is None
  def inspect_challenge(resource=challenge,actor='learner-one',actor_type='user',op=None):
   raw=sql('SELECT issuance_service.read_external_association_challenge('+','.join(map(q,[ORG,actor_type,actor,resource,op]))+');',True)
   return json.loads(raw) if raw else None
  learner_record=inspect_challenge()['record'];assert learner_record['current'] is True
  assert learner_record['application_id']=='application-one' and learner_record['subject_id']=='canonical-subject'
  producer_record=inspect_challenge(actor=key,actor_type='api_key')['record']
  assert producer_record['current'] is True and all(producer_record[k] is None for k in ['application_id','subject_id','identity'])
  assert inspect_challenge(actor='admin-one') is None
  assert inspect_challenge(actor=other_key,actor_type='api_key') is None
  assert inspect_challenge(op=consent_op)=={'kind':'receipt','receipt':confirmed[0]}
  assert inspect_challenge(actor=key,actor_type='api_key',op=consent_op) is None
  assert inspect_challenge(op=challenge_op) is None
  assert inspect_challenge(actor=key,actor_type='api_key',op=challenge_op)=={'kind':'receipt','receipt':challenge_results[0]}
  sql(f"UPDATE organization_service.api_keys SET scopes=ARRAY['evidence:submit'] WHERE id='{key}';")
  assert inspect_challenge()['record']['current'] is False
  assert inspect_challenge(actor=key,actor_type='api_key') is None
  sql(f"UPDATE organization_service.api_keys SET scopes=ARRAY['identity:attest'] WHERE id='{key}';")
  # Confirm another binding of the same canonical identity before unlinking.
  sql(f"INSERT INTO issuance_service.external_observation_bindings VALUES('binding-two','{ORG}','challenge-source','application-one','canonical-subject',true,1);")
  second=str(uuid.uuid4());old_pending=str(uuid.uuid4());old_pending_other=str(uuid.uuid4())
  assert create_challenge(op=str(uuid.uuid4()),resource=second,proof='7'*64,selected_binding='binding-two')['phase']=='pending'
  assert consent(resource=second,proof='7'*64)['phase']=='confirmed'
  assert create_challenge(op=str(uuid.uuid4()),resource=old_pending,proof='9'*64)['phase']=='pending'
  assert create_challenge(op=str(uuid.uuid4()),resource=old_pending_other,proof='4'*64,selected_binding='binding-two')['phase']=='pending'
  identity=learner_record['identity']['identity_id'];unlink_op=str(uuid.uuid4())
  def unlink(op=unlink_op,actor='learner-one',revision=1):
   raw=sql('SELECT issuance_service.unlink_external_association('+','.join(map(q,[ORG,actor,op,identity,revision]))+');',True)
   return json.loads(raw) if raw else None
  assert unlink(actor='admin-one') is None
  identity_before=sql('SELECT row_to_json(i) FROM issuance_service.external_association_identities i;')
  edges_before=sql('SELECT jsonb_agg(to_jsonb(e) ORDER BY binding_id) FROM issuance_service.external_association_bindings e;')
  operations_before=sql('SELECT count(*) FROM issuance_service.external_association_operations;')
  sql(f"""CREATE FUNCTION issuance_service.test_unlink_edge_revival() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $$BEGIN
    UPDATE issuance_service.external_association_bindings SET active=true,revision=revision+1,updated_at=clock_timestamp() WHERE identity_id='{identity}';RETURN NEW;END;$$;
   CREATE TRIGGER zz_test_unlink_edge_revival AFTER INSERT ON issuance_service.external_association_operations
    FOR EACH ROW WHEN(NEW.action='association.unlink') EXECUTE FUNCTION issuance_service.test_unlink_edge_revival();""")
  try:unlink(op=str(uuid.uuid4()));raise AssertionError('accepted audit-time binding revival during unlink')
  except AssertionError as error:assert 'unlink authority or audit changed' in str(error)
  assert sql('SELECT row_to_json(i) FROM issuance_service.external_association_identities i;')==identity_before
  assert sql('SELECT jsonb_agg(to_jsonb(e) ORDER BY binding_id) FROM issuance_service.external_association_bindings e;')==edges_before
  assert sql('SELECT count(*) FROM issuance_service.external_association_operations;')==operations_before
  sql('DROP TRIGGER zz_test_unlink_edge_revival ON issuance_service.external_association_operations;')
  with ThreadPoolExecutor(max_workers=8) as executor:
   unlinked=list(executor.map(lambda _:unlink(),range(8)))
  assert all(v==unlinked[0] for v in unlinked) and unlinked[0]['active'] is False and unlinked[0]['revision']==2
  def unlink_receipt(actor='learner-one',resource=identity,op=unlink_op):
   raw=sql('SELECT issuance_service.read_external_association_unlink_receipt('+','.join(map(q,[ORG,actor,resource,op]))+');',True)
   return json.loads(raw) if raw else None
  assert unlink_receipt()=={'kind':'receipt','receipt':unlinked[0]}
  assert unlink_receipt(actor='admin-one') is None
  assert unlink_receipt(resource=str(uuid.uuid4())) is None
  assert int(sql('SELECT count(*) FROM issuance_service.external_association_bindings WHERE active;'))==0
  assert inspect_challenge()['record']['current'] is False
  assert inspect_challenge(resource=old_pending)['record']['can_relink'] is False
  assert consent('relink',resource=old_pending,proof='9'*64,identity_revision=2) is None,'relink requires a fresh post-unlink challenge'
  fresh=str(uuid.uuid4());relink_op=str(uuid.uuid4())
  assert create_challenge(op=str(uuid.uuid4()),resource=fresh,proof='8'*64)['phase']=='pending'
  assert inspect_challenge(resource=fresh)['record']['can_relink'] is True
  assert consent(resource=fresh,proof='8'*64) is None,'normal confirmation cannot implicitly relink'
  assert consent('relink',resource=fresh,proof='8'*64,identity_revision=1) is None
  relinked=consent('relink',op=relink_op,resource=fresh,proof='8'*64,identity_revision=2)
  assert relinked['phase']=='confirmed'
  assert consent(resource=old_pending,proof='9'*64) is None,'pre-unlink code stays unusable after another fresh challenge relinks'
  assert inspect_challenge(resource=old_pending)['record']['current'] is False
  assert consent(resource=old_pending_other,proof='4'*64) is None,'pre-unlink other-binding code also stays invalid after relink'
  assert inspect_challenge(resource=old_pending_other)['record']['current'] is False
  assert inspect_challenge(resource=fresh)['record']['current'] is True
  assert inspect_challenge()['record']['current'] is False,'new consent supersedes the old challenge for this binding'
  assert inspect_challenge(resource=second)['record']['current'] is False,'relink does not revive other old application bindings'
  assert int(sql('SELECT count(*) FROM issuance_service.external_association_bindings WHERE active;'))==1
  assert unlink()==unlinked[0] and inspect_challenge(resource=fresh)['record']['current'] is True,'old unlink replay cannot revoke a newer explicit relink'
  def close(resource,action='abandon',op=None,selected_key=key):
   raw=sql('SELECT issuance_service.close_external_association_challenge('+','.join(map(q,[ORG,selected_key,op or str(uuid.uuid4()),resource,action,1]))+');',True)
   return json.loads(raw) if raw else None
  abandoned=str(uuid.uuid4());abandon_op=str(uuid.uuid4())
  assert create_challenge(op=str(uuid.uuid4()),resource=abandoned,proof='6'*64)['phase']=='pending'
  assert close(abandoned,'expire') is None
  assert close(abandoned,selected_key=other_key) is None
  with ThreadPoolExecutor(max_workers=8) as executor:
   closed=list(executor.map(lambda _:close(abandoned,op=abandon_op),range(8)))
  assert all(v==closed[0] for v in closed) and closed[0]['phase']=='abandoned'
  assert consent(resource=abandoned,proof='6'*64) is None
  expired=str(uuid.uuid4());expiry=int(sql("SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint+1500;"))
  assert create_challenge(op=str(uuid.uuid4()),resource=expired,proof='5'*64,expiry=expiry)['phase']=='pending'
  time.sleep(1.6)
  assert inspect_challenge(resource=expired)['record']['expired'] is True
  assert inspect_challenge(resource=expired)['record']['current'] is False
  assert close(expired,'expire')['phase']=='expired'
  pending=str(uuid.uuid4())
  assert create_challenge(op=str(uuid.uuid4()),resource=pending,proof='e'*64)['phase']=='pending'
  assert mutate('revoke',2,resource=challenge_grant)['active'] is False
  assert consent(resource=pending,proof='e'*64) is None,'revoked source cannot be confirmed'
  assert consent('deny',resource=pending,proof='e'*64)['phase']=='denied','captured learner may reject a revoked source challenge'
  assert consent(op=consent_op)==confirmed[0],'historical confirmation receipt does not restore source authority'
  assert create_challenge()==challenge_results[0],'historical creation receipt is recoverable after revocation'
  assert create_challenge(op=str(uuid.uuid4()),resource=str(uuid.uuid4()),proof='d'*64) is None
  print('Actual restricted-LOGIN PostgreSQL challenge creation: confirmed canonical ownership, exact source/binding revisions, short lifetime,8-way original replay, global proof-hash uniqueness and no automatic identity association PASS')
  print('Actual restricted-LOGIN PostgreSQL consent: intended session user plus original proof,8-way one-use confirmation, atomic identity/binding/audit, audit-time authority rollback, revocation and explicit denial PASS')
  print('Actual restricted-LOGIN current/receipt reads, producer privacy,8-way global unlink and abandonment, explicit fresh-code relink with old-binding non-revival, actual expiry PASS')
  if rust_contract:
   sql(f"INSERT INTO issuance_service.external_observation_bindings VALUES('binding-rust','{ORG}','synthetic-source','application-one','canonical-subject',true,1);")
   port=subprocess.check_output(['docker','port',name,'5432/tcp'],text=True).strip()
   assert port.startswith('127.0.0.1:') and '\n' not in port
   env=os.environ.copy();env.update(EXTERNAL_ASSOCIATION_SOURCE_TEST='synthetic-local-only',
    EXTERNAL_ASSOCIATION_SOURCE_PORT=port.split(':')[-1],EXTERNAL_ASSOCIATION_SOURCE_ORG=ORG,
    EXTERNAL_ASSOCIATION_SOURCE_GRANT=grant,EXTERNAL_ASSOCIATION_SOURCE_KEY=key,EXTERNAL_ASSOCIATION_SOURCE_EXPIRY=str(future))
   subprocess.run([sys.executable,str(ROOT/'scripts/run_application_ownership_contract.py'),'--compile-only'],env=env,check=True,stderr=subprocess.STDOUT)
 finally:
  subprocess.run(['docker','rm','--force',name],check=True,stdout=subprocess.DEVNULL)
if __name__=='__main__':main()

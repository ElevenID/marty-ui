#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Actual isolated PostgreSQL ownership state/receipt tests; no HTTP auth claim."""
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import json
import subprocess
import uuid
import time

ROOT=Path(__file__).resolve().parents[1]
IMAGE='postgres:16-alpine@sha256:16bc17c64a573ef34162af9298258d1aec548232985b33ed7b1eac33ba35c229'
ORG='10000000-0000-4000-8000-000000000001'
OTHER='10000000-0000-4000-8000-000000000002'
def quote(value):
    return 'NULL' if value is None else "'"+str(value).replace("'","''")+"'"

def main():
    name='application-ownership-'+uuid.uuid4().hex
    subprocess.run(['docker','run','--detach','--name',name,'--network','none','--label','elevenid.owner=codex-application-ownership',
                    '--env','POSTGRES_PASSWORD=synthetic-only',IMAGE],check=True,stdout=subprocess.DEVNULL)
    try:
        def sql(statement,role=False,fail=False):
            command=['docker','exec','-i',name,'psql','-X','-q','-A','-t','-h','127.0.0.1','-U','postgres','-v','ON_ERROR_STOP=1']
            r=subprocess.run(command,input=('SET ROLE ownership_runtime; ' if role else '')+statement,text=True,capture_output=True,timeout=30)
            if fail:
                assert r.returncode!=0,'expected SQL rejection';return
            assert r.returncode==0,r.stderr
            return r.stdout.strip()
        for attempt in range(100):
            r=subprocess.run(['docker','exec',name,'pg_isready','-h','127.0.0.1','-U','postgres'],capture_output=True,timeout=5)
            if r.returncode==0:break
            time.sleep(.1)
        else:raise AssertionError('disposable PostgreSQL did not start')
        sql('''CREATE SCHEMA issuance_service; CREATE SCHEMA organization_service;
         CREATE TABLE organization_service.organizations(id uuid PRIMARY KEY,status text NOT NULL);
         CREATE TABLE organization_service.members(id uuid PRIMARY KEY,organization_id uuid,user_id text,status text);
         CREATE TABLE organization_service.roles(id uuid PRIMARY KEY,organization_id uuid);
         CREATE TABLE organization_service.member_roles(member_id uuid,role_id uuid);
         CREATE TABLE organization_service.permissions(id uuid PRIMARY KEY,resource text,action text);
         CREATE TABLE organization_service.role_permissions(role_id uuid,permission_id uuid);
         CREATE TABLE issuance_service.applications(id varchar PRIMARY KEY,organization_id text,applicant_identifier text,status text,updated_at timestamptz,expires_at timestamptz);
         CREATE ROLE ownership_runtime NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT;
         GRANT USAGE ON SCHEMA issuance_service TO ownership_runtime;''')
        locks=(ROOT/'rust/services/issuance/migrations/0015_external_observation_runtime_locks.sql').read_text()
        for signature in ['external_observation_lock_organization','external_observation_lock_application']:
            start=locks.index('CREATE FUNCTION issuance_service.'+signature+'(')
            end=locks.index('$$;',start)+3
            sql(locks[start:end])
        sql((ROOT/'rust/services/issuance/migrations/0016_application_ownership.sql').read_text())
        member,role,permission=[str(uuid.uuid4()) for _ in range(3)]
        sql(f"""INSERT INTO organization_service.organizations VALUES('{ORG}','active'),('{OTHER}','active');
         INSERT INTO organization_service.members VALUES('{member}','{ORG}','admin-one','active');
         INSERT INTO organization_service.roles VALUES('{role}','{ORG}');
         INSERT INTO organization_service.member_roles VALUES('{member}','{role}');
         INSERT INTO organization_service.permissions VALUES('{permission}','application','manage-ownership');
         INSERT INTO organization_service.role_permissions VALUES('{role}','{permission}');
         INSERT INTO issuance_service.applications VALUES('application-one','{ORG}','canonical-subject','pending',clock_timestamp(),clock_timestamp()+interval '1hour');
         GRANT SELECT ON issuance_service.applications TO ownership_runtime;
         GRANT SELECT,INSERT,UPDATE ON issuance_service.application_ownerships TO ownership_runtime;
         GRANT SELECT,INSERT ON issuance_service.application_ownership_operations TO ownership_runtime;
         GRANT EXECUTE ON FUNCTION issuance_service.external_observation_lock_organization(uuid),issuance_service.external_observation_lock_application(text,text),
          issuance_service.application_ownership_lock_administrator(uuid,text),issuance_service.mutate_application_ownership(uuid,text,text,uuid,text,bigint,bigint,text) TO ownership_runtime;
         REVOKE EXECUTE ON FUNCTION issuance_service.external_observation_lock_organization(uuid),issuance_service.external_observation_lock_application(text,text) FROM PUBLIC;""")
        def app_revision():return int(sql("SELECT (extract(epoch FROM updated_at)*1000000)::bigint FROM issuance_service.applications WHERE id='application-one';"))
        def mutate(action,version,actor='admin-one',user=None,op=None,org=ORG,apprev=None):
            operation=op or str(uuid.uuid4())
            value=sql('SELECT issuance_service.mutate_application_ownership('+','.join(map(quote,[org,'application-one',actor,operation,action,version,app_revision() if apprev is None else apprev,user]))+');',True)
            return json.loads(value) if value else None
        original_rev=app_revision();op=str(uuid.uuid4())
        assert mutate('propose',0,actor='learner-one',user='learner-one') is None
        assert mutate('propose',0,user='learner-one',org=OTHER) is None
        assert mutate('propose',0,user='learner-one',apprev=original_rev+1) is None
        with ThreadPoolExecutor(max_workers=8) as executor:
            results=list(executor.map(lambda _:mutate('propose',0,user='learner-one',op=op,apprev=original_rev),range(8)))
        assert all(r==results[0] for r in results) and results[0]['status']=='proposed'
        assert int(sql('SELECT count(*) FROM issuance_service.application_ownership_operations;'))==1
        assert mutate('propose',0,user='other-learner',op=op,apprev=original_rev) is None
        assert mutate('confirm',1,actor='other-learner') is None
        confirm=str(uuid.uuid4());confirmed=mutate('confirm',1,actor='learner-one',op=confirm)
        assert confirmed['status']=='confirmed' and confirmed['revision']==2
        assert mutate('confirm',1,actor='learner-one',op=confirm)==confirmed
        assert mutate('confirm',2,actor='learner-one') is None
        revoked=mutate('revoke',2);assert revoked['status']=='revoked'
        assert mutate('confirm',1,actor='learner-one',op=confirm)==confirmed,'historical receipt retained after revocation'
        assert sql('SELECT status FROM issuance_service.application_ownerships;')=='revoked','replay cannot restore ownership'
        proposal=mutate('propose',3,user='learner-two');assert proposal['revision']==4
        sql("UPDATE issuance_service.applications SET applicant_identifier='changed-subject',updated_at=updated_at+interval '1second';")
        assert mutate('confirm',4,actor='learner-two') is None
        assert mutate('revoke',4)['status']=='revoked','revocation remains available after application changes'
        sql("UPDATE issuance_service.applications SET expires_at=clock_timestamp()-interval '1second';")
        assert mutate('propose',5,user='learner-one') is None
        sql("UPDATE issuance_service.applications SET expires_at=clock_timestamp()+interval '1hour';")
        # Only the exact new ownership permission admits proposals.
        sql("UPDATE organization_service.permissions SET resource='external-observation',action='manage';")
        assert mutate('propose',5,user='learner-one') is None
        sql("UPDATE organization_service.permissions SET resource='application',action='manage-ownership';")
        before=sql('SELECT row_to_json(o) FROM issuance_service.application_ownerships o;')
        count=sql('SELECT count(*) FROM issuance_service.application_ownership_operations;')
        sql("""CREATE FUNCTION issuance_service.test_rewrite_owner() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN
         NEW.user_id:='other-user';RETURN NEW;END;$$;
         CREATE TRIGGER zz_test_rewrite BEFORE UPDATE ON issuance_service.application_ownerships FOR EACH ROW EXECUTE FUNCTION issuance_service.test_rewrite_owner();""")
        try:mutate('propose',5,user='learner-one');raise AssertionError('postimage rewrite accepted')
        except AssertionError as error:assert 'postimage changed' in str(error)
        assert sql('SELECT row_to_json(o) FROM issuance_service.application_ownerships o;')==before
        assert sql('SELECT count(*) FROM issuance_service.application_ownership_operations;')==count
        sql('DROP TRIGGER zz_test_rewrite ON issuance_service.application_ownerships;')
        for statement in ['UPDATE issuance_service.application_ownership_operations SET actor_id=actor_id;',
                          'DELETE FROM issuance_service.application_ownership_operations;',
                          'DELETE FROM issuance_service.application_ownerships;',
                          "UPDATE issuance_service.applications SET status='approved';"]:
            sql(statement,True,fail=True)
        assert sql("SELECT EXISTS(SELECT 1 FROM pg_proc p CROSS JOIN LATERAL aclexplode(p.proacl) a WHERE p.oid='issuance_service.mutate_application_ownership(uuid,text,text,uuid,text,bigint,bigint,text)'::regprocedure AND a.grantee=0 AND a.privilege_type='EXECUTE');")=='f'
        print('Actual PostgreSQL ownership propose/learner-confirm/revoke, original8-way receipts, wrong actor/tenant/revision, changed subject/expiry, exact permission, postimage rollback and restricted role PASS')
    finally:
        subprocess.run(['docker','rm','--force',name],check=True,stdout=subprocess.DEVNULL)

if __name__=='__main__':main()

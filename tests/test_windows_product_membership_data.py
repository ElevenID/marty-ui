"""Opaque data evidence; optional real SQL uses only a newly owned tmpfs PG."""
from copy import deepcopy
import hashlib,json,os,subprocess,sys,time,uuid
from pathlib import Path
import pytest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import selfhost_windows_product_schema as witness
import selfhost_windows_product_ledger as ledger

ROOT=Path(__file__).resolve().parents[1]


def before():
    row={'row_count':2,'eligible_id_sha256':['a'*64],'observed_sha256':'b'*64,'expected_after_sha256':'c'*64}
    return {'schema':witness.SCHEMA,'side':'before','database_clock':'2026-01-01T00:00:00+00:00',
            'catalog_ready':True,'credential_template':deepcopy(row),'issuance_application':deepcopy(row)}


def after():
    row={'row_count':2,'masked_rows':1,'updated_at_in_window':True,'observed_sha256':'c'*64}
    return {'schema':witness.SCHEMA,'side':'after','database_clock':'2026-01-01T00:01:00+00:00',
            'credential_template':deepcopy(row),'issuance_application':deepcopy(row)}


def test_embedded_policy_is_exact_accepted_native_sql_and_queries_never_write():
    for value,path,digest in [(witness.CREDENTIAL_REPAIR,'credential-template/migrations/0003_membership_achievement_criteria.sql',witness.CREDENTIAL_REPAIR_SHA256),
                              (witness.APPLICATION_REPAIR,'issuance/migrations/0012_membership_achievement_criteria.sql',witness.APPLICATION_REPAIR_SHA256)]:
        native=(ROOT/'rust/services'/path).read_text()
        assert value==native and hashlib.sha256(value.encode()).hexdigest()==digest
    for query in (witness.before_sql(),witness.after_sql(before())):
        import re
        assert not re.search(r'\b(UPDATE|INSERT|DELETE|ALTER|CREATE|DROP|TRUNCATE)\b',query,re.I)


@pytest.mark.parametrize('field,value',[('row_count',3),('masked_rows',0),('updated_at_in_window',False),('updated_at_in_window',1),('observed_sha256','d'*64)])
def test_unexpected_data_or_missing_clock_proof_never_passes(field,value):
    result=after();result['issuance_application'][field]=value
    with pytest.raises(ValueError):witness.validate_delta(before(),result)


@pytest.mark.parametrize('kind',['extra','duplicate-key','bad-hash','overflow','row-overflow','naive-clock','catalog-missing'])
def test_before_fragment_cannot_inject_query_values_or_omit_catalog(kind):
    value=before()
    if kind=='extra':value['raw_row']={'email':'synthetic@example.invalid'}
    elif kind=='duplicate-key':value['credential_template']['eligible_id_sha256']*=2
    elif kind=='bad-hash':value['credential_template']['eligible_id_sha256']=["';DELETE"]
    elif kind=='overflow':value['credential_template']['eligible_id_sha256']=['a'*64]*65
    elif kind=='row-overflow':value['credential_template']['row_count']=witness.MAX_ROWS+1
    elif kind=='naive-clock':value['database_clock']='2026-01-01T00:00:00'
    else:value['catalog_ready']=False
    with pytest.raises(ValueError):witness.after_sql(value)


def test_valid_fragment_never_grants_native_or_product_authority():
    result=witness.validate_delta(before(),after())
    assert result['native_admission']is False and result['product_transition_admission']is False
    assert result['ordinary_row_data_returned']is False


@pytest.mark.skipif(os.environ.get('MARTY_RUN_PRODUCT_SCHEMA_DOCKER_TEST')!='1',reason='explicit isolated Docker qualification')
def test_native_repairs_and_unexpected_edits_on_fresh_owned_tmpfs_postgres(tmp_path):
    expected_engine=os.environ.get('MARTY_PRODUCT_SCHEMA_TEST_ENGINE_ID')
    assert expected_engine and not os.environ.get('DOCKER_HOST')
    def command(args,**kwargs):return subprocess.check_output(['docker',*args],timeout=90,**kwargs)
    context=command(['context','show']).decode().strip()
    info=json.loads(command(['info','--format','{{json .}}']))
    assert info['OSType']=='linux' and info['ID']==expected_engine
    # No external state, ports, volumes or network can be supplied to this test.
    project='marty-selfhost-schema-qa-'+uuid.uuid4().hex[:12]
    image=json.loads((ROOT/'release/external-images.json').read_text())['postgres']
    image_info=json.loads(command(['image','inspect',image]))[0]
    assert set(image_info['Config'].get('Volumes')or{}) <= {'/var/lib/postgresql/data','/var/run/postgresql','/tmp'}
    image_id=image_info['Id']
    assert command(['ps','-aq','--filter','label=com.docker.compose.project='+project]).strip()==b''
    model={'services':{'postgres':{'image':image,'user':'postgres','network_mode':'none','read_only':True,
        'environment':{'POSTGRES_DB':'marty_schema_test','POSTGRES_USER':'postgres','POSTGRES_HOST_AUTH_METHOD':'trust','PGDATA':'/var/lib/postgresql/data/owned'},
        'tmpfs':['/var/lib/postgresql/data:rw,noexec,nosuid,size=134217728,mode=1777','/var/run/postgresql:rw,noexec,nosuid,size=16777216,mode=1777','/tmp:rw,noexec,nosuid,size=16777216,mode=1777'],
        'mem_limit':'384m','cpus':0.5,'cap_drop':['ALL'],'security_opt':['no-new-privileges'],
        'labels':{'elevenid.owner':'windows-membership-data-test'}}}}
    path=tmp_path/'compose.json';path.write_text(json.dumps(model));compose=['compose','--project-name',project,'--file',str(path)]
    cid=None
    def owned():
        rows=json.loads(command(['inspect',cid]));assert len(rows)==1
        row=rows[0];labels=row['Config']['Labels']
        assert row['Image']==image_id and labels['com.docker.compose.project']==project
        assert labels['com.docker.compose.service']=='postgres' and labels['elevenid.owner']=='windows-membership-data-test'
        assert row['HostConfig']['NetworkMode']=='none' and all(m['Type']=='tmpfs'for m in row['Mounts'])
        return row
    def sql(statement):
        owned()
        return command(['exec','-i',cid,'psql','-X','-U','postgres','-d','marty_schema_test','-qAt','-v','ON_ERROR_STOP=1','-f','-'],input=statement.encode()).decode()
    try:
        command([*compose,'up','-d','--pull','never'])
        cid=command([*compose,'ps','-q','postgres']).decode().strip();assert len(cid)==64
        for _ in range(60):
            if subprocess.run(['docker','exec',cid,'pg_isready','-U','postgres','-d','marty_schema_test'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=5).returncode==0:break
            time.sleep(0.5)
        else:raise RuntimeError('Owned fixture did not become ready')
        class Docker:
            prefix=['docker','--context',context]
        profile=witness.probe.LedgerProfile(application='marty_schema_test')
        sql("CREATE SCHEMA credential_template_service; CREATE SCHEMA issuance_service; CREATE TABLE credential_template_service.credential_templates(id text PRIMARY KEY,organization_id text,name text,credential_type text,doctype text,vct text,claims jsonb,version int,updated_at timestamptz,customer_keep text); CREATE TABLE credential_template_service.rust_schema_versions(version text PRIMARY KEY); CREATE TABLE issuance_service.application_templates(id text PRIMARY KEY,organization_id text,name text,credential_template_id text,ui_config jsonb,form_fields jsonb,claim_collection_rules jsonb,management_version bigint,updated_at timestamptz,customer_keep text);")
        initial="""INSERT INTO credential_template_service.credential_templates VALUES
            ('50000000-0000-0000-0000-000000000040','owner','Marty Verified Member Badge','open_badge','org.openbadges.v3','https://synthetic.invalid/credentials/marty-verified-member-badge','[]',4,'2000-01-01','keep-catalog'),
            ('unrelated','customer','Customer Badge','custom','custom','custom','{}',9,'2000-01-01','preserve');
        INSERT INTO issuance_service.application_templates VALUES
            ('stock','owner','Marty Verified Member Badge Application','50000000-0000-0000-0000-000000000040','{"mip_0_3_system_claim_migration":{}}','[]','[{"claim_name":"achievement_name","source":"SYSTEM","source_config":{"system_field":"template.name"}},{"claim_name":"achievement_description","source":"SYSTEM","source_config":{"system_field":"template.description"}}]',3,'2000-01-01','keep-application');
        INSERT INTO issuance_service.application_templates SELECT 'customer',organization_id,'Customer application',credential_template_id,ui_config,form_fields,claim_collection_rules,8,updated_at,'preserve' FROM issuance_service.application_templates WHERE id='stock';"""
        sql(initial)
        prior=witness.capture(Docker(),[owned()],project,profile=profile)
        assert len(prior['credential_template']['eligible_id_sha256'])==1 and len(prior['issuance_application']['eligible_id_sha256'])==1
        sql(witness.CREDENTIAL_REPAIR+witness.APPLICATION_REPAIR)
        result=witness.capture(Docker(),[owned()],project,before=prior,profile=profile)
        assert witness.validate_delta(prior,result)['product_transition_admission']is False
        # Idempotent repair must preserve complete already-migrated rows.
        repeated=witness.capture(Docker(),[owned()],project,profile=profile)
        assert all(not repeated[name]['eligible_id_sha256']for name in witness.TABLES)
        sql(witness.CREDENTIAL_REPAIR+witness.APPLICATION_REPAIR)
        witness.capture(Docker(),[owned()],project,before=repeated,profile=profile)
        sql("UPDATE issuance_service.application_templates SET customer_keep='unexpected' WHERE id='customer';")
        with pytest.raises(ValueError):witness.capture(Docker(),[owned()],project,before=repeated,profile=profile)
        # Generated projection names cannot hide a newly added customer field.
        sql("UPDATE issuance_service.application_templates SET customer_keep='preserve' WHERE id='customer'; ALTER TABLE issuance_service.application_templates ADD COLUMN _cohort_eligible text DEFAULT 'unexpected';")
        with pytest.raises(ValueError):witness.capture(Docker(),[owned()],project,before=repeated,profile=profile)
        sql("ALTER TABLE issuance_service.application_templates DROP COLUMN _cohort_eligible;")
        # Restore only this synthetic row, then prove timestamp evidence matters.
        sql("UPDATE issuance_service.application_templates SET customer_keep='preserve' WHERE id='customer'; UPDATE credential_template_service.credential_templates SET updated_at='1999-01-01' WHERE id='50000000-0000-0000-0000-000000000040';")
        with pytest.raises(ValueError):witness.capture(Docker(),[owned()],project,before=prior,profile=profile)
        sql("UPDATE credential_template_service.credential_templates SET updated_at=NULL WHERE id='50000000-0000-0000-0000-000000000040';")
        with pytest.raises(ValueError):witness.capture(Docker(),[owned()],project,before=prior,profile=profile)
        # Existing physical columns with projection names remain part of the payload.
        sql("TRUNCATE credential_template_service.credential_templates,credential_template_service.rust_schema_versions,issuance_service.application_templates;")
        sql(initial)
        sql("ALTER TABLE issuance_service.application_templates ADD COLUMN _cohort_id_sha256 text DEFAULT 'retained'; ALTER TABLE issuance_service.application_templates ADD COLUMN _cohort_row text DEFAULT 'retained';")
        collision=witness.capture(Docker(),[owned()],project,profile=profile)
        sql(witness.CREDENTIAL_REPAIR+witness.APPLICATION_REPAIR)
        witness.capture(Docker(),[owned()],project,before=collision,profile=profile)
        sql("UPDATE issuance_service.application_templates SET _cohort_id_sha256='unexpected' WHERE id='customer';")
        with pytest.raises(ValueError):witness.capture(Docker(),[owned()],project,before=collision,profile=profile)
        sql("ALTER TABLE issuance_service.application_templates DROP COLUMN _cohort_id_sha256; ALTER TABLE issuance_service.application_templates DROP COLUMN _cohort_row;")
        # Both service startup orders must agree with the same retained-state witness.
        reset="TRUNCATE credential_template_service.credential_templates,credential_template_service.rust_schema_versions,issuance_service.application_templates;"
        sql(reset+initial)
        prior=witness.capture(Docker(),[owned()],project,profile=profile)
        sql(witness.APPLICATION_REPAIR+witness.CREDENTIAL_REPAIR)
        witness.capture(Docker(),[owned()],project,before=prior,profile=profile)
        # Retained customer and nested criteria are excluded by the original SQL.
        for claims in ([{'name':'achievement_criteria','description':'customer-owned'}],
                       [{'name':'achievement','claim_type':'object'}], {'malformed':'retained'}):
            sql(reset+initial)
            literal=json.dumps(claims).replace("'","''")
            sql("UPDATE credential_template_service.credential_templates SET claims='"+literal+"'::jsonb WHERE id='50000000-0000-0000-0000-000000000040';")
            prior=witness.capture(Docker(),[owned()],project,profile=profile)
            assert all(not prior[name]['eligible_id_sha256']for name in witness.TABLES)
            sql(witness.CREDENTIAL_REPAIR+witness.APPLICATION_REPAIR)
            witness.capture(Docker(),[owned()],project,before=prior,profile=profile)
        sql(reset+initial)
        sql("DELETE FROM credential_template_service.credential_templates WHERE id='50000000-0000-0000-0000-000000000040';")
        with pytest.raises(ValueError):witness.capture(Docker(),[owned()],project,profile=profile)
        # Synthetic ledger observations qualify only the read-only witness,
        # not native migration execution or the complete startup transition.
        sql("DROP TABLE credential_template_service.rust_schema_versions; CREATE SCHEMA trust_profile_service;")
        for table,versions in ledger.BASELINES.items():
            sql('CREATE TABLE '+table+'(version text PRIMARY KEY,applied_at timestamptz NOT NULL DEFAULT clock_timestamp());')
            sql('INSERT INTO '+table+"(version,applied_at) VALUES "+','.join("('"+v+"','2000-01-01')"for v in versions)+';')
        baseline=ledger.capture(Docker(),[owned()],project,profile=profile)
        for table,version in ledger.ADDITIONS.items():
            sql('INSERT INTO '+table+"(version) VALUES ('"+version+"');")
            with pytest.raises(ValueError):ledger.capture(Docker(),[owned()],project,profile=profile)
        final=ledger.capture(Docker(),[owned()],project,before=baseline,profile=profile)
        assert ledger.validate_delta(baseline,final)['product_transition_admission']is False
        # A partially/already upgraded baseline is not retry authority.
        with pytest.raises(ValueError):ledger.capture(Docker(),[owned()],project,profile=profile)
        for table,versions in ledger.BASELINES.items():
            sql('UPDATE '+table+" SET applied_at='1999-01-01' WHERE version='"+versions[0]+"';")
            with pytest.raises(ValueError):ledger.capture(Docker(),[owned()],project,before=baseline,profile=profile)
            sql('UPDATE '+table+" SET applied_at='2000-01-01' WHERE version='"+versions[0]+"';")
            sql('UPDATE '+table+" SET applied_at='1999-01-01' WHERE version='"+ledger.ADDITIONS[table]+"';")
            with pytest.raises(ValueError):ledger.capture(Docker(),[owned()],project,before=baseline,profile=profile)
            sql('UPDATE '+table+" SET applied_at=clock_timestamp()+interval '1 hour' WHERE version='"+ledger.ADDITIONS[table]+"';")
            with pytest.raises(ValueError):ledger.capture(Docker(),[owned()],project,before=baseline,profile=profile)
            sql('UPDATE '+table+" SET applied_at=clock_timestamp() WHERE version='"+ledger.ADDITIONS[table]+"';")
            sql('INSERT INTO '+table+"(version) VALUES ('unexpected');")
            with pytest.raises(ValueError):ledger.capture(Docker(),[owned()],project,before=baseline,profile=profile)
            sql('DELETE FROM '+table+" WHERE version='unexpected';")
        ledger.capture(Docker(),[owned()],project,before=baseline,profile=profile)
        table='issuance_service.rust_schema_migrations'
        sql('ALTER TABLE '+table+' ALTER COLUMN applied_at DROP NOT NULL; UPDATE '+table+" SET applied_at=NULL WHERE version='"+ledger.ADDITIONS[table]+"';")
        with pytest.raises(ValueError):ledger.capture(Docker(),[owned()],project,before=baseline,profile=profile)
        sql('UPDATE '+table+" SET applied_at=clock_timestamp() WHERE version='"+ledger.ADDITIONS[table]+"'; ALTER TABLE "+table+' ALTER COLUMN applied_at SET NOT NULL;')
        sql('ALTER TABLE '+table+' ADD COLUMN customer_metadata text;')
        with pytest.raises(ValueError):ledger.capture(Docker(),[owned()],project,before=baseline,profile=profile)
    finally:
        if cid is None:
            remaining=command(['ps','-aq','--filter','label=com.docker.compose.project='+project]).decode().split()
            assert len(remaining)<=1
            if remaining:cid=remaining[0]
        if cid is not None:
            owned();command([*compose,'down'])
            assert not command(['ps','-aq','--filter','label=com.docker.compose.project='+project]).strip()

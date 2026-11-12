"""Read-only authority-table catalog fragment, not deployment admission.

Preserve retained catalog identities, including TOAST and internal triggers.
Only a separately validated native new-object closure may be excluded. The
existing product owner does not consume this fragment. Full startup, ledger,
source/image, data and native custody qualification remain required.
"""
import json

import selfhost_windows_product_probe as probe

SCHEMA = 'marty.windows-authority-catalog/v1'
SHAPE_SHA256 = {
    True: '326bbb519f028d1c826aef867d0d12f17b657b7d44732c43e386dcf8dbaf191b',
    False: '8900c9d99b08714f9ffbeb87e70fe178a7bace331db544eeb930af3d87ae18a7',
}
TABLE = 'trust_profile_service.credential_authority_revisions'
PARENT = 'trust_profile_service.trust_profiles'


def require(value):
    if not value:raise ValueError('Authority catalog witness refused')


def _hash(expression):
    return "encode(sha256(convert_to(coalesce("+expression+",'[]'::jsonb)::text,'UTF8')),'hex')"


def _ctes():
    return """a AS (SELECT to_regclass('trust_profile_service.credential_authority_revisions')::oid AS oid),
    parent AS (SELECT * FROM pg_class WHERE oid=to_regclass('trust_profile_service.trust_profiles')),
    parent_pk AS (SELECT indexrelid AS oid FROM pg_index WHERE indrelid=(SELECT oid FROM parent) AND indisprimary),
    xr AS (SELECT oid FROM a WHERE oid IS NOT NULL UNION
        SELECT indexrelid FROM pg_index WHERE indrelid=(SELECT oid FROM a) AND indisprimary UNION
        SELECT reltoastrelid FROM pg_class WHERE oid=(SELECT oid FROM a) AND reltoastrelid<>0 UNION
        SELECT indexrelid FROM pg_index WHERE indrelid=(SELECT reltoastrelid FROM pg_class WHERE oid=(SELECT oid FROM a))),
    xt AS (SELECT oid FROM pg_type WHERE oid=(SELECT reltype FROM pg_class WHERE oid=(SELECT oid FROM a))
        OR oid=(SELECT typarray FROM pg_type WHERE oid=(SELECT reltype FROM pg_class WHERE oid=(SELECT oid FROM a)))),
    xc AS (SELECT oid FROM pg_constraint WHERE conrelid IN (SELECT oid FROM xr)),
    xg AS (SELECT oid FROM pg_trigger WHERE tgrelid IN (SELECT oid FROM xr) OR tgconstraint IN (SELECT oid FROM xc)),
    xd AS (SELECT oid FROM pg_attrdef WHERE adrelid IN (SELECT oid FROM xr)),
    nodes AS (
        SELECT 'pg_class'::regclass::oid AS classid,c.oid,
            CASE WHEN c.oid=(SELECT oid FROM a) THEN 'authority'
                 WHEN c.relkind='t' THEN 'toast'
                 WHEN c.relnamespace='pg_toast'::regnamespace THEN 'toast_index'
                 ELSE 'authority_pk' END AS label FROM pg_class c WHERE c.oid IN (SELECT oid FROM xr)
        UNION ALL SELECT 'pg_type'::regclass::oid,t.oid,CASE WHEN t.typrelid=(SELECT oid FROM a) THEN 'row_type' ELSE 'array_type' END FROM pg_type t WHERE oid IN (SELECT oid FROM xt)
        UNION ALL SELECT 'pg_constraint'::regclass::oid,c.oid,'constraint:'||c.conname FROM pg_constraint c WHERE oid IN (SELECT oid FROM xc)
        UNION ALL SELECT 'pg_attrdef'::regclass::oid,d.oid,'default:'||d.adnum::text FROM pg_attrdef d WHERE oid IN (SELECT oid FROM xd)
        UNION ALL SELECT 'pg_trigger'::regclass::oid,t.oid,'trigger:'||p.proname||':'||CASE WHEN t.tgrelid=(SELECT oid FROM parent) THEN 'parent' ELSE 'child' END
            FROM pg_trigger t JOIN pg_proc p ON p.oid=t.tgfoid WHERE t.oid IN (SELECT oid FROM xg)
    )"""


def _ref(classname, expression):
    classid="'"+classname+"'::regclass::oid"
    return "CASE WHEN ("+expression+")=0 THEN 'none' WHEN "+classid+"='pg_class'::regclass AND ("+expression+")=(SELECT oid FROM parent) THEN '<parent>' WHEN "+classid+"='pg_class'::regclass AND ("+expression+")=(SELECT oid FROM parent_pk) THEN '<parent_pk>' WHEN "+classid+"='pg_authid'::regclass AND ("+expression+")=(SELECT relowner FROM parent) THEN '<owner>' ELSE coalesce((SELECT label FROM nodes WHERE classid="+classid+" AND oid=("+expression+")),pg_describe_object("+classid+",("+expression+"),0)) END"


def _catalog(protected, before):
    sql=probe.CATALOG_SQL
    old="WHERE nspname !~ '^pg_' AND nspname <> 'information_schema'"
    require(sql.count(old)==1)
    sql=sql.replace(old,"WHERE (nspname !~ '^pg_' AND nspname <> 'information_schema') OR nspname='pg_toast'")
    require(sql.count(' AND NOT tgisinternal')==1)
    sql=sql.replace(' AND NOT tgisinternal','')
    if protected:
        substitutions={
            'SELECT * FROM pg_class WHERE relnamespace IN (SELECT oid FROM n)': 'SELECT * FROM pg_class WHERE relnamespace IN (SELECT oid FROM n) AND oid NOT IN (SELECT oid FROM xr)',
            'WHERE connamespace IN (SELECT oid FROM n)': 'WHERE connamespace IN (SELECT oid FROM n) AND conrelid NOT IN (SELECT oid FROM xr)',
            'FROM pg_type a WHERE typnamespace IN (SELECT oid FROM n))': 'FROM pg_type a WHERE typnamespace IN (SELECT oid FROM n) AND oid NOT IN (SELECT oid FROM xt))',
            'WHERE tgrelid IN (SELECT oid FROM c))': 'WHERE tgrelid IN (SELECT oid FROM c) AND oid NOT IN (SELECT oid FROM xg))',
            'to_jsonb(c)-ARRAY': "(to_jsonb(c)||CASE WHEN c.oid="+str(before['parent_oid'])+" THEN jsonb_build_object('relhastriggers',"+str(before['parent_has_triggers']).lower()+") ELSE '{}'::jsonb END)-ARRAY",
        }
        for old,new in substitutions.items():
            require(sql.count(old)==1);sql=sql.replace(old,new)
    return sql.replace('WITH n AS (','WITH '+_ctes()+', n AS (',1)


def _dependency_hash(shared, protected):
    table='pg_shdepend' if shared else 'pg_depend'
    conditions=["d.dbid=(SELECT oid FROM pg_database WHERE datname=current_database())"] if shared else ['true']
    if protected:
        conditions += ['NOT EXISTS(SELECT 1 FROM nodes n WHERE (n.classid=d.classid AND n.oid=d.objid) OR (n.classid=d.refclassid AND n.oid=d.refobjid))']
    return _hash('(SELECT jsonb_agg(to_jsonb(d) ORDER BY to_jsonb(d)::text) FROM '+table+' d WHERE '+' AND '.join(conditions)+')')


def shape():
    """All values here are public schema metadata; no ordinary rows or secrets."""
    rel=_ref('pg_class','c.oid')
    native_toast="'pg_toast_'||(SELECT oid::text FROM a)"
    relations="""SELECT jsonb_agg((to_jsonb(c)-ARRAY['oid','relfilenode','reltype','relnamespace','relowner','reltoastrelid','relpages','reltuples','relallvisible','relallfrozen','relfrozenxid','relminmxid'])||jsonb_build_object(
        'label',"""+rel+",'owner',"+_ref('pg_authid','c.relowner')+",'rowtype',"+_ref('pg_type','c.reltype')+",'toast',"+_ref('pg_class','c.reltoastrelid')+""",'namespace',c.relnamespace::regnamespace::text,
        'relname',CASE WHEN c.relname="""+native_toast+" THEN '<toast>' WHEN c.relname="+native_toast+"||'_index' THEN '<toast_index>' ELSE c.relname END) ORDER BY "+rel+") FROM pg_class c WHERE c.oid IN (SELECT oid FROM xr)"
    attributes="SELECT jsonb_agg((to_jsonb(p)-'attrelid')||jsonb_build_object('relation',"+_ref('pg_class','p.attrelid')+") ORDER BY "+_ref('pg_class','p.attrelid')+",attnum) FROM pg_attribute p WHERE attrelid IN (SELECT oid FROM xr) AND attnum>0"
    constraints="SELECT jsonb_agg((to_jsonb(p)-ARRAY['oid','connamespace','conrelid','contypid','conindid','confrelid','conparentid','conbin'])||jsonb_build_object('namespace',connamespace::regnamespace::text,'relation',"+_ref('pg_class','p.conrelid')+",'index',"+_ref('pg_class','p.conindid')+",'parent',"+_ref('pg_class','p.confrelid')+",'domain',"+_ref('pg_type','p.contypid')+",'parent_constraint',"+_ref('pg_constraint','p.conparentid')+",'definition',pg_get_constraintdef(p.oid,true)) ORDER BY conname) FROM pg_constraint p WHERE oid IN (SELECT oid FROM xc)"
    indexes="SELECT jsonb_agg((to_jsonb(p)-ARRAY['indexrelid','indrelid'])||jsonb_build_object('index',"+_ref('pg_class','p.indexrelid')+",'relation',"+_ref('pg_class','p.indrelid')+",'definition',replace(pg_get_indexdef(indexrelid),"+native_toast+",'<toast>')) ORDER BY "+_ref('pg_class','p.indexrelid')+") FROM pg_index p WHERE indexrelid IN (SELECT oid FROM xr)"
    types="SELECT jsonb_agg((to_jsonb(p)-ARRAY['oid','typowner','typnamespace','typrelid','typelem','typarray'])||jsonb_build_object('owner',"+_ref('pg_authid','p.typowner')+",'namespace',typnamespace::regnamespace::text,'relation',"+_ref('pg_class','p.typrelid')+",'element',"+_ref('pg_type','p.typelem')+",'array',"+_ref('pg_type','p.typarray')+") ORDER BY typname) FROM pg_type p WHERE oid IN (SELECT oid FROM xt)"
    defaults="SELECT jsonb_agg(jsonb_build_object('relation',"+_ref('pg_class','p.adrelid')+",'column',adnum,'expression',pg_get_expr(adbin,adrelid)) ORDER BY adnum) FROM pg_attrdef p WHERE oid IN (SELECT oid FROM xd)"
    triggers="SELECT jsonb_agg((to_jsonb(t)-ARRAY['oid','tgname','tgfoid','tgrelid','tgconstrrelid','tgconstrindid','tgconstraint'])||jsonb_build_object('name_matches_oid',tgname ~ ('^RI_ConstraintTrigger_[ac]_'||t.oid::text||'$'),'function',t.tgfoid::regproc::text,'relation',"+_ref('pg_class','t.tgrelid')+",'other_relation',"+_ref('pg_class','t.tgconstrrelid')+",'index',"+_ref('pg_class','t.tgconstrindid')+",'constraint',"+_ref('pg_constraint','t.tgconstraint')+") ORDER BY "+_ref('pg_trigger','t.oid')+") FROM pg_trigger t WHERE t.oid IN (SELECT oid FROM xg)"
    deps=[]
    for shared in [False,True]:
        own="coalesce((SELECT label FROM nodes WHERE classid=d.classid AND oid=d.objid),pg_describe_object(d.classid,d.objid,0))"
        ref="coalesce((SELECT label FROM nodes WHERE classid=d.refclassid AND oid=d.refobjid),CASE WHEN d.refclassid='pg_authid'::regclass AND d.refobjid=(SELECT relowner FROM parent) THEN '<owner>' ELSE pg_describe_object(d.refclassid,d.refobjid,0) END)"
        cols="jsonb_build_object('class',d.classid::regclass::text,'object',"+own+",'column',d.objsubid,'refclass',d.refclassid::regclass::text,'refobject',"+ref+",'refcolumn',"+('0' if shared else 'd.refobjsubid')+",'kind',d.deptype)"
        deps.append("SELECT jsonb_agg(v ORDER BY v::text) FROM (SELECT "+cols+" AS v FROM "+('pg_shdepend' if shared else 'pg_depend')+" d WHERE "+("d.dbid=(SELECT oid FROM pg_database WHERE datname=current_database()) AND " if shared else '')+"EXISTS(SELECT 1 FROM nodes n WHERE (n.classid=d.classid AND n.oid=d.objid) OR (n.classid=d.refclassid AND n.oid=d.refobjid))) q")
    entries=dict(relations=relations,attributes=attributes,constraints=constraints,indexes=indexes,
                 types=types,defaults=defaults,triggers=triggers,dependencies=deps[0],shared_dependencies=deps[1])
    body="jsonb_build_object("+','.join("'"+key+"',("+value+")"for key,value in entries.items())+")"
    return body


def statement(before=None, *, debug_shape=False):
    if before is not None:validate_before(before)
    protected=before is not None
    prefix='WITH '+_ctes()+' '
    if debug_shape:
        require(protected);return prefix+'SELECT '+shape()+';'
    catalog=_catalog(protected,before)
    full=_catalog(False,None)
    fields=["'schema','"+SCHEMA+"'","'side','"+('after' if protected else 'before')+"'",
            "'parent_oid',(SELECT oid::bigint FROM parent)","'parent_has_triggers',(SELECT relhastriggers FROM parent)",
            "'parent_owner_oid',(SELECT relowner::bigint FROM parent)","'parent_owner_bootstrap',(SELECT relowner=10 FROM parent)",
            "'catalog_sha256',("+catalog+")","'dependencies_sha256',"+_dependency_hash(False,protected),
            "'shared_dependencies_sha256',"+_dependency_hash(True,protected)]
    if protected:
        fields += ["'shape_sha256',"+_hash(shape()),"'raw_catalog_sha256',("+full+")",
                   "'raw_dependencies_sha256',"+_dependency_hash(False,False),
                   "'raw_shared_dependencies_sha256',"+_dependency_hash(True,False),
                   "'new_row_count',(SELECT count(*) FROM "+TABLE+")",
                   "'unsupported_objects',EXISTS(SELECT 1 FROM pg_inherits WHERE inhrelid IN (SELECT oid FROM xr) OR inhparent IN (SELECT oid FROM xr)) OR EXISTS(SELECT 1 FROM pg_partitioned_table WHERE partrelid IN (SELECT oid FROM xr)) OR EXISTS(SELECT 1 FROM pg_policy WHERE polrelid IN (SELECT oid FROM xr)) OR EXISTS(SELECT 1 FROM pg_rewrite WHERE ev_class IN (SELECT oid FROM xr)) OR EXISTS(SELECT 1 FROM pg_sequence WHERE seqrelid IN (SELECT oid FROM xr)) OR EXISTS(SELECT 1 FROM pg_description d JOIN nodes n ON n.classid=d.classoid AND n.oid=d.objoid) OR EXISTS(SELECT 1 FROM pg_seclabel d JOIN nodes n ON n.classid=d.classoid AND n.oid=d.objoid)",
                   "'storage_distinct',(SELECT count(DISTINCT relfilenode)=count(*) AND bool_and(relfilenode>0 AND reltablespace=0) FROM pg_class WHERE oid IN (SELECT oid FROM xr)) AND NOT EXISTS(SELECT 1 FROM pg_class x JOIN pg_class retained ON x.relfilenode=retained.relfilenode AND x.reltablespace=retained.reltablespace WHERE x.oid IN (SELECT oid FROM xr) AND retained.oid NOT IN (SELECT oid FROM xr))"]
    else:
        fields += ["'new_objects_absent',NOT EXISTS(SELECT 1 FROM pg_class WHERE relnamespace=(SELECT relnamespace FROM parent) AND relname IN ('credential_authority_revisions','credential_authority_revisions_pkey')) AND NOT EXISTS(SELECT 1 FROM pg_type WHERE typnamespace=(SELECT relnamespace FROM parent) AND typname IN ('credential_authority_revisions','_credential_authority_revisions'))",
                   "'parent_key_valid',(SELECT count(*)=1 AND bool_and(indnkeyatts=1 AND indkey[0]=1 AND indisvalid AND indisready) FROM pg_index WHERE indexrelid IN (SELECT oid FROM parent_pk)) AND EXISTS(SELECT 1 FROM pg_attribute WHERE attrelid=(SELECT oid FROM parent) AND attname='id' AND attnum=1 AND atttypid='text'::regtype AND attnotnull) AND EXISTS(SELECT 1 FROM parent WHERE relkind='r' AND relpersistence='p' AND NOT relispartition) AND NOT EXISTS(SELECT 1 FROM pg_inherits WHERE inhrelid IN (SELECT oid FROM parent) OR inhparent IN (SELECT oid FROM parent))",
                   "'owner_defaults_empty',NOT EXISTS(SELECT 1 FROM pg_default_acl WHERE defaclrole=(SELECT relowner FROM parent))",
                   "'supported',NOT(EXISTS(SELECT 1 FROM pg_foreign_table) OR EXISTS(SELECT 1 FROM pg_event_trigger))"]
    return prefix+'SELECT jsonb_build_object('+','.join(fields)+');'


def validate_before(value):
    require(type(value) is dict and set(value)=={'schema','side','parent_oid','parent_has_triggers','parent_owner_oid','parent_owner_bootstrap',
        'catalog_sha256','dependencies_sha256','shared_dependencies_sha256','new_objects_absent','parent_key_valid','owner_defaults_empty','supported'})
    require(value['schema']==SCHEMA and value['side']=='before' and value['new_objects_absent'] is True and value['parent_key_valid'] is True
            and value['owner_defaults_empty'] is True and value['supported'] is True)
    require(type(value['parent_oid']) is int and 0<value['parent_oid']<2**32 and type(value['parent_has_triggers']) is bool)
    require(type(value['parent_owner_oid']) is int and (value['parent_owner_oid']==10 or 16384<=value['parent_owner_oid']<2**32)
            and type(value['parent_owner_bootstrap']) is bool and value['parent_owner_bootstrap']==(value['parent_owner_oid']==10))
    for key in ('catalog_sha256','dependencies_sha256','shared_dependencies_sha256'):
        require(type(value[key]) is str and probe.SHA.fullmatch(value[key]))


def validate_delta(before, after):
    validate_before(before)
    require(type(after) is dict and set(after)=={'schema','side','parent_oid','parent_has_triggers','parent_owner_oid','parent_owner_bootstrap',
        'catalog_sha256','dependencies_sha256','shared_dependencies_sha256','shape_sha256',
        'raw_catalog_sha256','raw_dependencies_sha256','raw_shared_dependencies_sha256','new_row_count','unsupported_objects','storage_distinct'})
    require(after['schema']==SCHEMA and after['side']=='after' and type(after['parent_oid']) is int
        and after['parent_oid']==before['parent_oid'] and after['parent_has_triggers'] is True)
    require(type(after['parent_owner_oid']) is int and after['parent_owner_oid']==before['parent_owner_oid']
            and type(after['parent_owner_bootstrap']) is bool and after['parent_owner_bootstrap']==before['parent_owner_bootstrap'])
    for key in ('catalog_sha256','dependencies_sha256','shared_dependencies_sha256'):
        require(type(after[key]) is str and after[key]==before[key])
    expected=SHAPE_SHA256[before['parent_owner_bootstrap']]
    require(expected!='0'*64 and type(after['shape_sha256']) is str and after['shape_sha256']==expected)
    raw={}
    for key in ('catalog_sha256','dependencies_sha256','shared_dependencies_sha256'):
        value=after['raw_'+key]
        require(type(value) is str and probe.SHA.fullmatch(value));raw[key]=value
    require(type(after['new_row_count']) is int and after['new_row_count']==0
            and after['unsupported_objects'] is False and after['storage_distinct'] is True)
    return {'schema':'marty.windows-authority-catalog-delta/v1','raw_after':raw,
            'native_admission':False,'product_transition_admission':False}


def _observe(docker, items, project, *, before=None, profile=probe.LedgerProfile()):
    require(type(profile) is probe.LedgerProfile)
    base=probe._postgres_base(items,project)
    result=json.loads(probe._text(docker,[base[0],'--interactive',*base[1:],
        '--dbname',profile.application,'--file=-'],stdin_bytes=statement(before).encode()))
    if before is None:validate_before(result)
    return result


def capture(docker, items, project, *, before=None, profile=probe.LedgerProfile()):
    result=_observe(docker,items,project,before=before,profile=profile)
    if before is not None:validate_delta(before,result)
    return result

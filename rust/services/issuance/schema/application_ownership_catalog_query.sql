-- SPDX-License-Identifier: AGPL-3.0-only
-- Execute with search_path=pg_catalog. No user rows or ACL secrets are read.
WITH relations AS (
 SELECT c.oid,c.relname,c.relkind,c.relpersistence,c.relrowsecurity,c.relforcerowsecurity,c.relacl,c.relowner
 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
 WHERE n.nspname='issuance_service' AND c.relname ~ '^application_ownership'
 AND c.relkind IN ('r','p','v','m','f','S')
), tables AS (
 SELECT jsonb_agg(jsonb_build_object('name',relname,'kind',relkind,'persistence',relpersistence,
  'rls',relrowsecurity,'force_rls',relforcerowsecurity,
  'public_privileges',EXISTS(SELECT 1 FROM aclexplode(coalesce(relacl,acldefault('r',relowner))) acl WHERE acl.grantee=0))
  ORDER BY relname COLLATE "C") AS value FROM relations
), columns AS (
 SELECT jsonb_agg(jsonb_build_object('table',r.relname,'name',a.attname,'type',format_type(a.atttypid,a.atttypmod),
  'not_null',a.attnotnull,'default',pg_get_expr(d.adbin,d.adrelid),'identity',a.attidentity,'generated',a.attgenerated,
  'public_privileges',EXISTS(SELECT 1 FROM aclexplode(a.attacl) acl WHERE acl.grantee=0))
  ORDER BY r.relname COLLATE "C",a.attnum) AS value
 FROM relations r JOIN pg_attribute a ON a.attrelid=r.oid
 LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum
 WHERE a.attnum>0 AND NOT a.attisdropped
), constraints AS (
 SELECT jsonb_agg(jsonb_build_object('table',r.relname,'name',c.conname,'kind',c.contype,
  'validated',c.convalidated,'deferrable',c.condeferrable,'deferred',c.condeferred,'definition',pg_get_constraintdef(c.oid))
  ORDER BY r.relname COLLATE "C",c.conname COLLATE "C") AS value
 FROM relations r JOIN pg_constraint c ON c.conrelid=r.oid
), indexes AS (
 SELECT jsonb_agg(jsonb_build_object('table',r.relname,'name',c.relname,'unique',x.indisunique,
  'valid',x.indisvalid,'ready',x.indisready,'primary',x.indisprimary,'definition',pg_get_indexdef(c.oid))
  ORDER BY r.relname COLLATE "C",c.relname COLLATE "C") AS value
 FROM relations r JOIN pg_index x ON x.indrelid=r.oid JOIN pg_class c ON c.oid=x.indexrelid
), functions AS (
 SELECT jsonb_agg(jsonb_build_object('name',p.proname,'arguments',pg_get_function_arguments(p.oid),
  'result',pg_get_function_result(p.oid),'language',l.lanname,'kind',p.prokind,'volatility',p.provolatile,
  'strict',p.proisstrict,'definer',p.prosecdef,'settings',p.proconfig,'returns_set',p.proretset,
  'body',replace(p.prosrc,E'\r\n',E'\n'),
  'public_privileges',EXISTS(SELECT 1 FROM aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) acl WHERE acl.grantee=0))
  ORDER BY p.proname COLLATE "C",p.oid::regprocedure::text COLLATE "C") AS value
 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace JOIN pg_language l ON l.oid=p.prolang
 WHERE n.nspname='issuance_service' AND (p.proname ~ 'application_ownership'
  OR p.proname IN ('external_observation_lock_organization','external_observation_lock_application'))
), internal_triggers AS (
 SELECT jsonb_agg(jsonb_build_object('table',r.relname,'constraint',c.conname,
  'function',t.tgfoid::regprocedure::text,'type',t.tgtype,'enabled',t.tgenabled,
  'referenced_relation',t.tgconstrrelid::regclass::text,'deferrable',t.tgdeferrable,
  'initially_deferred',t.tginitdeferred,'attributes',t.tgattr::text,
  'qualifier',pg_get_expr(t.tgqual,t.tgrelid),'arguments',encode(t.tgargs,'hex'))
  ORDER BY r.relname COLLATE "C",c.conname COLLATE "C",t.tgtype,t.tgfoid::regprocedure::text COLLATE "C") AS value
 FROM relations r JOIN pg_trigger t ON t.tgrelid=r.oid
 LEFT JOIN pg_constraint c ON c.oid=t.tgconstraint WHERE t.tgisinternal
), rules AS (
 SELECT jsonb_agg(jsonb_build_object('table',r.relname,'name',w.rulename,
  'enabled',w.ev_enabled,'definition',pg_get_ruledef(w.oid))
  ORDER BY r.relname COLLATE "C",w.rulename COLLATE "C") AS value
 FROM relations r JOIN pg_rewrite w ON w.ev_class=r.oid
), triggers AS (
 SELECT jsonb_agg(jsonb_build_object('table',r.relname,'name',t.tgname,'enabled',t.tgenabled,
  'definition',pg_get_triggerdef(t.oid),'arguments',encode(t.tgargs,'hex'))
  ORDER BY r.relname COLLATE "C",t.tgname COLLATE "C") AS value
 FROM relations r JOIN pg_trigger t ON t.tgrelid=r.oid WHERE NOT t.tgisinternal
)
SELECT jsonb_build_object('tables',coalesce(tables.value,'[]'::jsonb),'columns',coalesce(columns.value,'[]'::jsonb),
 'constraints',coalesce(constraints.value,'[]'::jsonb),'indexes',coalesce(indexes.value,'[]'::jsonb),
 'functions',coalesce(functions.value,'[]'::jsonb),'triggers',coalesce(triggers.value,'[]'::jsonb),
 'internal_triggers',coalesce(internal_triggers.value,'[]'::jsonb),'rules',coalesce(rules.value,'[]'::jsonb))
FROM tables,columns,constraints,indexes,functions,triggers,internal_triggers,rules;

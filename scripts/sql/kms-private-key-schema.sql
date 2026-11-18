
SELECT 'table:' || n.nspname || '.' || c.relname
FROM pg_catalog.pg_class AS c
JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace
WHERE c.relkind IN ('r', 'p', 'm', 'f')
  AND n.nspname NOT IN ('pg_catalog', 'information_schema')
  AND left(n.nspname, 3) <> 'pg_'
  AND (c.relname = 'issuer_signing_keys'
       OR c.relname ~* '(private_key|private_jwk|secret_key)')
UNION ALL
SELECT 'column:' || n.nspname || '.' || c.relname || '.' || a.attname
FROM pg_catalog.pg_attribute AS a
JOIN pg_catalog.pg_class AS c ON c.oid = a.attrelid
JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace
WHERE c.relkind IN ('r', 'p', 'm', 'f')
  AND a.attnum > 0 AND NOT a.attisdropped
  AND n.nspname NOT IN ('pg_catalog', 'information_schema')
  AND left(n.nspname, 3) <> 'pg_'
  AND a.attname ~* '(private_key|private_jwk|encrypted_jwk|secret_key|key_material)'
ORDER BY 1
LIMIT 20

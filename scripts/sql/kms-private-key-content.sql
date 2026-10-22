
DO $kms_private_content$
DECLARE
    candidate record;
    found boolean;
BEGIN
    FOR candidate IN
        SELECT n.nspname AS schema_name, c.relname AS table_name,
               a.attname AS column_name,
               a.atttypid IN ('json'::regtype, 'jsonb'::regtype) AS is_json
        FROM pg_catalog.pg_class AS c
        JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace
        JOIN pg_catalog.pg_attribute AS a ON a.attrelid = c.oid
        WHERE c.relkind IN ('r', 'p', 'm', 'f')
          AND a.attnum > 0 AND NOT a.attisdropped
          AND a.atttypid IN ('json'::regtype, 'jsonb'::regtype,
                              'text'::regtype, 'varchar'::regtype,
                              'bpchar'::regtype)
          AND n.nspname NOT IN ('pg_catalog', 'information_schema')
          AND left(n.nspname, 3) <> 'pg_'
    LOOP
        IF candidate.is_json THEN
            EXECUTE format(
                'SELECT EXISTS (SELECT 1 FROM %I.%I WHERE %I::text ~* %L '
                || 'OR %I::text ~* %L '
                || 'OR jsonb_path_exists(%I::jsonb, %L::jsonpath))',
                candidate.schema_name, candidate.table_name,
                candidate.column_name,
                '"[^"]*(private[^[:alnum:]]*(key|jwk|pem)|secret[^[:alnum:]]*key|encrypted[^[:alnum:]]*jwk|key[^[:alnum:]]*material|pkcs8)[^"]*"[[:space:]]*:',
                candidate.column_name,
                '-----BEGIN (RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----',
                candidate.column_name,
                '$.** ? (exists(@.kty) && (exists(@.d) || exists(@.p) || exists(@.q) || exists(@.dp) || exists(@.dq) || exists(@.qi) || exists(@.oth) || exists(@.k) || exists(@.rsa_d)))'
            ) INTO found;
        ELSE
            EXECUTE format(
                'SELECT EXISTS (SELECT 1 FROM %I.%I WHERE %I::text ~* %L)',
                candidate.schema_name, candidate.table_name,
                candidate.column_name,
                '-----BEGIN (RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----'
            ) INTO found;
        END IF;
        IF found THEN
            RAISE EXCEPTION 'private-key content storage in %.%.%',
                candidate.schema_name, candidate.table_name,
                candidate.column_name;
        END IF;
    END LOOP;
END
$kms_private_content$;

-- Read-only release check for the separate Keycloak database.
-- Run with psql -v ON_ERROR_STOP=1 after Keycloak has started and both realms
-- have issued and refreshed a token. Qualify the exact Keycloak image and
-- Marty provider JAR separately: database rows alone cannot prove that the
-- factory with a built-in provider ID is the approved remote implementation.
-- This script never selects or prints secret values.
BEGIN READ ONLY;

DO $keycloak_kms_only$
DECLARE
    expected_realms integer;
    total_realms integer;
    private_entries bigint;
    private_pem_entries bigint;
    private_jwk_entries bigint;
    private_schema_objects bigint;
    secret_entries bigint;
    unexpected_providers bigint;
    duplicate_providers bigint;
    missing_providers bigint;
BEGIN
    IF to_regclass('public.component') IS NULL
       OR to_regclass('public.component_config') IS NULL
       OR to_regclass('public.realm') IS NULL THEN
        RAISE EXCEPTION 'Keycloak key-provider catalog is missing';
    END IF;

    SELECT count(*) INTO expected_realms
    FROM public.realm
    WHERE name IN ('master', '11id');
    IF expected_realms <> 2 THEN
        RAISE EXCEPTION 'Keycloak master and 11id realms are both required';
    END IF;

    SELECT count(*) INTO total_realms FROM public.realm;

    SELECT count(*) FILTER (WHERE cc.name = 'secret'),
           count(DISTINCT c.id) FILTER (
               WHERE c.provider_id IS NULL OR c.provider_id NOT IN (
                   'rsa-generated', 'rsa-enc-generated',
                   'hmac-generated', 'aes-generated'))
    INTO secret_entries, unexpected_providers
    FROM public.component AS c
    JOIN public.realm AS r ON r.id = c.realm_id
    LEFT JOIN public.component_config AS cc ON cc.component_id = c.id
    WHERE c.provider_type = 'org.keycloak.keys.KeyProvider';

    -- Search every component, since a different SPI must not silently persist
    -- issuer keys outside the KeyProvider graph. Never print stored values.
    SELECT count(*) FILTER (WHERE cc.name ~* 'private[_-]?(key|jwk)'),
           count(*) FILTER (WHERE cc.value ~* '-----BEGIN ([A-Z0-9 ]* )?PRIVATE KEY-----'),
           count(*) FILTER (
               WHERE cc.value ~* '"kty"[[:space:]]*:[[:space:]]*"(RSA|EC|OKP|oct)"'
                 AND cc.value ~* '"(d|p|q|dp|dq|qi|oth|k)"[[:space:]]*:')
    INTO private_entries, private_pem_entries, private_jwk_entries
    FROM public.component_config AS cc;

    SELECT count(*) INTO private_schema_objects
    FROM information_schema.columns
    WHERE table_schema = 'public'
      AND (table_name ~* 'private[_-]?(key|jwk)'
           OR column_name ~* 'private[_-]?(key|jwk)');

    SELECT count(*) INTO duplicate_providers
    FROM (
        SELECT c.realm_id, c.provider_id
        FROM public.component AS c
        WHERE c.provider_type = 'org.keycloak.keys.KeyProvider'
        GROUP BY c.realm_id, c.provider_id
        HAVING count(*) <> 1
    ) AS duplicate;

    SELECT count(*) INTO missing_providers
    FROM public.realm AS r
    CROSS JOIN (VALUES ('rsa-generated'), ('rsa-enc-generated'),
                       ('hmac-generated'), ('aes-generated')) AS required(id)
    WHERE NOT EXISTS (
        SELECT 1 FROM public.component AS c
        WHERE c.realm_id = r.id
          AND c.provider_type = 'org.keycloak.keys.KeyProvider'
          AND c.provider_id = required.id
    );

    IF private_entries <> 0 OR private_pem_entries <> 0 OR private_jwk_entries <> 0
       OR private_schema_objects <> 0 OR secret_entries <> 0
       OR unexpected_providers <> 0 OR duplicate_providers <> 0
       OR missing_providers <> 0 THEN
        RAISE EXCEPTION
            'Keycloak KMS-only custody failed: private-key entries %, private-key PEM entries %, private JWK entries %, private-key schema objects %, local-secret entries %, unexpected providers %, duplicate providers %, missing required providers % across % realms',
            private_entries, private_pem_entries, private_jwk_entries, private_schema_objects,
            secret_entries, unexpected_providers,
            duplicate_providers, missing_providers, total_realms;
    END IF;
END
$keycloak_kms_only$;

COMMIT;

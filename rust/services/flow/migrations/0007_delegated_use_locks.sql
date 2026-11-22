-- Definition/proof locks for the distinct delegated-use transaction writer.
-- Helpers only read and lock exact rows; they cannot modify source state.

CREATE OR REPLACE FUNCTION flow_service.lock_delegated_use_definition(organization text, definition text)
RETURNS SETOF flow_service.flow_definitions
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $lock$
    SELECT source.* FROM flow_service.flow_definitions source
    WHERE source.organization_id=$1 AND source.id=$2 FOR SHARE OF source;
$lock$;
REVOKE ALL ON FUNCTION flow_service.lock_delegated_use_definition(text,text) FROM PUBLIC;

CREATE OR REPLACE FUNCTION flow_service.lock_delegated_use_proof(organization uuid, challenge uuid, submission uuid)
RETURNS SETOF flow_service.delegated_proof_submissions
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $lock$
    SELECT source.* FROM flow_service.delegated_proof_submissions source
    WHERE source.organization_id=$1 AND source.challenge_id=$2 AND source.submission_id=$3 FOR SHARE OF source;
$lock$;
REVOKE ALL ON FUNCTION flow_service.lock_delegated_use_proof(uuid,uuid,uuid) FROM PUBLIC;

INSERT INTO flow_service.rust_schema_versions(version) VALUES ('rust_flow_delegated_use_locks_0007') ON CONFLICT DO NOTHING;

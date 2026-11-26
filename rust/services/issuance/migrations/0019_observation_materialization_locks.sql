-- SPDX-License-Identifier: AGPL-3.0-only
-- Owner-installed, read-only row locks for the canonical evidence writer.
-- PostgreSQL row locking otherwise requires UPDATE on immutable journal rows.
-- Callers retain the existing authorization, snapshot and replay checks in
-- their transaction. These helpers neither write nor manufacture authority.
CREATE FUNCTION issuance_service.materialization_lock_binding(requested_organization uuid, requested_source text, requested_binding text)
RETURNS SETOF issuance_service.external_observation_bindings
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $materialization_binding$
    SELECT b.* FROM issuance_service.external_observation_bindings b
    WHERE b.organization_id=requested_organization AND b.source_id=requested_source
      AND b.id=requested_binding FOR SHARE OF b;
$materialization_binding$;

CREATE FUNCTION issuance_service.materialization_lock_journal(requested_receipt uuid, requested_organization text)
RETURNS TABLE(receipt issuance_service.external_observation_receipts, admission_event text, admission_received_at_ms bigint)
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $materialization_journal$
    SELECT r,a.event_type,a.received_at_ms
    FROM issuance_service.external_observation_receipts r
    JOIN issuance_service.external_observation_audit a ON a.receipt_id=r.receipt_id
    WHERE r.receipt_id=requested_receipt AND r.organization_id=requested_organization
    FOR SHARE OF r,a;
$materialization_journal$;

CREATE FUNCTION issuance_service.materialization_lock_head(requested_organization text, requested_source text, requested_binding text)
RETURNS SETOF issuance_service.external_observation_heads
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $materialization_head$
    SELECT h.* FROM issuance_service.external_observation_heads h
    WHERE h.organization_id=requested_organization AND h.source_id=requested_source
      AND h.binding_id=requested_binding FOR SHARE OF h;
$materialization_head$;

REVOKE ALL ON FUNCTION issuance_service.materialization_lock_binding(uuid,text,text),
    issuance_service.materialization_lock_journal(uuid,text),
    issuance_service.materialization_lock_head(text,text,text) FROM PUBLIC;

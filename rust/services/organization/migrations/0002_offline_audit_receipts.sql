-- Receipts use the existing append-only audit store. These indexes do not
-- change uniqueness or retention of any other organization audit event.
CREATE UNIQUE INDEX IF NOT EXISTS uq_offline_audit_organization_event
    ON organization_service.audit_events
      (organization_id, (metadata->'offline_receipt'->>'event_id'))
    WHERE event_type='offline_verification.reported';

CREATE UNIQUE INDEX IF NOT EXISTS uq_offline_audit_organization_verification
    ON organization_service.audit_events (organization_id, resource_id)
    WHERE event_type='offline_verification.reported';

INSERT INTO organization_service.rust_schema_versions(version)
VALUES ('rust_organization_0002_offline_audit') ON CONFLICT DO NOTHING;

-- Synthetic fixture only. The driver appends the real verifier and rollback.
BEGIN;
CREATE TRIGGER synthetic_unreviewed_companion BEFORE UPDATE ON issuance_service.physical_document_jobs FOR EACH ROW EXECUTE FUNCTION issuance_service.guard_administratively_cancelled_passport_job();

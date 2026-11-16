/**
 * Pure helpers for the organization applications page.
 */

export function mergeApplicantsIntoApplications(applications, applicants = []) {
  const applicantById = new Map(applicants.map((a) => [a.id, a]));
  return applications.map((app) => {
    const applicant = applicantById.get(app.applicant_id);
    const status = (app.status || '').toLowerCase();
    const metadata = app.metadata || {};
    return {
      id: app.id,
      reference: app.reference_number,
      applicant: applicant?.email || app.applicant_email || app.applicant_identifier || app.applicant_id,
      credentialType: app.credential_display_name || app.credential_template_id,
      submittedAt: app.submitted_at || app.created_at,
      // The native queue does not report these signals. Missing evidence must
      // remain unknown instead of claiming every application passed checks.
      documentsUploaded: typeof app.documents_uploaded === 'boolean' ? app.documents_uploaded : null,
      verificationPassed: typeof app.verification_passed === 'boolean' ? app.verification_passed : null,
      status,
      rawStatus: status,
      issuanceTransactionId: metadata.issuance_transaction_id || null,
    };
  });
}

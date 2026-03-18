/**
 * Pure helpers for the organization applications page.
 */

export function mergeApplicantsIntoApplications(applications, applicants) {
  const applicantById = new Map(applicants.map((a) => [a.id, a]));
  return applications.map((app) => {
    const applicant = applicantById.get(app.applicant_id);
    const status = (app.status || '').toLowerCase();
    const metadata = app.metadata || {};
    return {
      id: app.id,
      applicant: applicant?.email || app.applicant_id,
      credentialType: app.credential_display_name || metadata.credential_display_name || app.credential_configuration_id,
      submittedAt: app.submitted_at || app.created_at,
      documentsUploaded: true,
      verificationPassed: true,
      status,
      rawStatus: status,
      issuanceTransactionId: metadata.issuance_transaction_id || null,
    };
  });
}

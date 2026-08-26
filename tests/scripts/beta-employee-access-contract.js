'use strict';

function employeeAccessBehaviorAssertions(report = {}) {
  const application = report.application || {};
  const issuance = report.issuance || {};
  const activeAccess = report.activeAccess || {};
  const suspension = report.suspension || {};

  return {
    approve_employee: Boolean(
      application.created
      && String(application.submittedStatus || '').toUpperCase() === 'SUBMITTED'
      && application.lockAcquired
      && application.approvalOk
      && String(application.approvedStatus || '').toUpperCase() === 'APPROVED',
    ),
    issue_employee_credential: Boolean(
      issuance.issueOk
      && issuance.walletReceived
      && issuance.vct
      && issuance.vct === report.configuration?.vct
      && issuance.credentialId,
    ),
    allow_active_access: Boolean(
      String(activeAccess.credentialStatus || '').toUpperCase() === 'ACTIVE'
      && activeAccess.result?.decision === 'allow',
    ),
    suspended_employee_denied: Boolean(
      suspension.actionOk
      && String(suspension.credentialStatus || '').toUpperCase() === 'SUSPENDED'
      && suspension.result?.decision === 'deny'
      && /suspend/i.test(suspension.result?.decisionReason || ''),
    ),
  };
}

module.exports = { employeeAccessBehaviorAssertions };

'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const { employeeAccessBehaviorAssertions } = require('./beta-employee-access-contract');

function passingReport() {
  return {
    configuration: { vct: 'https://beta.example/credentials/employee-access' },
    application: {
      created: true,
      employeeId: 'EMP-D04-1',
      submittedStatus: 'SUBMITTED',
      lockAcquired: true,
      approvalOk: true,
      approvedStatus: 'APPROVED',
    },
    issuance: {
      issueOk: true,
      walletReceived: true,
      vct: 'https://beta.example/credentials/employee-access',
      credentialId: 'credential-1',
    },
    activeAccess: {
      credentialStatus: 'ACTIVE',
      result: { decision: 'allow', decisionReason: 'Requirements satisfied' },
    },
    suspension: {
      actionOk: true,
      credentialStatus: 'SUSPENDED',
      result: { decision: 'deny', decisionReason: 'Credential suspended' },
    },
  };
}

test('requires the complete employee approval, issuance, allow, and suspension behavior', () => {
  assert.deepEqual(employeeAccessBehaviorAssertions(passingReport()), {
    approve_employee: true,
    issue_employee_credential: true,
    allow_active_access: true,
    suspended_employee_denied: true,
  });
});

test('does not accept issuance without approval or an untested active state', () => {
  const noApproval = passingReport();
  noApproval.application.approvalOk = false;
  assert.equal(employeeAccessBehaviorAssertions(noApproval).approve_employee, false);

  const noActiveDecision = passingReport();
  noActiveDecision.activeAccess.result = null;
  assert.equal(employeeAccessBehaviorAssertions(noActiveDecision).allow_active_access, false);

  const failOpen = passingReport();
  failOpen.suspension.result = { decision: 'allow', decisionReason: 'Requirements satisfied' };
  assert.equal(employeeAccessBehaviorAssertions(failOpen).suspended_employee_denied, false);

  const wrongCredentialType = passingReport();
  wrongCredentialType.issuance.vct = 'https://beta.example/credentials/not-employee-access';
  assert.equal(employeeAccessBehaviorAssertions(wrongCredentialType).issue_employee_credential, false);
});

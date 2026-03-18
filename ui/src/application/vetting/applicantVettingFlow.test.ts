import { describe, expect, it } from 'vitest';

import {
  APPLICATION_WIZARD_STEPS,
  APPLICANT_REGISTRATION_STEPS,
  buildApplicantRegistrationPayload,
  buildApplicationCreationPayload,
  buildApprovalPayload,
  buildCompleteCheckPayload,
  buildRejectionPayload,
  canCompleteBiometricEnrollment,
  canContinueApplicantRegistration,
  canRejectApplication,
  canSubmitApplicationWizard,
  createApplicantRegistrationFormData,
  createApplicationWizardFormData,
  filterApplicationsByTab,
  formatStatusLabel,
  getDashboardStats,
  mapApprovedApplicantOptions,
  normalizeCheckStatus,
  normalizeEnumValue,
  resolveApprovalNotesInput,
  resolveApplicantCreated,
  resolveApplicantRegistrationCompleted,
  resolveApproveDialogClose,
  resolveApproveDialogOpen,
  resolveApprovedApplicantSelection,
  resolveApprovedApplicantSelected,
  resolveApprovedApplicationsLoadResult,
  resolveApplicationCreated,
  resolveApplicationSubmitted,
  resolveApproveSuccess,
  resolveBiometricCaptured,
  resolveCheckCompletionSuccess,
  resolveDashboardTabChange,
  resolveDetailDialogClose,
  resolveDashboardLoadResult,
  resolveDocumentTypeDetails,
  resolveDocumentTypesLoadResult,
  resolveRejectDialogClose,
  resolveRejectDialogOpen,
  resolveRejectionReasonInput,
  resolveRejectSuccess,
  resolveViewDetailsResult,
  updateApplicantRegistrationFormData,
  updateApplicationWizardFormData,
} from './applicantVettingFlow';

describe('applicantVettingFlow helpers', () => {
  it('exports the expected step definitions', () => {
    expect(APPLICANT_REGISTRATION_STEPS).toHaveLength(3);
    expect(APPLICATION_WIZARD_STEPS).toHaveLength(3);
  });

  it('normalizes enums and check statuses', () => {
    expect(normalizeEnumValue('pending-approval')).toBe('PENDING_APPROVAL');
    expect(normalizeCheckStatus('completed-passed')).toBe('PASSED');
    expect(formatStatusLabel('PENDING_APPROVAL')).toBe('Pending Approval');
  });

  it('builds applicant registration payloads and validates required fields', () => {
    expect(createApplicantRegistrationFormData()).toEqual({
      given_name: '',
      family_name: '',
      email: '',
      phone_number: '',
      date_of_birth: '',
      nationality: 'USA',
      address: {
        street_line1: '',
        street_line2: '',
        city: '',
        state_province: '',
        postal_code: '',
        country: 'USA',
      },
    });

    expect(updateApplicantRegistrationFormData(createApplicantRegistrationFormData(), 'address.city', 'London')).toMatchObject({
      address: { city: 'London' },
    });

    expect(buildApplicantRegistrationPayload({
      userId: 'user-1',
      formData: { given_name: 'Ada' },
    })).toEqual({
      user_id: 'user-1',
      given_name: 'Ada',
    });

    expect(canContinueApplicantRegistration({ given_name: 'Ada', family_name: 'Lovelace', email: 'ada@example.com' })).toBe(true);
    expect(canContinueApplicantRegistration({ given_name: 'Ada', family_name: '', email: 'ada@example.com' })).toBe(false);
  });

  it('validates biometric completion requirements', () => {
    expect(canCompleteBiometricEnrollment({ createdApplicant: { id: 'app-1' }, biometricData: { image: true } })).toBe(true);
    expect(canCompleteBiometricEnrollment({ createdApplicant: null, biometricData: { image: true } })).toBe(false);
    expect(resolveApplicantCreated({ id: 'app-1' })).toEqual({ createdApplicant: { id: 'app-1' }, activeStep: 1 });
    expect(resolveBiometricCaptured({ image: true })).toEqual({ biometricData: { image: true } });
    expect(resolveApplicantRegistrationCompleted({ id: 'app-1' })).toEqual({
      activeStep: 2,
      completedApplicant: { id: 'app-1' },
    });
  });

  it('builds application payloads and resolves document type details', () => {
    expect(createApplicationWizardFormData('Gov Agency')).toEqual({
      document_type: 'PASSPORT',
      issuing_authority: 'Gov Agency',
      requested_validity_years: 10,
      travel_purpose: '',
      destination_countries: [],
      is_expedited: false,
    });

    expect(updateApplicationWizardFormData(createApplicationWizardFormData('Gov Agency'), 'document_type', 'VISA')).toMatchObject({
      document_type: 'VISA',
      issuing_authority: 'Gov Agency',
    });

    expect(buildApplicationCreationPayload({
      applicantId: 'app-1',
      formData: { document_type: 'PASSPORT' },
    })).toEqual({
      applicant_id: 'app-1',
      document_type: 'PASSPORT',
    });

    expect(canSubmitApplicationWizard({ document_type: 'PASSPORT' })).toBe(true);
    expect(resolveDocumentTypeDetails([{ document_type: 'PASSPORT', label: 'Passport' }], 'PASSPORT')).toEqual({
      document_type: 'PASSPORT',
      label: 'Passport',
    });
    expect(resolveDocumentTypesLoadResult([{ document_type: 'PASSPORT' }])).toEqual({
      documentTypes: [{ document_type: 'PASSPORT' }],
    });
    expect(resolveApplicationCreated({ id: 'application-1' })).toEqual({
      createdApplication: { id: 'application-1' },
      activeStep: 1,
    });
    expect(resolveApplicationSubmitted({ id: 'application-1' })).toEqual({
      createdApplication: { id: 'application-1' },
      activeStep: 2,
      completedApplication: { id: 'application-1' },
    });
  });

  it('builds dashboard action payloads', () => {
    expect(buildApprovalPayload({ notes: 'Looks good' })).toEqual({ approved_by: 'admin', notes: 'Looks good' });
    expect(buildRejectionPayload({ reason: 'Missing evidence' })).toEqual({ rejected_by: 'admin', reason: 'Missing evidence' });
    expect(buildCompleteCheckPayload({ passed: false })).toEqual({
      passed: false,
      performed_by: 'admin',
      notes: 'Failed verification',
    });
    expect(canRejectApplication('Because')).toBe(true);
    expect(canRejectApplication('')).toBe(false);
  });

  it('filters applications by tab and derives dashboard stats', () => {
    const applications = [
      { id: '1', status: 'pending_approval' },
      { id: '2', status: 'under_review' },
      { id: '3', status: 'approved', approved_at: '2026-03-16T10:00:00.000Z' },
    ];

    expect(filterApplicationsByTab(applications, 1)).toEqual([{ id: '1', status: 'pending_approval' }]);
    expect(getDashboardStats(applications, [{ id: 'check-1' }], new Date('2026-03-16T12:00:00.000Z'))).toEqual({
      pendingApprovalCount: 1,
      underReviewCount: 1,
      pendingChecksCount: 1,
      approvedTodayCount: 1,
    });

    expect(resolveDashboardTabChange(2)).toEqual({ tabValue: 2 });
  });

  it('maps approved applicant options for selection UIs', () => {
    expect(mapApprovedApplicantOptions([
      {
        application_id: 'app-1',
        applicant_name: 'Ada Lovelace',
        reference_number: 'REF-1',
        document_type: 'PASSPORT',
      },
    ])).toEqual([
      {
        value: 'app-1',
        primaryLabel: 'Ada Lovelace',
        secondaryLabel: 'REF-1 - PASSPORT',
      },
    ]);
  });

  it('normalizes dashboard load and detail view results', () => {
    expect(resolveDashboardLoadResult({
      applicationsResponse: { applications: [{ id: 'app-1' }] },
      pendingChecksResponse: [{ id: 'check-1' }],
    })).toEqual({
      applications: [{ id: 'app-1' }],
      pendingChecks: [{ id: 'check-1' }],
    });

    expect(resolveViewDetailsResult({
      application: { id: 'app-1' },
      details: { application: { id: 'app-1' } },
    })).toEqual({
      selectedApplication: { id: 'app-1' },
      applicationDetails: { application: { id: 'app-1' } },
      detailDialogOpen: true,
    });

    expect(resolveDetailDialogClose()).toEqual({
      detailDialogOpen: false,
    });
  });

  it('builds dashboard dialog transitions', () => {
    expect(resolveApproveDialogOpen({ id: 'app-1' })).toEqual({
      selectedApplication: { id: 'app-1' },
      approveDialogOpen: true,
    });

    expect(resolveApproveDialogClose()).toEqual({
      approveDialogOpen: false,
      approvalNotes: '',
    });

    expect(resolveRejectDialogOpen({ id: 'app-2' })).toEqual({
      selectedApplication: { id: 'app-2' },
      rejectDialogOpen: true,
    });

    expect(resolveRejectDialogClose()).toEqual({
      rejectDialogOpen: false,
      rejectionReason: '',
    });

    expect(resolveApprovalNotesInput('Looks good')).toEqual({ approvalNotes: 'Looks good' });
    expect(resolveRejectionReasonInput('Missing docs')).toEqual({ rejectionReason: 'Missing docs' });
  });

  it('builds approve, reject, and check completion outcomes', () => {
    expect(resolveApproveSuccess()).toEqual({
      successMessage: 'Application approved successfully',
      approveDialogOpen: false,
      approvalNotes: '',
      shouldReload: true,
    });

    expect(resolveRejectSuccess()).toEqual({
      successMessage: 'Application rejected',
      rejectDialogOpen: false,
      rejectionReason: '',
      shouldReload: true,
    });

    expect(resolveCheckCompletionSuccess(false)).toEqual({
      successMessage: 'Check failed',
      shouldReload: true,
      shouldRefreshDetails: true,
    });
  });

  it('resolves approved-applicant loading and selection', () => {
    const approvedApps = [{ application_id: 'app-1', applicant_name: 'Ada', reference_number: 'REF-1', document_type: 'PASSPORT' }];

    expect(resolveApprovedApplicationsLoadResult(approvedApps)).toEqual({
      approvedApps,
      options: [{ value: 'app-1', primaryLabel: 'Ada', secondaryLabel: 'REF-1 - PASSPORT' }],
    });

    expect(resolveApprovedApplicantSelection(approvedApps, 'app-1')).toEqual(approvedApps[0]);
    expect(resolveApprovedApplicantSelection(approvedApps, 'missing')).toBeNull();
    expect(resolveApprovedApplicantSelected(approvedApps, 'app-1')).toEqual({
      selectedApp: approvedApps[0],
    });
  });
});

import { describe, expect, it, vi } from 'vitest';

import {
  approveVettingApplication,
  completeApplicantBiometricEnrollment,
  completeVettingDashboardCheck,
  createApplicantDocumentApplication,
  loadApplicationDocumentTypes,
  loadApprovedApplicantOptions,
  loadVettingApplicationDetails,
  loadVettingDashboard,
  registerApplicant,
  rejectVettingApplication,
  submitApplicantDocumentApplication,
} from './applicantVettingUseCases';

describe('applicantVetting use cases', () => {
  it('registers an applicant through injected dependencies', async () => {
    const createApplicant = vi.fn().mockResolvedValue({ id: 'app-1' });

    await expect(registerApplicant({
      createApplicant,
      userId: 'user-1',
      formData: { given_name: 'Ada' },
    })).resolves.toEqual({
      createdApplicant: { id: 'app-1' },
      activeStep: 1,
    });

    expect(createApplicant).toHaveBeenCalledWith({
      user_id: 'user-1',
      given_name: 'Ada',
    });
  });

  it('completes biometric enrollment only when requirements are met', async () => {
    const enrollBiometric = vi.fn().mockResolvedValue(undefined);
    const createdApplicant = { id: 'app-1' };
    const biometricData = { image_data_base64: 'abc' };

    await expect(completeApplicantBiometricEnrollment({
      enrollBiometric,
      createdApplicant,
      biometricData,
    })).resolves.toEqual({
      activeStep: 2,
      completedApplicant: createdApplicant,
    });

    await expect(completeApplicantBiometricEnrollment({
      enrollBiometric,
      createdApplicant: null,
      biometricData,
    })).resolves.toBeNull();
  });

  it('loads document types and creates/submits applications', async () => {
    const getDocumentTypes = vi.fn().mockResolvedValue([{ document_type: 'PASSPORT' }]);
    const createApplication = vi.fn().mockResolvedValue({ id: 'created-1' });
    const submitApplication = vi.fn().mockResolvedValue({ id: 'submitted-1' });

    await expect(loadApplicationDocumentTypes({ getDocumentTypes })).resolves.toEqual({
      documentTypes: [{ document_type: 'PASSPORT' }],
    });

    await expect(createApplicantDocumentApplication({
      createApplication,
      applicantId: 'applicant-1',
      formData: { document_type: 'PASSPORT' },
    })).resolves.toEqual({
      createdApplication: { id: 'created-1' },
      activeStep: 1,
    });

    expect(createApplication).toHaveBeenCalledWith({
      applicant_id: 'applicant-1',
      document_type: 'PASSPORT',
    });

    await expect(submitApplicantDocumentApplication({
      submitApplication,
      createdApplication: { id: 'created-1' },
    })).resolves.toEqual({
      createdApplication: { id: 'submitted-1' },
      activeStep: 2,
      completedApplication: { id: 'submitted-1' },
    });
  });

  it('loads dashboard data and details', async () => {
    const listApplications = vi.fn().mockResolvedValue({ applications: [{ id: 'app-1' }] });
    const getPendingChecks = vi.fn().mockResolvedValue([{ id: 'check-1' }]);
    const getApplication = vi.fn().mockResolvedValue({ application: { id: 'app-1' } });

    await expect(loadVettingDashboard({ listApplications, getPendingChecks, limit: 25 })).resolves.toEqual({
      applications: [{ id: 'app-1' }],
      pendingChecks: [{ id: 'check-1' }],
    });

    expect(listApplications).toHaveBeenCalledWith({ limit: 25 });

    await expect(loadVettingApplicationDetails({
      getApplication,
      application: { id: 'app-1' },
    })).resolves.toEqual({
      selectedApplication: { id: 'app-1' },
      applicationDetails: { application: { id: 'app-1' } },
      detailDialogOpen: true,
    });
  });

  it('runs approve, reject, and complete-check workflows', async () => {
    const approveApplication = vi.fn().mockResolvedValue(undefined);
    const rejectApplication = vi.fn().mockResolvedValue(undefined);
    const completeCheck = vi.fn().mockResolvedValue(undefined);
    const getApplication = vi.fn().mockResolvedValue({ application: { id: 'app-1' } });

    await expect(approveVettingApplication({
      approveApplication,
      applicationId: 'app-1',
      approvalNotes: 'Looks good',
    })).resolves.toEqual({
      successMessage: 'Application approved successfully',
      approveDialogOpen: false,
      approvalNotes: '',
      shouldReload: true,
    });

    expect(approveApplication).toHaveBeenCalledWith('app-1', {
      approved_by: 'admin',
      notes: 'Looks good',
    });

    await expect(rejectVettingApplication({
      rejectApplication,
      applicationId: 'app-2',
      rejectionReason: 'Missing documents',
    })).resolves.toEqual({
      successMessage: 'Application rejected',
      rejectDialogOpen: false,
      rejectionReason: '',
      shouldReload: true,
    });

    expect(rejectApplication).toHaveBeenCalledWith('app-2', {
      rejected_by: 'admin',
      reason: 'Missing documents',
    });

    await expect(completeVettingDashboardCheck({
      completeCheck,
      getApplication,
      checkId: 'check-1',
      passed: true,
      applicationDetails: { application: { id: 'app-1' } },
      selectedApplication: { id: 'app-1' },
    })).resolves.toEqual({
      successMessage: 'Check passed',
      shouldReload: true,
      shouldRefreshDetails: true,
      applicationDetails: { application: { id: 'app-1' } },
    });
  });

  it('loads approved applicants through injected dependencies', async () => {
    const getApprovedApplications = vi.fn().mockResolvedValue([
      {
        application_id: 'app-1',
        applicant_name: 'Ada Lovelace',
        reference_number: 'REF-1',
        document_type: 'PASSPORT',
      },
    ]);

    await expect(loadApprovedApplicantOptions({ getApprovedApplications })).resolves.toEqual({
      approvedApps: [
        {
          application_id: 'app-1',
          applicant_name: 'Ada Lovelace',
          reference_number: 'REF-1',
          document_type: 'PASSPORT',
        },
      ],
      options: [
        {
          value: 'app-1',
          primaryLabel: 'Ada Lovelace',
          secondaryLabel: 'REF-1 - PASSPORT',
        },
      ],
    });
  });
});

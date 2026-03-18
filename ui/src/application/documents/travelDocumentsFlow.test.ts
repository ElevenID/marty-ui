import { describe, expect, it } from 'vitest';

import {
  TRAVEL_DOCUMENTS_DEFAULT_STATS,
  canSubmitTravelDocumentIssue,
  createTravelDocumentIssueForm,
  formatTravelDocumentDate,
  formatTravelDocumentDateTime,
  prefillTravelDocumentIssueForm,
  resolveApprovedTravelDocumentApplicants,
  resolveTravelDocumentsList,
  resolveTravelDocumentStats,
} from './travelDocumentsFlow';

describe('travelDocumentsFlow helpers', () => {
  it('creates a default issue form and prefills it from an approved applicant', () => {
    const form = createTravelDocumentIssueForm({ issuingAuthority: 'Demo Authority' });

    expect(form).toMatchObject({
      document_type: 'eMRTD',
      issuing_authority: 'Demo Authority',
      validity_years: 10,
    });

    expect(prefillTravelDocumentIssueForm(form, {
      document_type: 'Visa',
      applicant_name: 'Avery Example',
      applicant_given_name: 'Avery',
      applicant_family_name: 'Example',
      applicant_dob: '1990-01-02',
      applicant_nationality: 'CAN',
    })).toMatchObject({
      document_type: 'Visa',
      holder_name: 'Avery Example',
      holder_given_name: 'Avery',
      holder_family_name: 'Example',
      holder_dob: '1990-01-02',
      nationality: 'CAN',
      issuing_country: 'CAN',
    });
  });

  it('normalizes dashboard list, stats, and approved applicants payloads', () => {
    expect(resolveTravelDocumentsList({
      documents: [{ id: 'doc-1' }],
      total: 9,
    })).toEqual({
      documents: [{ id: 'doc-1' }],
      total: 9,
    });

    expect(resolveTravelDocumentStats({
      total_documents: 3,
      by_status: { active: 2 },
      by_type: { eMRTD: 1 },
    })).toEqual({
      ...TRAVEL_DOCUMENTS_DEFAULT_STATS,
      total_documents: 3,
      by_status: {
        ...TRAVEL_DOCUMENTS_DEFAULT_STATS.by_status,
        active: 2,
      },
      by_type: { eMRTD: 1 },
    });

    expect(resolveApprovedTravelDocumentApplicants({
      applications: [{ application_id: 'app-1' }],
    })).toEqual([{ application_id: 'app-1' }]);
  });

  it('formats dates and determines whether issue submission is allowed', () => {
    expect(formatTravelDocumentDate('2026-03-17T12:00:00.000Z')).not.toBe('N/A');
    expect(formatTravelDocumentDateTime('2026-03-17T12:00:00.000Z')).not.toBe('N/A');
    expect(formatTravelDocumentDate(null)).toBe('N/A');

    expect(canSubmitTravelDocumentIssue({
      issueMode: 'applicant',
      selectedApplicant: { application_id: 'app-1' },
    })).toBe(true);

    expect(canSubmitTravelDocumentIssue({
      issueMode: 'manual',
      issueForm: {
        document_number: 'P1234',
        holder_name: 'Avery Example',
        holder_dob: '1990-01-02',
      },
    })).toBe(true);

    expect(canSubmitTravelDocumentIssue({
      loading: true,
      issueMode: 'manual',
      issueForm: {
        document_number: 'P1234',
        holder_name: 'Avery Example',
        holder_dob: '1990-01-02',
      },
    })).toBe(false);
  });
});

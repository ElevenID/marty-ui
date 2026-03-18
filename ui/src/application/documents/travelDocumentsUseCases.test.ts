import { describe, expect, it, vi } from 'vitest';

import {
  deleteTravelDocument,
  issueTravelDocument,
  loadApprovedTravelDocumentApplicants,
  loadTravelDocumentAudit,
  loadTravelDocumentsDashboard,
  updateTravelDocumentStatus,
} from './travelDocumentsUseCases';

describe('travelDocumentsUseCases', () => {
  it('loads documents and stats together while preserving stats fallback behavior', async () => {
    await expect(loadTravelDocumentsDashboard({
      filters: { document_type: 'eMRTD', limit: 10, offset: 20 },
      getDocuments: vi.fn().mockResolvedValue({
        documents: [{ id: 'doc-1' }],
        total: 1,
      }),
      getDocumentStats: vi.fn().mockResolvedValue({
        total_documents: 8,
        by_status: { active: 6 },
      }),
    })).resolves.toMatchObject({
      documents: [{ id: 'doc-1' }],
      total: 1,
      stats: expect.objectContaining({
        total_documents: 8,
        by_status: expect.objectContaining({ active: 6 }),
      }),
      statsError: null,
    });

    await expect(loadTravelDocumentsDashboard({
      getDocuments: vi.fn().mockResolvedValue({ documents: [], total: 0 }),
      getDocumentStats: vi.fn().mockRejectedValue(new Error('stats unavailable')),
    })).resolves.toMatchObject({
      documents: [],
      total: 0,
      statsError: 'stats unavailable',
    });
  });

  it('loads approved applicants and routes issue flows correctly', async () => {
    await expect(loadApprovedTravelDocumentApplicants({
      documentType: 'Visa',
      getApprovedApplicants: vi.fn().mockResolvedValue({
        applications: [{ application_id: 'app-1' }],
      }),
    })).resolves.toEqual([{ application_id: 'app-1' }]);

    const issueDocument = vi.fn().mockResolvedValue({ id: 'doc-manual' });
    const issueDocumentForApplicant = vi.fn().mockResolvedValue({ id: 'doc-applicant' });

    await expect(issueTravelDocument({
      issueMode: 'manual',
      issueForm: { document_number: 'P123', holder_name: 'Avery Example' },
      issueDocument,
      issueDocumentForApplicant,
    })).resolves.toEqual({
      successMessage: 'Document issued successfully',
    });

    await expect(issueTravelDocument({
      issueMode: 'applicant',
      selectedApplicant: { application_id: 'app-7' },
      issueForm: {},
      issueDocument,
      issueDocumentForApplicant,
      now: () => 42,
    })).resolves.toEqual({
      successMessage: 'Document issued successfully for approved applicant',
    });

    expect(issueDocument).toHaveBeenCalledTimes(1);
    expect(issueDocumentForApplicant).toHaveBeenCalledWith({
      applicationId: 'app-7',
      documentNumber: undefined,
      now: expect.any(Function),
    });
  });

  it('wraps status, delete, and audit actions for the adapter', async () => {
    const updateDocumentStatus = vi.fn().mockResolvedValue({});
    const deleteDocument = vi.fn().mockResolvedValue(null);
    const getDocumentAudit = vi.fn().mockResolvedValue({
      entries: [{ id: 'audit-1', event_type: 'issued' }],
    });

    await expect(updateTravelDocumentStatus({
      documentId: 'doc-1',
      status: 'suspended',
      reason: 'manual review',
      updateDocumentStatus,
    })).resolves.toEqual({
      successMessage: 'Document status updated to suspended',
    });

    await expect(deleteTravelDocument({
      documentId: 'doc-1',
      reason: 'duplicate',
      deleteDocument,
    })).resolves.toEqual({
      successMessage: 'Document deleted successfully',
    });

    await expect(loadTravelDocumentAudit({
      documentId: 'doc-1',
      getDocumentAudit,
    })).resolves.toEqual({
      entries: [{ id: 'audit-1', event_type: 'issued' }],
    });
  });
});

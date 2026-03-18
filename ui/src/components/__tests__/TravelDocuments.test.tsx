import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen, waitFor } from '@test/utils';

import TravelDocuments from '../TravelDocuments';

const { mockLoadTravelDocumentsDashboard, mockLoadApprovedTravelDocumentApplicants } = vi.hoisted(() => ({
  mockLoadTravelDocumentsDashboard: vi.fn(),
  mockLoadApprovedTravelDocumentApplicants: vi.fn(),
}));

vi.mock('../../hooks/useBranding', () => ({
  useBranding: () => ({
    issuingAuthority: 'Demo Authority',
  }),
}));

vi.mock('../../application/documents', async () => {
  const actual = await vi.importActual<typeof import('../../application/documents')>('../../application/documents');

  return {
    ...actual,
    loadTravelDocumentsDashboard: (...args: unknown[]) => mockLoadTravelDocumentsDashboard(...args),
    loadApprovedTravelDocumentApplicants: (...args: unknown[]) => mockLoadApprovedTravelDocumentApplicants(...args),
  };
});

describe('TravelDocuments', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockLoadTravelDocumentsDashboard.mockResolvedValue({
      documents: [
        {
          id: 'doc-1',
          document_type: 'eMRTD',
          document_number: 'P1234567',
          holder_name: 'Avery Example',
          nationality: 'USA',
          issued_at: '2026-03-17T00:00:00.000Z',
          expires_at: '2036-03-17T00:00:00.000Z',
          status: 'active',
        },
      ],
      total: 1,
      stats: {
        total_documents: 1,
        by_status: { active: 1 },
        issued_today: 1,
        expiring_soon: 0,
        by_type: { eMRTD: 1 },
      },
      statsError: null,
    });
    mockLoadApprovedTravelDocumentApplicants.mockResolvedValue([]);
  });

  it('loads the dashboard data into the stats cards and table', async () => {
    render(<TravelDocuments />);

    expect(await screen.findByTestId('document-row-doc-1')).toBeInTheDocument();
    expect(screen.getByText('P1234567')).toBeInTheDocument();
    expect(mockLoadTravelDocumentsDashboard).toHaveBeenCalledWith({
      filters: {
        document_type: undefined,
        status: undefined,
        limit: 10,
        offset: 0,
      },
    });
  });

  it('loads approved applicants when opening issuance from a document type card', async () => {
    const { user } = render(<TravelDocuments />);

    await screen.findByTestId('document-row-doc-1');
    await user.click(screen.getByRole('tab', { name: 'Document Types' }));
    await user.click(screen.getAllByRole('button', { name: 'Issue New' })[0]);

    expect(await screen.findByTestId('issue-document-dialog')).toBeInTheDocument();
    await waitFor(() => {
      expect(mockLoadApprovedTravelDocumentApplicants).toHaveBeenCalledWith({ documentType: 'eMRTD' });
    });
  });
});

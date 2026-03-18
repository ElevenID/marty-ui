import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen } from '@test/utils';

import MasterListViewer from '../MasterListViewer';

const { mockLoadMasterLists } = vi.hoisted(() => ({
  mockLoadMasterLists: vi.fn(),
}));

vi.mock('../../application/admin', async () => {
  const actual = await vi.importActual<typeof import('../../application/admin')>('../../application/admin');
  return {
    ...actual,
    loadMasterLists: (...args: unknown[]) => mockLoadMasterLists(...args),
  };
});

describe('MasterListViewer', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockLoadMasterLists.mockResolvedValue({
      masterLists: [
        {
          country: 'CAN',
          sequenceNumber: 12,
          version: '1.0.0',
          issueDate: '2026-03-01T00:00:00.000Z',
          nextUpdate: '2026-04-01T00:00:00.000Z',
          signer: 'CAN CSCA',
          metadata: { testingOnly: false },
          certificates: [
            {
              certificateId: 'CAN_CSCA_1',
              thumbprint: 'abcdef1234567890',
              subject: 'CN=CAN CSCA 1, O=CAN Government, C=CAN',
              validFrom: '2025-01-01T00:00:00.000Z',
              validTo: '2027-01-01T00:00:00.000Z',
            },
          ],
        },
      ],
      error: null,
    });
  });

  it('loads master list summaries and country content', async () => {
    render(<MasterListViewer />);

    expect(await screen.findByText('CAN')).toBeInTheDocument();
    expect(screen.getByText('Countries')).toBeInTheDocument();
    expect(screen.getByText('Total Certificates')).toBeInTheDocument();
    expect(screen.getByText('Valid Certificates')).toBeInTheDocument();
    expect(mockLoadMasterLists).toHaveBeenCalledTimes(1);
  });

  it('shows the fallback info alert when sample data is used', async () => {
    mockLoadMasterLists.mockResolvedValueOnce({
      masterLists: [],
      error: 'offline',
    });

    render(<MasterListViewer />);

    expect(await screen.findByText('offline')).toBeInTheDocument();
  });
});

import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen, waitFor } from '@test/utils';

import CscaManager from '../CscaManager';

const {
  mockLoadCscaCertificates,
  mockCreateCscaCertificate,
} = vi.hoisted(() => ({
  mockLoadCscaCertificates: vi.fn(),
  mockCreateCscaCertificate: vi.fn(),
}));

vi.mock('../../application/admin', async () => {
  const actual = await vi.importActual<typeof import('../../application/admin')>('../../application/admin');
  return {
    ...actual,
    loadCscaCertificates: (...args: unknown[]) => mockLoadCscaCertificates(...args),
    createCscaCertificate: (...args: unknown[]) => mockCreateCscaCertificate(...args),
  };
});

describe('CscaManager', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockLoadCscaCertificates.mockResolvedValue({
      certificates: [{ id: 'cert-1', subject: 'CN=Root', not_after: '2030-01-01', revoked: false }],
      error: null,
    });
    mockCreateCscaCertificate.mockResolvedValue({
      success: true,
      error: null,
    });
  });

  it('loads certificates through the application layer', async () => {
    render(<CscaManager />);

    expect(await screen.findByText('CN=Root')).toBeInTheDocument();
    expect(mockLoadCscaCertificates).toHaveBeenCalledTimes(1);
  });

  it('creates certificates through the application layer', async () => {
    const { user } = render(<CscaManager />);

    await screen.findByText('CN=Root');
    await user.click(screen.getByRole('button', { name: /create certificate/i }));
    await user.type(screen.getByLabelText('Subject Name (CN)'), 'CN=New Root');
    await user.click(screen.getByRole('button', { name: /^create$/i }));

    await waitFor(() => {
      expect(mockCreateCscaCertificate).toHaveBeenCalledWith({
        subjectName: 'CN=New Root',
      });
    });

    await waitFor(() => {
      expect(mockLoadCscaCertificates).toHaveBeenCalledTimes(2);
    });
  });
});
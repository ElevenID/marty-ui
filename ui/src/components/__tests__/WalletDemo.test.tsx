import { beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@test/utils';

import WalletDemo from '../WalletDemo';

const {
  mockLoadWalletDemoCredentials,
  mockCreateWalletDemoPresentation,
} = vi.hoisted(() => ({
  mockLoadWalletDemoCredentials: vi.fn(),
  mockCreateWalletDemoPresentation: vi.fn(),
}));

vi.mock('../../application/wallet', async () => {
  const actual = await vi.importActual<typeof import('../../application/wallet')>('../../application/wallet');
  return {
    ...actual,
    loadWalletDemoCredentials: (...args: unknown[]) => mockLoadWalletDemoCredentials(...args),
    createWalletDemoPresentation: (...args: unknown[]) => mockCreateWalletDemoPresentation(...args),
  };
});

describe('WalletDemo', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockLoadWalletDemoCredentials.mockResolvedValue({
      error: null,
      credentials: [{
        id: 'cred-1',
        type: 'mDL',
        issuer: 'DMV',
        issued_date: '2026-01-01',
        expiry_date: '2030-01-01',
        status: 'active',
        subject_data: {
          given_name: 'Jane',
          family_name: 'Doe',
          document_number: 'DL123',
        },
      }],
    });
    mockCreateWalletDemoPresentation.mockResolvedValue({
      success: true,
      error: null,
      message: 'Presentation created successfully!',
    });
  });

  it('loads credentials through the application layer', async () => {
    render(<WalletDemo />);

    expect(await screen.findByText('mDL')).toBeInTheDocument();
    expect(mockLoadWalletDemoCredentials).toHaveBeenCalledTimes(1);
  });

  it('creates a presentation through the application layer', async () => {
    const alertSpy = vi.spyOn(window, 'alert').mockImplementation(() => {});
    const { user } = render(<WalletDemo />);

    await screen.findByText('mDL');
    await user.click(screen.getByRole('button', { name: /share/i }));
    fireEvent.change(screen.getByLabelText('Presentation Request (JSON)'), {
      target: { value: '{"audience":"demo-aud"}' },
    });
    await user.click(screen.getByRole('button', { name: /create presentation/i }));

    await waitFor(() => {
      expect(mockCreateWalletDemoPresentation).toHaveBeenCalledWith({
        selectedCredential: expect.objectContaining({ id: 'cred-1' }),
        presentationRequest: '{"audience":"demo-aud"}',
      });
    });

    expect(alertSpy).toHaveBeenCalledWith('Presentation created successfully!');
    alertSpy.mockRestore();
  });
});
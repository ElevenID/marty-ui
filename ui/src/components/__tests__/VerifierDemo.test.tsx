import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen, waitFor } from '@test/utils';

import VerifierDemo from '../VerifierDemo';

const { mockVerifyVerifierDemoPresentation } = vi.hoisted(() => ({
  mockVerifyVerifierDemoPresentation: vi.fn(),
}));

vi.mock('../../application/verifier', async () => {
  const actual = await vi.importActual<typeof import('../../application/verifier')>('../../application/verifier');
  return {
    ...actual,
    verifyVerifierDemoPresentation: (...args: unknown[]) => mockVerifyVerifierDemoPresentation(...args),
  };
});

describe('VerifierDemo', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockVerifyVerifierDemoPresentation.mockResolvedValue({
      success: true,
      verified: true,
      claims: { given_name: 'Jane' },
      issuer: 'did:example:holder',
      checks: [
        { check_name: 'JWT Structure', passed: true, details: 'Valid JWT format' },
      ],
    });
  });

  it('verifies presentation data through the application layer', async () => {
    const { user } = render(<VerifierDemo />);

    await user.type(screen.getByLabelText('Paste Presentation Data'), 'jwt-token');
    await user.click(screen.getByRole('button', { name: /verify presentation/i }));

    await waitFor(() => {
      expect(mockVerifyVerifierDemoPresentation).toHaveBeenCalledWith({
        presentationData: 'jwt-token',
      });
    });

    expect(await screen.findByTestId('verification-success-alert')).toBeInTheDocument();
    expect(screen.getByTestId('verification-result-chip')).toHaveTextContent('VERIFIED');
  });
});
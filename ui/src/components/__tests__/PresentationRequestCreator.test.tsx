import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen, waitFor } from '@test/utils';

import PresentationRequestCreator from '../verifier/PresentationRequestCreator';

const { mockCreatePresentationRequest } = vi.hoisted(() => ({
  mockCreatePresentationRequest: vi.fn(),
}));

vi.mock('../../application/verifier', async () => {
  const actual = await vi.importActual<typeof import('../../application/verifier')>('../../application/verifier');
  return {
    ...actual,
    createPresentationRequest: (...args: unknown[]) => mockCreatePresentationRequest(...args),
  };
});

describe('PresentationRequestCreator', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockCreatePresentationRequest.mockResolvedValue({
      error: null,
      requestId: 'req-123',
      requestUri: 'openid-vc://request/123',
      requestAudience: 'demo-audience',
      requestStatus: 'pending',
    });
  });

  it('creates a presentation request through the application layer', async () => {
    const { user } = render(<PresentationRequestCreator />);

    await user.clear(screen.getByLabelText('Verifier Name'));
    await user.type(screen.getByLabelText('Verifier Name'), 'Verifier One');
    await user.click(screen.getByRole('button', { name: /create request/i }));

    await waitFor(() => {
      expect(mockCreatePresentationRequest).toHaveBeenCalledWith({
        selectedCredentialType: 'mDL',
        verifierName: 'Verifier One',
      });
    });

    expect(await screen.findByDisplayValue('openid-vc://request/123')).toBeInTheDocument();
    expect(screen.getByText(/request id: req-123/i)).toBeInTheDocument();
  });
});
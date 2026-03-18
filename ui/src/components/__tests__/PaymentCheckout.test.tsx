import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen, waitFor } from '@test/utils';

import PaymentCheckout from '../applicant/PaymentCheckout';

const {
  mockNavigate,
  mockInitializePayment,
  mockProcessPayment,
  mockPost,
} = vi.hoisted(() => ({
  mockNavigate: vi.fn(),
  mockInitializePayment: vi.fn(),
  mockProcessPayment: vi.fn(),
  mockPost: vi.fn(),
}));

vi.mock('react-router-dom', async () => {
  const actual = await vi.importActual<typeof import('react-router-dom')>('react-router-dom');
  return {
    ...actual,
    useNavigate: () => mockNavigate,
    useLocation: () => ({
      state: {
        credential: {
          id: 'cred-1',
          name: 'Digital Passport',
          description: 'Travel credential',
          vendorName: 'Acme Org',
          processingTime: '5 business days',
        },
        processingFee: 25,
      },
    }),
  };
});

vi.mock('../../hooks/useAuth', () => ({
  useAuth: () => ({
    user: {
      name: 'Ada Lovelace',
      email: 'ada@example.com',
    },
    organizationName: 'Acme Org',
  }),
}));

vi.mock('../../contexts/paymentHooks', () => ({
  usePayment: () => ({
    initializePayment: mockInitializePayment,
    processPayment: mockProcessPayment,
    isProcessing: false,
    error: null,
    isMockMode: true,
  }),
}));

vi.mock('../../services/api', () => ({
  post: mockPost,
}));

describe('PaymentCheckout', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockInitializePayment.mockResolvedValue({ success: true, error: null });
    mockProcessPayment.mockResolvedValue({ success: true, paymentId: 'pay-1' });
    mockPost.mockResolvedValue({ applicationId: 'app-1' });
  });

  it('processes a paid checkout using the payment context contract', async () => {
    const { user } = render(<PaymentCheckout />);

    await waitFor(() => {
      expect(mockInitializePayment).toHaveBeenCalledWith('card-container');
    });

    await user.click(screen.getByRole('checkbox'));
    await user.click(screen.getByRole('button', { name: 'Continue to Payment' }));

    await user.type(screen.getByLabelText('Address'), '1 Main St');
    await user.type(screen.getByLabelText('City'), 'London');
    await user.type(screen.getByLabelText('State'), 'LN');
    await user.type(screen.getByLabelText('ZIP'), '12345');

    await user.click(screen.getByRole('button', { name: 'Pay $25.00' }));

    await waitFor(() => {
      expect(mockProcessPayment).toHaveBeenCalledWith(25, 'USD', {
        billingContact: expect.objectContaining({
          name: 'Ada Lovelace',
          email: 'ada@example.com',
          address: '1 Main St',
          city: 'London',
          state: 'LN',
          zip: '12345',
          country: 'US',
        }),
        metadata: {
          credentialId: 'cred-1',
          credentialName: 'Digital Passport',
          applicantEmail: 'ada@example.com',
        },
      });

      expect(mockPost).toHaveBeenCalledWith('/api/applicant/applications', {
        credentialId: 'cred-1',
        credentialType: 'cred-1',
        paymentId: 'pay-1',
        processingFee: 25,
        billingInfo: expect.objectContaining({
          address: '1 Main St',
          city: 'London',
          state: 'LN',
          zip: '12345',
        }),
      });

      expect(screen.getByText('Application Submitted!')).toBeInTheDocument();
      expect(screen.getByText('app-1')).toBeInTheDocument();
      expect(screen.getByText('pay-1')).toBeInTheDocument();
    });
  });
});

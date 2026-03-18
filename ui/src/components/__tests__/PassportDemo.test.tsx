import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen, waitFor } from '@test/utils';

import PassportDemo from '../PassportDemo';

const {
  mockIssuePassport,
  mockInspectPassport,
} = vi.hoisted(() => ({
  mockIssuePassport: vi.fn(),
  mockInspectPassport: vi.fn(),
}));

vi.mock('../../application/admin', async () => {
  const actual = await vi.importActual<typeof import('../../application/admin')>('../../application/admin');
  return {
    ...actual,
    issuePassport: (...args: unknown[]) => mockIssuePassport(...args),
    inspectPassport: (...args: unknown[]) => mockInspectPassport(...args),
  };
});

describe('PassportDemo', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockIssuePassport.mockResolvedValue({
      error: null,
      result: { passport_number: 'P123', status: 'issued' },
    });
    mockInspectPassport.mockResolvedValue({
      error: null,
      inspectResult: {
        details: {
          passport_number: 'P123',
          holder: 'Avery Example',
          nationality: 'USA',
        },
      },
    });
  });

  it('issues a passport through the application layer', async () => {
    const { user } = render(<PassportDemo />);

    await user.type(screen.getAllByLabelText('Passport Number')[0], 'P123');
    await user.click(screen.getByRole('button', { name: /issue passport/i }));

    await waitFor(() => {
      expect(mockIssuePassport).toHaveBeenCalledWith({ passportNumber: 'P123' });
    });

    expect(await screen.findByText('Passport Issued Successfully')).toBeInTheDocument();
  });

  it('inspects a passport through the application layer', async () => {
    const { user } = render(<PassportDemo />);

    await user.type(screen.getByPlaceholderText('Enter passport number to inspect'), 'P123');
    await user.click(screen.getByRole('button', { name: /inspect passport/i }));

    await waitFor(() => {
      expect(mockInspectPassport).toHaveBeenCalledWith({ passportNumber: 'P123' });
    });

    expect(await screen.findByText('Valid Passport')).toBeInTheDocument();
    expect(screen.getByText('Avery Example')).toBeInTheDocument();
  });
});

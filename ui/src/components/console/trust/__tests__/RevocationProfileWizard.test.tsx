/**
 * Tests for RevocationProfileWizard
 *
 * Covers: rendering, form validation, mechanism toggle, submit success/error,
 * cancel navigation, breadcrumb rendering.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@test/utils';
import RevocationProfileWizard from '../RevocationProfileWizard';

// ---------------------------------------------------------------------------
// Module mocks
// ---------------------------------------------------------------------------

const mockCreateRevocationProfile = vi.fn();

vi.mock('../../../../services/presentationPolicyApi', () => ({
  createRevocationProfile: (...args: unknown[]) => mockCreateRevocationProfile(...args),
}));

vi.mock('../../../../hooks/useAuth', () => ({
  useAuth: () => ({ organizationId: 'org-1' }),
}));

const mockNavigate = vi.fn();

vi.mock('react-router-dom', async () => {
  const actual = await vi.importActual('react-router-dom');
  return {
    ...actual,
    useNavigate: () => mockNavigate,
  };
});

vi.mock('react-i18next', () => ({
  useTranslation: () => ({
    t: (key: string, opts?: string | Record<string, unknown>) => {
      if (typeof opts === 'string') return opts;
      return (opts?.defaultValue as string | undefined) ?? key;
    },
  }),
}));

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function renderWizard() {
  return render(<RevocationProfileWizard />);
}

function getNameInput() {
  return screen.getByTestId('revocationWizard.name');
}

function getCreateButton() {
  return screen.getByRole('button', { name: /create profile/i });
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('RevocationProfileWizard', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('renders the page heading', () => {
    renderWizard();
    expect(screen.getByRole('heading', { name: /new revocation profile/i })).toBeInTheDocument();
  });

  it('renders breadcrumbs including Revocation Profiles link', () => {
    renderWizard();
    expect(screen.getByRole('link', { name: /revocation profiles/i })).toBeInTheDocument();
  });

  it('Create button is disabled when name is empty', () => {
    renderWizard();
    const createBtn = getCreateButton();
    expect(createBtn).toBeDisabled();
  });

  it('Create button is enabled after entering a name', async () => {
    renderWizard();
    fireEvent.change(getNameInput(), { target: { value: 'My Profile' } });
    await waitFor(() => expect(getCreateButton()).not.toBeDisabled());
  });

  it('toggles a mechanism off then on again', async () => {
    renderWizard();
    // StatusList2021 is checked by default
    const sl2021 = screen.getByRole('checkbox', { name: /status list 2021/i });
    expect(sl2021).toBeChecked();

    // Uncheck it
    fireEvent.click(sl2021);
    await waitFor(() => expect(sl2021).not.toBeChecked());

    // Re-check it
    fireEvent.click(sl2021);
    await waitFor(() => expect(sl2021).toBeChecked());
  });

  it('checking an additional mechanism adds it to the selection', async () => {
    renderWizard();
    const ocsp = screen.getByRole('checkbox', { name: /^ocsp$/i });
    expect(ocsp).not.toBeChecked();
    fireEvent.click(ocsp);
    await waitFor(() => expect(ocsp).toBeChecked());
  });

  it('calls createRevocationProfile with correct payload on submit', async () => {
    mockCreateRevocationProfile.mockResolvedValue({ id: 'rev-42' });

    renderWizard();
    fireEvent.change(getNameInput(), { target: { value: 'StatusList Profile' } });
    fireEvent.click(getCreateButton());

    await waitFor(() => {
      expect(mockCreateRevocationProfile).toHaveBeenCalledWith(
        expect.objectContaining({
          name: 'StatusList Profile',
          check_mode: 'HARD_FAIL',
          revocation_mechanism: ['StatusList2021'],
          organization_id: 'org-1',
        })
      );
    });
  });

  it('navigates to new profile detail page on successful submit', async () => {
    mockCreateRevocationProfile.mockResolvedValue({ id: 'rev-new' });

    renderWizard();
    fireEvent.change(getNameInput(), { target: { value: 'New Profile' } });
    fireEvent.click(getCreateButton());

    await waitFor(() => {
      expect(mockNavigate).toHaveBeenCalledWith('/console/org/trust/revocation/rev-new');
    });
  });

  it('displays an error alert when createRevocationProfile rejects', async () => {
    mockCreateRevocationProfile.mockRejectedValue(new Error('Server error'));

    renderWizard();
    fireEvent.change(getNameInput(), { target: { value: 'Bad Profile' } });
    fireEvent.click(getCreateButton());

    await waitFor(() => {
      expect(screen.getByRole('alert')).toHaveTextContent('Server error');
    });
    expect(mockNavigate).not.toHaveBeenCalled();
  });

  it('Create button is re-enabled after a failed submit', async () => {
    mockCreateRevocationProfile.mockRejectedValue(new Error('Fail'));

    renderWizard();
    fireEvent.change(getNameInput(), { target: { value: 'Profile X' } });
    fireEvent.click(getCreateButton());

    await waitFor(() => expect(getCreateButton()).not.toBeDisabled());
  });

  it('navigates back to revocation profiles list on Cancel', () => {
    renderWizard();
    const cancelBtn = screen.getByRole('button', { name: /cancel/i });
    fireEvent.click(cancelBtn);
    expect(mockNavigate).toHaveBeenCalledWith('/console/org/trust/revocation');
  });

  it('strips optional numeric fields when left blank', async () => {
    mockCreateRevocationProfile.mockResolvedValue({ id: 'rev-1' });

    renderWizard();
    fireEvent.change(getNameInput(), { target: { value: 'Clean Profile' } });
    fireEvent.click(getCreateButton());

    await waitFor(() => {
      const payload = mockCreateRevocationProfile.mock.calls[0][0];
      expect(payload).not.toHaveProperty('grace_period_seconds');
      expect(payload).not.toHaveProperty('cache_ttl_seconds');
    });
  });

  it('includes numeric fields when populated', async () => {
    mockCreateRevocationProfile.mockResolvedValue({ id: 'rev-2' });

    renderWizard();
    fireEvent.change(getNameInput(), { target: { value: 'Timed Profile' } });
    fireEvent.change(screen.getByTestId('revocationWizard.gracePeriod'), { target: { value: '30' } });
    fireEvent.change(screen.getByTestId('revocationWizard.cacheTtl'), { target: { value: '3600' } });
    fireEvent.click(getCreateButton());

    await waitFor(() => {
      const payload = mockCreateRevocationProfile.mock.calls[0][0];
      expect(payload.grace_period_seconds).toBe(30);
      expect(payload.cache_ttl_seconds).toBe(3600);
    });
  });
});

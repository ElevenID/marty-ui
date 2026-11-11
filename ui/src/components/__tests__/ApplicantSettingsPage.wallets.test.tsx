import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen, waitFor } from '@test/utils';
import { AuthContext } from '../../contexts/AuthContext';
import ApplicantSettingsPage from '../console/applicant/ApplicantSettingsPage';

vi.mock('../../services/applicantApi', () => ({
  getMyApplicantProfile: vi.fn(async () => ({ id: 'applicant-profile', given_name: 'Account', family_name: 'Owner' })),
  upsertMyApplicantProfile: vi.fn(),
}));
vi.mock('../../services/walletRegistryApi', () => ({
  listWallets: vi.fn(async () => [{ id: 'wallet-one', name: 'Example Wallet', supported_platforms: ['web'] }]),
}));

function AccountSettings({ userId = 'account-one' }) {
  return <AuthContext.Provider value={{ user: { user_id: userId, name: 'Account Owner' } } as any}>
    <ApplicantSettingsPage />
  </AuthContext.Provider>;
}

describe('wallet settings with real account-scoped browser storage', () => {
  beforeEach(() => window.localStorage.clear());
  afterEach(() => vi.restoreAllMocks());

  it.each([false, true])('retains the persisted checkbox after a failed write and retries the intended choice (initially selected=%s)', async initiallySelected => {
    const key = 'elevenid_wallets_account-one';
    window.localStorage.setItem(key, JSON.stringify(initiallySelected ? ['wallet-one'] : []));
    const { user } = render(<AccountSettings />);
    const checkbox = await screen.findByRole('checkbox', { name: 'Example Wallet' });
    await waitFor(() => expect(screen.getByRole('button', { name: 'Save profile' })).toBeEnabled());
    expect((checkbox as HTMLInputElement).checked).toBe(initiallySelected);
    const storageWrite = vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => {
      throw new DOMException('Storage is full', 'QuotaExceededError');
    });

    checkbox.focus();
    await user.keyboard(' ');

    expect(await screen.findByText('Wallet choices could not be saved in this browser. Please try again.')).toBeVisible();
    expect((checkbox as HTMLInputElement).checked).toBe(initiallySelected);
    expect(JSON.parse(window.localStorage.getItem(key)!)).toEqual(initiallySelected ? ['wallet-one'] : []);
    expect(storageWrite).toHaveBeenCalledTimes(1);
    storageWrite.mockRestore();
    await user.click(screen.getByRole('button', { name: 'Retry' }));

    expect((checkbox as HTMLInputElement).checked).toBe(!initiallySelected);
    expect(JSON.parse(window.localStorage.getItem(key)!)).toEqual(initiallySelected ? [] : ['wallet-one']);
    expect(screen.queryByText('Wallet choices could not be saved in this browser. Please try again.')).not.toBeInTheDocument();
  });

  it('drops the previous account failed choice and error when the account changes', async () => {
    window.localStorage.setItem('elevenid_wallets_account-two', JSON.stringify(['wallet-one']));
    const { user, rerender } = render(<AccountSettings />);
    const checkbox = await screen.findByRole('checkbox', { name: 'Example Wallet' });
    const storageWrite = vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => {
      throw new DOMException('Storage is unavailable', 'SecurityError');
    });
    await user.click(checkbox);
    expect(await screen.findByText('Wallet choices could not be saved in this browser. Please try again.')).toBeVisible();
    storageWrite.mockRestore();

    rerender(<AccountSettings userId="account-two" />);

    expect(screen.getByRole('checkbox', { name: 'Example Wallet' })).toBeChecked();
    expect(screen.queryByText('Wallet choices could not be saved in this browser. Please try again.')).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Retry' })).not.toBeInTheDocument();
    expect(window.localStorage.getItem('elevenid_wallets_account-one')).toBeNull();
    expect(JSON.parse(window.localStorage.getItem('elevenid_wallets_account-two')!)).toEqual(['wallet-one']);
  });
});

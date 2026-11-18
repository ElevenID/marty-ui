import { act, renderHook } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import useWalletPreferences from '../useWalletPreferences';

describe('wallet preference storage ownership', () => {
  beforeEach(() => window.localStorage.clear());
  afterEach(() => vi.restoreAllMocks());

  it('keeps an unsuccessful retry recoverable without claiming the desired list was persisted', () => {
    window.localStorage.setItem('elevenid_wallets_owner', JSON.stringify(['existing']));
    const { result } = renderHook(() => useWalletPreferences('owner'));
    const write = vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => {
      throw new DOMException('Storage is full', 'QuotaExceededError');
    });
    act(() => expect(result.current.addWallet('new')).toBe(false));
    act(() => expect(result.current.retry()).toBe(false));
    expect(result.current.walletIds).toEqual(['existing']);
    expect(result.current.error).toBe('Wallet choices could not be saved in this browser. Please try again.');
    write.mockRestore();
    act(() => expect(result.current.retry()).toBe(true));
    expect(result.current.walletIds).toEqual(['existing', 'new']);
    expect(result.current.error).toBeNull();
    expect(JSON.parse(window.localStorage.getItem('elevenid_wallets_owner')!)).toEqual(['existing', 'new']);
  });

  it('invalidates old setters and retry intents across an account change, including a return to the same account', () => {
    window.localStorage.setItem('elevenid_wallets_second', JSON.stringify(['second-wallet']));
    const { result, rerender } = renderHook(({ id }) => useWalletPreferences(id), { initialProps: { id: 'first' } });
    const write = vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => {
      throw new DOMException('Storage is unavailable', 'SecurityError');
    });
    act(() => result.current.addWallet('unsaved'));
    const oldRetry = result.current.retry;
    const oldSetter = result.current.setWalletIds;
    write.mockRestore();

    rerender({ id: 'second' });
    expect(result.current.walletIds).toEqual(['second-wallet']);
    expect(result.current.error).toBeNull();
    act(() => {
      expect(oldRetry()).toBe(false);
      expect(oldSetter(['obsolete'])).toBe(false);
    });
    rerender({ id: 'first' });
    act(() => expect(oldRetry()).toBe(false));
    expect(result.current.walletIds).toEqual([]);
    expect(result.current.error).toBeNull();
    expect(window.localStorage.getItem('elevenid_wallets_first')).toBeNull();
    expect(JSON.parse(window.localStorage.getItem('elevenid_wallets_second')!)).toEqual(['second-wallet']);
  });

  it('makes a callback retained from an unmounted account inert', () => {
    const { result, unmount } = renderHook(() => useWalletPreferences('owner'));
    const add = result.current.addWallet;
    unmount();
    expect(add('obsolete')).toBe(false);
    expect(window.localStorage.getItem('elevenid_wallets_owner')).toBeNull();
  });
});

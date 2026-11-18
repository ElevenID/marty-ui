import { describe, expect, it } from 'vitest';

import {
  createWalletSelectionAllowlist,
  filterAllowedWalletIds,
  filterSelectableWallets,
  isWalletSelectable,
} from '../walletSelectionRestrictions';

describe('walletSelectionRestrictions', () => {
  it('does not restrict wallets when no allowlist is configured', () => {
    expect(createWalletSelectionAllowlist(null)).toBeNull();
    expect(isWalletSelectable('wr-lissi-001', null)).toBe(true);
    expect(filterAllowedWalletIds(['wr-lissi-001', 'wr-spruce-001'], null)).toEqual(['wr-lissi-001', 'wr-spruce-001']);
    expect(filterSelectableWallets([{ id: 'wr-lissi-001' }, { id: 'wr-spruce-001' }], null)).toEqual([
      { id: 'wr-lissi-001' },
      { id: 'wr-spruce-001' },
    ]);
  });

  it('limits self-host wallet preferences to the configured allowlist', () => {
    const allowlist = ['wr-spruce-001', 'wr-marty-001'];

    expect(isWalletSelectable('wr-spruce-001', allowlist)).toBe(true);
    expect(isWalletSelectable('wr-marty-001', allowlist)).toBe(true);
    expect(isWalletSelectable('wr-lissi-001', allowlist)).toBe(false);
    expect(isWalletSelectable('wr-google-001', allowlist)).toBe(false);

    expect(filterAllowedWalletIds(['wr-lissi-001', 'wr-spruce-001', 'wr-google-001', 'wr-marty-001'], allowlist)).toEqual([
      'wr-spruce-001',
      'wr-marty-001',
    ]);

    expect(filterSelectableWallets([
      { id: 'wr-lissi-001', name: 'LISSI Wallet' },
      { id: 'wr-spruce-001', name: 'SpruceKit' },
      { id: 'wr-marty-001', name: 'Marty Authenticator' },
    ], allowlist)).toEqual([
      { id: 'wr-spruce-001', name: 'SpruceKit' },
      { id: 'wr-marty-001', name: 'Marty Authenticator' },
    ]);
  });
});

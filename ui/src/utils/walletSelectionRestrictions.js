export function createWalletSelectionAllowlist(allowedWalletIds) {
  return Array.isArray(allowedWalletIds) ? new Set(allowedWalletIds.filter(Boolean)) : null;
}

export function isWalletSelectable(walletId, allowedWalletIds) {
  const allowlist = createWalletSelectionAllowlist(allowedWalletIds);
  return !allowlist || allowlist.has(walletId);
}

export function filterAllowedWalletIds(walletIds, allowedWalletIds) {
  const list = Array.isArray(walletIds) ? walletIds : [];
  const allowlist = createWalletSelectionAllowlist(allowedWalletIds);
  return allowlist ? list.filter((walletId) => allowlist.has(walletId)) : list;
}

export function filterSelectableWallets(wallets, allowedWalletIds) {
  const list = Array.isArray(wallets) ? wallets : [];
  const allowlist = createWalletSelectionAllowlist(allowedWalletIds);
  return allowlist ? list.filter((wallet) => allowlist.has(wallet?.id)) : list;
}

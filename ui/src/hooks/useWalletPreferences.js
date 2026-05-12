/**
 * useWalletPreferences
 *
 * Reads / writes the user's preferred wallet IDs to localStorage.
 * Each user can register which wallet apps they have installed so the
 * "Add to Wallet" dialog shows the right tabs.
 *
 * Storage key is scoped to the authenticated user ID so multiple users on
 * the same browser each keep their own list.
 */

import { useState, useCallback, useEffect } from 'react';

const STORAGE_KEY_PREFIX = 'elevenid_wallets_';

function storageKey(userId) {
  return `${STORAGE_KEY_PREFIX}${userId || 'anon'}`;
}

function readFromStorage(userId) {
  try {
    const raw = localStorage.getItem(storageKey(userId));
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

function writeToStorage(userId, ids) {
  localStorage.setItem(storageKey(userId), JSON.stringify(ids));
}

/**
 * @param {string} userId — authenticated user ID (from useAuth)
 * @returns {{ walletIds: string[], addWallet, removeWallet, setWalletIds }}
 */
export default function useWalletPreferences(userId) {
  const [walletIds, setWalletIdsState] = useState(() => readFromStorage(userId));

  useEffect(() => {
    setWalletIdsState(readFromStorage(userId));
  }, [userId]);

  const setWalletIds = useCallback(
    (ids) => {
      const list = Array.isArray(ids) ? ids : [];
      writeToStorage(userId, list);
      setWalletIdsState(list);
    },
    [userId],
  );

  const addWallet = useCallback(
    (id) => {
      setWalletIds([...new Set([...readFromStorage(userId), id])]);
    },
    [userId, setWalletIds],
  );

  const removeWallet = useCallback(
    (id) => {
      setWalletIds(readFromStorage(userId).filter((w) => w !== id));
    },
    [userId, setWalletIds],
  );

  return { walletIds, addWallet, removeWallet, setWalletIds };
}

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

import { useState, useCallback, useEffect, useLayoutEffect, useMemo, useRef } from 'react';

import { WALLET_SELECTION_ALLOWED_WALLET_IDS } from '@ui-public-config';
import { filterAllowedWalletIds } from '../utils/walletSelectionRestrictions';

const STORAGE_KEY_PREFIX = 'elevenid_wallets_';

function storageKey(userId) {
  return `${STORAGE_KEY_PREFIX}${userId || 'anon'}`;
}

function readFromStorage(userId) {
  try {
    const raw = localStorage.getItem(storageKey(userId));
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    return filterAllowedWalletIds(parsed, WALLET_SELECTION_ALLOWED_WALLET_IDS);
  } catch {
    return [];
  }
}

function writeToStorage(userId, ids) {
  localStorage.setItem(storageKey(userId), JSON.stringify(filterAllowedWalletIds(ids, WALLET_SELECTION_ALLOWED_WALLET_IDS)));
}

/**
 * @param {string} userId — authenticated user ID (from useAuth)
 * @returns {{ walletIds: string[], error: string|null, retry, addWallet, removeWallet, setWalletIds }}
 */
export default function useWalletPreferences(userId) {
  const scope = useMemo(() => ({ userId }), [userId]);
  const currentScope = useRef(scope);
  currentScope.current = scope;
  const active = useRef(false);
  const [state, setState] = useState(() => ({ scope, walletIds: readFromStorage(userId), pendingIds: null, error: null }));
  const currentState = state.scope === scope
    ? state
    : { scope, walletIds: readFromStorage(userId), pendingIds: null, error: null };
  const stateRef = useRef(currentState);
  stateRef.current = currentState;

  useLayoutEffect(() => {
    active.current = true;
    return () => { active.current = false; };
  }, []);

  useEffect(() => {
    setState(previous => previous.scope === scope
      ? previous
      : { scope, walletIds: readFromStorage(userId), pendingIds: null, error: null });
  }, [scope, userId]);

  const setWalletIds = useCallback(
    (ids) => {
      if (!active.current || currentScope.current !== scope) return false;
      const list = [...filterAllowedWalletIds(ids, WALLET_SELECTION_ALLOWED_WALLET_IDS)];
      let nextState;
      try {
        writeToStorage(userId, list);
        nextState = { scope, walletIds: list, pendingIds: null, error: null };
      } catch {
        nextState = {
          ...stateRef.current,
          pendingIds: list,
          error: 'Wallet choices could not be saved in this browser. Please try again.',
        };
      }
      stateRef.current = nextState;
      setState(nextState);
      return !nextState.error;
    },
    [scope, userId],
  );

  const addWallet = useCallback(
    (id) => setWalletIds([...new Set([...readFromStorage(userId), id])]),
    [userId, setWalletIds],
  );

  const removeWallet = useCallback(
    (id) => setWalletIds(readFromStorage(userId).filter((w) => w !== id)),
    [userId, setWalletIds],
  );

  const retry = useCallback(() => {
    if (stateRef.current.scope !== scope || !stateRef.current.pendingIds) return false;
    return setWalletIds(stateRef.current.pendingIds);
  }, [scope, setWalletIds]);

  return { walletIds: currentState.walletIds, error: currentState.error, retry, addWallet, removeWallet, setWalletIds };
}

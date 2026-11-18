import { useCallback, useLayoutEffect, useRef, useState } from 'react';
import { buildWalletOpenLink } from '../services/walletRegistryApi';

const PROTOCOL_ONLY_OPEN_LINK = /^(openid-credential-offer|openid4vp|haip-vci|haip-vp):/i;

export function chooseWalletOpenUri(walletOpenUri, fallbackOpenLink) {
  if (!walletOpenUri) return fallbackOpenLink;
  if (fallbackOpenLink && fallbackOpenLink !== walletOpenUri
      && PROTOCOL_ONLY_OPEN_LINK.test(walletOpenUri)
      && !PROTOCOL_ONLY_OPEN_LINK.test(fallbackOpenLink)) {
    return fallbackOpenLink;
  }
  return walletOpenUri;
}

/**
 * Open the selected wallet only while the originating view and offer are active.
 * The caller supplies already-resolved URIs; this hook does not invent routing.
 */
export default function useWalletOpenLink({
  active = true,
  requestScopeKey = null,
  walletId = '',
  innerUri = '',
  platform,
  fallbackOpenLink = '',
} = {}) {
  const current = useRef(null);
  const [openingWallet, setOpeningWallet] = useState(false);

  useLayoutEffect(() => {
    const context = { active, pending: false, walletId, innerUri, platform, fallbackOpenLink };
    current.current = context;
    setOpeningWallet(false);
    return () => { context.active = false; };
  }, [active, requestScopeKey, walletId, innerUri, platform, fallbackOpenLink]);

  const openWallet = useCallback(async (fallbackOverride) => {
    const context = current.current;
    if (!context?.active || context.pending) return;
    // QRCodeDisplay supplies a string; a React click event is deliberately ignored.
    const fallback = typeof fallbackOverride === 'string' && fallbackOverride
      ? fallbackOverride : context.fallbackOpenLink;
    if (!fallback) return;
    const isCurrent = () => context.active && current.current === context;
    if (!context.walletId || !context.innerUri) {
      if (isCurrent()) window.location.href = fallback;
      return;
    }

    // Set synchronously, before React renders disabled state, to coalesce two
    // clicks delivered in the same event turn into one registry request.
    context.pending = true;
    setOpeningWallet(true);
    try {
      const response = await buildWalletOpenLink(context.walletId, {
        innerUri: context.innerUri,
        platform: context.platform,
      });
      if (isCurrent()) window.location.href = chooseWalletOpenUri(response?.open_uri, fallback);
    } catch {
      if (isCurrent()) window.location.href = fallback;
    } finally {
      context.pending = false;
      if (isCurrent()) setOpeningWallet(false);
    }
  }, []);

  return { openingWallet, openWallet };
}

/**
 * Device Detection Utilities
 *
 * Lightweight helpers for determining the user's platform/device type so
 * that the issuance UX can adapt (QR-first for desktop, deep-link-first for mobile).
 */

/**
 * Returns true if the current device is a mobile phone or tablet.
 */
export function isMobile() {
  if (typeof navigator === 'undefined') return false;
  return /Android|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini|Mobile|mobile|CriOS/i.test(
    navigator.userAgent
  );
}

/**
 * Returns the effective platform: 'ios' | 'android' | 'desktop'.
 */
export function getPlatform() {
  if (typeof navigator === 'undefined') return 'desktop';
  const ua = navigator.userAgent;
  if (/iPad|iPhone|iPod/.test(ua)) return 'ios';
  if (/Android/.test(ua)) return 'android';
  return 'desktop';
}

/**
 * Filter a list of wallet registry entries to those compatible with the
 * current device's platform.
 *
 * @param {Array<{platforms: string[]}>} wallets
 * @returns {Array}
 */
export function filterWalletsForDevice(wallets) {
  const platform = getPlatform();
  if (platform === 'desktop') {
    // On desktop show all wallets that support web or have no platform restriction
    return wallets.filter(
      (w) => !w.platforms?.length || w.platforms.includes('web') || w.platforms.includes('desktop')
    );
  }
  return wallets.filter(
    (w) => !w.platforms?.length || w.platforms.includes(platform)
  );
}

/**
 * Attempt to open a deep link and detect failure via visibility change.
 *
 * @param {string} url - The deep link URL to open.
 * @param {number} [timeoutMs=2000] - How long to wait before assuming failure.
 * @returns {Promise<boolean>} Resolves true if the app was likely opened,
 *                             false if it fell back (app not installed).
 */
export function openDeepLink(url, timeoutMs = 2000) {
  return new Promise((resolve) => {
    let resolved = false;

    const onVisibilityChange = () => {
      if (document.hidden) {
        // Page went hidden → app opened
        resolved = true;
        clearTimeout(timer);
        document.removeEventListener('visibilitychange', onVisibilityChange);
        resolve(true);
      }
    };

    const timer = setTimeout(() => {
      if (!resolved) {
        document.removeEventListener('visibilitychange', onVisibilityChange);
        resolve(false);
      }
    }, timeoutMs);

    document.addEventListener('visibilitychange', onVisibilityChange);
    window.location.href = url;
  });
}

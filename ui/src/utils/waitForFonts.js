const DEFAULT_FONT_WAIT_MS = 2000;

export function waitForFonts(timeoutMs = DEFAULT_FONT_WAIT_MS) {
  const fontsReady = document.fonts?.ready;

  if (!fontsReady || typeof fontsReady.then !== 'function') {
    return Promise.resolve();
  }

  return new Promise((resolve) => {
    const timeoutId = setTimeout(resolve, timeoutMs);

    Promise.resolve(fontsReady)
      .catch(() => {})
      .then(() => {
        clearTimeout(timeoutId);
        resolve();
      });
  });
}

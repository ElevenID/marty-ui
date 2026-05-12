import { useEffect } from 'react';
import { useLocation } from 'react-router-dom';

function PrerenderReadySignal() {
  const location = useLocation();

  useEffect(() => {
    let cancelled = false;
    const fontsReady =
      document.fonts && typeof document.fonts.ready?.then === 'function'
        ? document.fonts.ready.catch(() => {})
        : Promise.resolve();

    Promise.resolve(fontsReady).then(() => {
      requestAnimationFrame(() => {
        requestAnimationFrame(() => {
          if (!cancelled) {
            document.dispatchEvent(new Event('app-rendered'));
          }
        });
      });
    });

    return () => {
      cancelled = true;
    };
  }, [location.pathname, location.search]);

  return null;
}

export default PrerenderReadySignal;
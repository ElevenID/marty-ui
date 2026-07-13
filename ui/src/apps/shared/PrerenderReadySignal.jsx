import { useEffect } from 'react';
import { useLocation } from 'react-router-dom';
import { waitForFonts } from '../../utils/waitForFonts';

function PrerenderReadySignal() {
  const location = useLocation();

  useEffect(() => {
    let cancelled = false;

    const waitForRouteContent = () => {
      if (!location.pathname.startsWith('/demos')) return Promise.resolve();
      if (document.querySelector('[data-demo-render-state="settled"]')) return Promise.resolve();

      return new Promise((resolve) => {
        const timeout = window.setTimeout(resolve, 15000);
        const observer = new MutationObserver(() => {
          if (document.querySelector('[data-demo-render-state="settled"]')) {
            window.clearTimeout(timeout);
            observer.disconnect();
            resolve();
          }
        });
        observer.observe(document.body, { childList: true, subtree: true, attributes: true });
      });
    };

    Promise.all([waitForFonts(), waitForRouteContent()]).then(() => {
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

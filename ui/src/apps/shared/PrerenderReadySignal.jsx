import { useEffect } from 'react';
import { useLocation } from 'react-router-dom';
import { waitForFonts } from '../../utils/waitForFonts';
import i18n from '../../i18n';

function waitForTranslations(timeoutMs = 10000) {
  const namespaces = Array.isArray(i18n.options.ns) ? i18n.options.ns : [];
  const translationsReady = i18n.loadNamespaces(namespaces).catch(() => {});

  return Promise.race([
    translationsReady,
    new Promise((resolve) => window.setTimeout(resolve, timeoutMs)),
  ]);
}

function PrerenderReadySignal() {
  const location = useLocation();

  useEffect(() => {
    let cancelled = false;

    const waitForAppContent = () => {
      if (!document.querySelector('[data-app-loading]')) return Promise.resolve();

      return new Promise((resolve) => {
        const observer = new MutationObserver(() => {
          if (!document.querySelector('[data-app-loading]')) {
            observer.disconnect();
            resolve();
          }
        });
        observer.observe(document.body, { childList: true, subtree: true });
      });
    };

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

    Promise.all([waitForFonts(), waitForTranslations(), waitForAppContent(), waitForRouteContent()]).then(() => {
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

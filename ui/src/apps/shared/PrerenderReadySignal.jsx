import { useEffect } from 'react';
import { useLocation } from 'react-router-dom';
import { waitForFonts } from '../../utils/waitForFonts';

function PrerenderReadySignal() {
  const location = useLocation();

  useEffect(() => {
    let cancelled = false;

    waitForFonts().then(() => {
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

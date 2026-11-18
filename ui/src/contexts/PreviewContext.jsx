/**
 * Preview Context
 * 
 * Provides preview mode state and functionality throughout the applicant-facing
 * components when viewed by admins/vendors for testing and validation.
 */

import { createContext, useContext, useState, useCallback, useLayoutEffect, useRef } from 'react';
import { useLocation, useNavigate } from 'react-router';
import PropTypes from 'prop-types';
import { redirectBrowser, shouldBrowserRedirect } from '../application/routing/appHandoff';

const PreviewContext = createContext(null);

export const usePreview = () => {
  const context = useContext(PreviewContext);
  // Return safe default if not in preview context
  if (!context) {
    return { isPreview: false };
  }
  return context;
};

export function PreviewProvider({ 
  children, 
  resourceType = null, 
  resourceId = null, 
  returnUrl = '/console' 
}) {
  const navigate = useNavigate();
  const location = useLocation();
  const [contextLabel, setContextLabel] = useState(null);
  const exitTimer = useRef(null);
  const exitGeneration = useRef(0);

  const cancelExit = useCallback(() => {
    exitGeneration.current += 1;
    if (exitTimer.current !== null) window.clearTimeout(exitTimer.current);
    exitTimer.current = null;
  }, []);

  useLayoutEffect(() => cancelExit, [cancelExit, location.key, location.pathname, location.search, returnUrl]);

  const exitPreview = useCallback(() => {
    cancelExit();
    const generation = exitGeneration.current;
    try {
      window.close();
    } catch {
      // Browsers may refuse to close a tab that the user opened directly.
    }
    if (window.closed) return;

    exitTimer.current = window.setTimeout(() => {
      if (exitGeneration.current !== generation) return;
      exitTimer.current = null;
      if (window.closed || !returnUrl) return;
      if (shouldBrowserRedirect({ currentPathname: location.pathname, destination: returnUrl })) {
        redirectBrowser(returnUrl, { replace: false });
        return;
      }

      navigate(returnUrl);
    }, 100);
  }, [cancelExit, location.pathname, navigate, returnUrl]);

  const updateContextLabel = useCallback((label) => {
    setContextLabel(label);
  }, []);

  const value = {
    isPreview: true,
    previewResourceType: resourceType,
    previewResourceId: resourceId,
    returnUrl,
    contextLabel,
    updateContextLabel,
    exitPreview,
  };

  return (
    <PreviewContext.Provider value={value}>
      {children}
    </PreviewContext.Provider>
  );
}

PreviewProvider.propTypes = {
  children: PropTypes.node.isRequired,
  resourceType: PropTypes.oneOf(['catalog', 'credential', 'application', 'flow', 'policy']),
  resourceId: PropTypes.string,
  returnUrl: PropTypes.string,
};

export default PreviewContext;

/**
 * Preview Context
 * 
 * Provides preview mode state and functionality throughout the applicant-facing
 * components when viewed by admins/vendors for testing and validation.
 */

import { createContext, useContext, useState, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import PropTypes from 'prop-types';

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
  const [contextLabel, setContextLabel] = useState(null);

  const exitPreview = useCallback(() => {
    // Try to close the window (works if opened via window.open)
    const closed = window.close();
    
    // If window.close() didn't work (e.g., not opened by script),
    // navigate back to the return URL
    setTimeout(() => {
      if (!closed && returnUrl) {
        navigate(returnUrl);
      }
    }, 100);
  }, [navigate, returnUrl]);

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

import React, { createContext, useState, useEffect } from 'react';

// Default branding configuration (fallback if config.json fails to load)
const defaultBranding = {
  appName: 'ElevenID',
  shortName: 'ElevenID',
  authenticatorName: 'ElevenID Authenticator',
  tagline: 'Secure Digital Identity Platform',
  issuingAuthority: 'ElevenID Trust Services',
  deepLinkProtocol: 'elevenid',
  logoUrl: null,
  appStoreUrl: '#',
  playStoreUrl: '#',
  primaryColor: '#1976d2',
  secondaryColor: '#dc004e',
  supportEmail: 'support@elevenid.demo',
};

export const BrandingContext = createContext({
  branding: defaultBranding,
  isLoading: true,
});

/**
 * BrandingProvider - Loads runtime branding configuration from /config.json
 * 
 * This allows per-deployment customization without rebuilding the app.
 * Organizations can mount their own config.json with custom branding.
 * 
 * TODO: Future feature - Org Profile Page for branding customization
 * - Allow orgs to configure: appName, logoUrl, primaryColor, secondaryColor, tagline
 * - Store org theme settings in database (org_settings table)
 * - Fetch org-specific branding based on authenticated user's organization
 * - API endpoint: GET /api/org/{org_id}/branding
 * - Consider caching strategy for branding config
 * - Add UI in vendor settings for org admins to customize branding
 * - Support logo file upload and storage
 */
export function BrandingProvider({ children }) {
  const [branding, setBranding] = useState(defaultBranding);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    // Fetch runtime branding configuration
    fetch('/config.json')
      .then(response => {
        if (!response.ok) {
          throw new Error('Config not found, using defaults');
        }
        return response.json();
      })
      .then(config => {
        // Merge with defaults to ensure all fields exist
        setBranding({ ...defaultBranding, ...config });
      })
      .catch(error => {
        console.warn('Failed to load branding config, using defaults:', error.message);
        setBranding(defaultBranding);
      })
      .finally(() => {
        setIsLoading(false);
      });
  }, []);

  // Update document title when branding loads
  useEffect(() => {
    if (!isLoading && branding.appName) {
      document.title = branding.appName;
    }
  }, [branding.appName, isLoading]);

  return (
    <BrandingContext.Provider value={{ branding, isLoading }}>
      {children}
    </BrandingContext.Provider>
  );
}

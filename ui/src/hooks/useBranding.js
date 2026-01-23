import { useContext } from 'react';
import { BrandingContext } from '../contexts/BrandingContext';

/**
 * Hook to access branding configuration
 * 
 * @returns {Object} branding - Current branding configuration
 * @returns {boolean} isLoading - Whether branding config is still loading
 * 
 * @example
 * const { branding, isLoading } = useBranding();
 * return <h1>{branding.appName}</h1>;
 */
export function useBranding() {
  const context = useContext(BrandingContext);
  
  if (context === undefined) {
    throw new Error('useBranding must be used within a BrandingProvider');
  }
  
  return context;
}

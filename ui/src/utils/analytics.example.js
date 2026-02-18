/**
 * Analytics Integration Example
 * 
 * Add this to App.jsx to enable analytics and performance monitoring
 */

// 1. Add imports at the top of App.jsx:
import { useEffect } from 'react';
import { useLocation } from 'react-router-dom';
import { initAnalytics, trackPageView, trackWebVitals } from './utils/analytics';

// 2. Inside AppContent function, add these hooks:

function AppContent() {
  const location = useLocation();
  const auth = useContext(AuthContext) || {};
  // ... other hooks

  // Initialize analytics once on mount
  useEffect(() => {
    initAnalytics();
    trackWebVitals();
  }, []);

  // Track page views on route changes
  useEffect(() => {
    trackPageView(location.pathname, document.title);
  }, [location]);

  // ... rest of component
}

// 3. Track custom events in components:

// Example: Track CTA clicks in LandingPage.jsx
import { trackEvent, trackConversion } from '../utils/analytics';

const handleGetStarted = () => {
  trackEvent('cta_clicked', { 
    button_name: 'get_started',
    page: 'landing',
  });
  navigate('/pricing');
};

// Example: Track signup in OnboardingPage.jsx
const handleSignup = async () => {
  const result = await signupUser();
  if (result.success) {
    trackConversion('signup', { 
      plan: selectedPlan,
      method: 'email',
    });
  }
};

// Example: Track API key creation in console
const handleCreateApiKey = async () => {
  const key = await createApiKey();
  trackConversion('api_key_created', {
    environment: activeEnvironment,
  });
};

// 4. Add to .env.production:
// VITE_GA_MEASUREMENT_ID=G-XXXXXXXXXX

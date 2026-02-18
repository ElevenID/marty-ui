/**
 * Analytics & Monitoring Utilities
 * 
 * Handles Google Analytics, performance monitoring, and Core Web Vitals tracking
 */

/**
 * Initialize Google Analytics
 * Call this once in App.jsx after router is ready
 */
export const initAnalytics = () => {
  const GA_ID = import.meta.env.VITE_GA_MEASUREMENT_ID;
  
  if (!GA_ID || typeof window === 'undefined') {
    console.log('Analytics: GA_MEASUREMENT_ID not configured or SSR mode');
    return;
  }

  // Load gtag.js script
  const script = document.createElement('script');
  script.async = true;
  script.src = `https://www.googletagmanager.com/gtag/js?id=${GA_ID}`;
  document.head.appendChild(script);

  // Initialize dataLayer
  window.dataLayer = window.dataLayer || [];
  function gtag() {
    window.dataLayer.push(arguments);
  }
  window.gtag = gtag;

  gtag('js', new Date());
  gtag('config', GA_ID, {
    send_page_view: false, // Handled by router
  });

  console.log('Analytics: Google Analytics initialized');
};

/**
 * Track page view
 * Call this on route changes
 * 
 * @param {string} path - Page path (e.g., '/pricing')
 * @param {string} title - Page title
 */
export const trackPageView = (path, title) => {
  if (typeof window === 'undefined' || !window.gtag) return;

  window.gtag('event', 'page_view', {
    page_path: path,
    page_title: title,
  });
};

/**
 * Track custom event
 * 
 * @param {string} eventName - Event name (e.g., 'signup_started')
 * @param {object} params - Event parameters
 */
export const trackEvent = (eventName, params = {}) => {
  if (typeof window === 'undefined' || !window.gtag) return;

  window.gtag('event', eventName, params);
};

/**
 * Track Core Web Vitals
 * Automatically reports CLS, FID, LCP to Google Analytics
 */
export const trackWebVitals = () => {
  if (typeof window === 'undefined') return;

  // Use web-vitals library if available
  import('web-vitals').then(({ onCLS, onFID, onLCP, onFCP, onTTFB, onINP }) => {
    const sendToGA = (metric) => {
      if (!window.gtag) return;

      window.gtag('event', metric.name, {
        event_category: 'Web Vitals',
        event_label: metric.id,
        value: Math.round(metric.name === 'CLS' ? metric.value * 1000 : metric.value),
        non_interaction: true,
      });

      console.log(`Web Vital: ${metric.name}`, metric.value);
    };

    onCLS(sendToGA);
    onFID(sendToGA);
    onLCP(sendToGA);
    onFCP(sendToGA);
    onTTFB(sendToGA);
    onINP(sendToGA);
  }).catch(() => {
    console.log('web-vitals library not available');
  });
};

/**
 * Track user engagement
 * Useful for measuring time on page, scroll depth
 */
export const trackEngagement = () => {
  if (typeof window === 'undefined') return;

  let startTime = Date.now();
  let maxScroll = 0;

  // Track scroll depth
  const handleScroll = () => {
    const scrollPercentage = Math.round(
      (window.scrollY / (document.documentElement.scrollHeight - window.innerHeight)) * 100
    );
    
    if (scrollPercentage > maxScroll) {
      maxScroll = scrollPercentage;
      
      // Report at 25%, 50%, 75%, 100%
      if ([25, 50, 75, 100].includes(scrollPercentage)) {
        trackEvent('scroll_depth', { 
          scroll_percentage: scrollPercentage,
        });
      }
    }
  };

  // Track time on page
  const handleUnload = () => {
    const timeOnPage = Math.round((Date.now() - startTime) / 1000);
    trackEvent('time_on_page', {
      duration_seconds: timeOnPage,
      max_scroll_percentage: maxScroll,
    });
  };

  window.addEventListener('scroll', handleScroll, { passive: true });
  window.addEventListener('beforeunload', handleUnload);

  return () => {
    window.removeEventListener('scroll', handleScroll);
    window.removeEventListener('beforeunload', handleUnload);
  };
};

/**
 * Track conversion events
 */
export const trackConversion = (type, metadata = {}) => {
  trackEvent('conversion', {
    conversion_type: type,
    ...metadata,
  });
};

/**
 * Example conversion events:
 * trackConversion('signup', { plan: 'FREE' })
 * trackConversion('upgrade', { from_plan: 'FREE', to_plan: 'STARTER' })
 * trackConversion('api_key_created')
 * trackConversion('credential_issued')
 */

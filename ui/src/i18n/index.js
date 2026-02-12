import i18n from 'i18next';
import { initReactI18next } from 'react-i18next';
import LanguageDetector from 'i18next-browser-languagedetector';
import HttpBackend from 'i18next-http-backend';

i18n
  // Load translation files
  .use(HttpBackend)
  // Detect user language
  .use(LanguageDetector)
  // Pass i18n instance to react-i18next
  .use(initReactI18next)
  // Initialize i18next
  .init({
    // Fallback language
    fallbackLng: 'en',
    
    // Supported languages
    supportedLngs: ['en', 'de', 'ja', 'es', 'fr', 'nl'],
    
    // Debug mode (disable in production)
    debug: import.meta.env.DEV,
    
    // Namespaces
    ns: ['common', 'console', 'onboarding', 'forms', 'errors', 'applicant', 'vendor', 'marketing'],
    defaultNS: 'common',
    
    // Detection options
    detection: {
      // Order of detection methods
      order: ['querystring', 'cookie', 'localStorage', 'navigator', 'htmlTag'],
      
      // Keys to look for
      lookupQuerystring: 'lng',
      lookupCookie: 'i18nextLng',
      lookupLocalStorage: 'i18nextLng',
      
      // Cache user language
      caches: ['localStorage', 'cookie'],
      
      // Only detect languages in supportedLngs
      checkWhitelist: true,
    },
    
    // Backend options
    backend: {
      // Path to load translation files
      loadPath: '/locales/{{lng}}/{{ns}}.json',
      
      // Allow cross-domain requests
      crossDomain: false,
    },
    
    // Interpolation options
    interpolation: {
      // React already escapes values
      escapeValue: false,
      
      // Format values
      format: (value, format, lng) => {
        if (format === 'uppercase') return value.toUpperCase();
        if (format === 'lowercase') return value.toLowerCase();
        if (value instanceof Date) {
          return new Intl.DateTimeFormat(lng).format(value);
        }
        return value;
      },
    },
    
    // React-specific options
    react: {
      // Wait for translations to load before rendering
      useSuspense: true,
    },
  });

export default i18n;

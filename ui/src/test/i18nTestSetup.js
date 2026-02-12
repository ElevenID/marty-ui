import i18n from 'i18next';
import { initReactI18next } from 'react-i18next';

// Import English translations for tests
import commonEn from '../../public/locales/en/common.json';
import consoleEn from '../../public/locales/en/console.json';
import onboardingEn from '../../public/locales/en/onboarding.json';
import formsEn from '../../public/locales/en/forms.json';
import errorsEn from '../../public/locales/en/errors.json';

i18n
  .use(initReactI18next)
  .init({
    lng: 'en',
    fallbackLng: 'en',
    debug: false,
    
    // Namespaces for testing
    ns: ['common', 'console', 'onboarding', 'forms', 'errors'],
    defaultNS: 'common',
    
    resources: {
      en: {
        common: commonEn,
        console: consoleEn,
        onboarding: onboardingEn,
        forms: formsEn,
        errors: errorsEn,
      },
    },
    
    interpolation: {
      escapeValue: false,
    },
    
    react: {
      useSuspense: false, // Disable Suspense in tests
    },
  });

export default i18n;

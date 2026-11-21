import i18n from 'i18next';
import { initReactI18next } from 'react-i18next';

import commonEn from '../../public/locales/en/common.json';
import consoleEn from '../../public/locales/en/console.json';
import onboardingEn from '../../public/locales/en/onboarding.json';
import formsEn from '../../public/locales/en/forms.json';
import errorsEn from '../../public/locales/en/errors.json';
import vendorEn from '../../public/locales/en/vendor.json';
import applicantEn from '../../public/locales/en/applicant.json';

i18n
  .use(initReactI18next)
  .init({
    lng: 'en',
    fallbackLng: 'en',
    debug: false,
    ns: ['common', 'console', 'onboarding', 'forms', 'errors', 'vendor', 'applicant'],
    defaultNS: 'common',
    resources: {
      en: {
        common: commonEn,
        console: consoleEn,
        onboarding: onboardingEn,
        forms: formsEn,
        errors: errorsEn,
        vendor: vendorEn,
        applicant: applicantEn,
      },
    },
    interpolation: {
      escapeValue: false,
    },
    react: {
      useSuspense: false,
    },
  });

export default i18n;

# Localization Guide

This document describes the internationalization (i18n) implementation for marty-ui and the Keycloak authentication theme.

## Overview

Marty-UI supports multiple languages across both the React application and Keycloak authentication pages:
- **English (en)** - Default/fallback language
- **German (de)** - Deutsch
- **Japanese (ja)** - 日本語
- **Spanish (es)** - Español
- **French (fr)** - Français

### Architecture

- **React App**: Uses `react-i18next` for client-side translations
- **Keycloak Theme**: Uses Java properties files (`.properties`) for server-rendered auth pages
- **Language Sync**: Locale preference is synchronized between both systems via URL parameters and localStorage

## React Application (marty-ui)

### Tech Stack
- **Library**: react-i18next v14.x
- **Core**: i18next v23.x
- **Backend**: i18next-http-backend (lazy-loads translations)
- **Detection**: i18next-browser-languagedetector
- **Storage**: localStorage, cookies, browser preferences

### File Structure

```
ui/
├── src/
│   └── i18n/
│       └── index.js              # i18n configuration
└── public/
    └── locales/
        ├── en/                    # English (source language)
        │   ├── common.json        # Shared UI strings
        │   ├── console.json       # Admin console
        │   ├── onboarding.json    # Onboarding flows
        │   ├── forms.json         # Form labels and validation
        │   └── errors.json        # Error messages
        ├── de/                    # German translations
        ├── ja/                    # Japanese translations
        ├── es/                    # Spanish translations
        └── fr/                    # French translations
```

### Usage in Components

#### Basic Usage

```jsx
import { useTranslation } from 'react-i18next';

function MyComponent() {
  const { t } = useTranslation('common'); // Load 'common' namespace
  
  return (
    <div>
      <h1>{t('welcome')}</h1>
      <button>{t('actions.save')}</button>
    </div>
  );
}
```

#### Multiple Namespaces

```jsx
function MyComponent() {
  const { t } = useTranslation(['common', 'forms']);
  
  return (
    <div>
      <h1>{t('common:welcome')}</h1>
      <label>{t('forms:labels.email')}</label>
    </div>
  );
}
```

#### Interpolation

```jsx
// Translation file: { "welcome": "Welcome, {{name}}!" }
const { t } = useTranslation('common');

<h1>{t('welcome', { name: user.name })}</h1>
```

#### Interpolation with Branding

```jsx
// Translation file: { "message": "Welcome to {{appName}}" }
const { t } = useTranslation('common');
const { branding } = useBranding();

<p>{t('message', { appName: branding.appName })}</p>
```

#### Pluralization

```jsx
// Translation file:
// {
//   "items_one": "{{count}} item",
//   "items_other": "{{count}} items"
// }

<span>{t('items', { count: items.length })}</span>
```

### Translation Files Format

JSON files with nested keys:

```json
{
  "actions": {
    "save": "Save",
    "cancel": "Cancel"
  },
  "validation": {
    "required": "This field is required",
    "minLength": "Must be at least {{count}} characters"
  }
}
```

### Adding New Translations

1. **Add to English file** (`ui/public/locales/en/[namespace].json`)
   ```json
   {
     "myNewKey": "My new text"
   }
   ```

2. **Use in component**
   ```jsx
   const { t } = useTranslation('namespace');
   <div>{t('myNewKey')}</div>
   ```

3. **Add to other languages** - For now, other language files can remain empty ({}). The system will fall back to English until translations are provided.

### Language Switcher

The `<LanguageSwitcher />` component is available in the app header:

```jsx
import { LanguageSwitcher } from './components/common';

<LanguageSwitcher variant="standard" sx={{ mr: 2 }} />
```

It automatically:
- Detects and displays the current language
- Saves preference to localStorage
- Passes locale to Keycloak on login/register

## Keycloak Authentication Theme

### File Structure

```
config/keycloak/themes/11id/login/
├── theme.properties                # Theme configuration
├── login.ftl                       # Login page template
├── register.ftl                    # Registration page template
├── error.ftl                       # Error page template
├── messages/                       # Translation files
│   ├── messages_en.properties      # English
│   ├── messages_de.properties      # German
│   ├── messages_ja.properties      # Japanese
│   ├── messages_es.properties      # Spanish
│   └── messages_fr.properties      # French
└── resources/
    └── css/
        └── marty.css              # Custom styling (includes language switcher)
```

### Properties File Format

Standard Java properties format with `key=value` pairs:

```properties
# Login page messages
loginAccountTitle=Sign in to your account
doLogIn=Sign in
username=Username
password=Password

# With variables (${}  syntax for Keycloak)
invalidUserMessage=Invalid username or email

# Language names (for dropdown)
locale_en=English
locale_de=Deutsch
locale_ja=日本語
```

### Adding New Keycloak Translations

1. **Add to English** (`messages_en.properties`)
   ```properties
   myNewKey=My new text
   ```

2. **Use in FTL template**
   ```ftl
   ${msg("myNewKey")}
   ```

3. **Add to other languages** - Add the same key to `messages_de.properties`, `messages_ja.properties`, etc.

### Language Switcher in Keycloak

The login and registration pages include a dropdown in the header:

```ftl
<#if realm.internationalizationEnabled && locale.supported?has_content>
  <div class="kc-locale-dropdown">
    <select onchange="window.location.href=this.value;">
      <#list locale.supported as l>
        <option value="${l.url}" <#if locale.currentLanguageTag == l.label>selected</#if>>
          ${msg("locale_${l.label}")}
        </option>
      </#list>
    </select>
  </div>
</#if>
```

## Language Synchronization

### marty-ui → Keycloak

When a user logs in or registers from marty-ui:

1. User selects language in marty-ui header
2. Language stored in localStorage (`i18nextLng`)
3. On login/register, current language passed as `kc_locale` parameter
4. Keycloak renders auth pages in that language

```javascript
// authApi.js
function initiateLogin(redirectUri, locale) {
  const params = new URLSearchParams();
  if (locale) params.append('kc_locale', locale);
  window.location.href = `/v1/auth/login?${params}`;
}
```

### Keycloak → marty-ui

After authentication, if you want to sync back:

1. Read `kc_locale` cookie or session after callback
2. Update i18next language on app load

```javascript
// In app initialization
const urlParams = new URLSearchParams(window.location.search);
const kcLocale = urlParams.get('kc_locale');
if (kcLocale) {
  i18n.changeLanguage(kcLocale);
}
```

## Testing

### Testing React Components

Wrap components with i18n provider:

```javascript
import { I18nextProvider } from 'react-i18next';
import i18n from '../i18n/testConfig'; // Test-specific config

test('renders translated text', () => {
  render(
    <I18nextProvider i18n={i18n}>
      <MyComponent />
    </I18nextProvider>
  );
  
  expect(screen.getByText(/welcome/i)).toBeInTheDocument();
});
```

### Test Configuration

Create `ui/src/test/i18nTestSetup.js`:

```javascript
import i18n from 'i18next';
import { initReactI18next } from 'react-i18next';

i18n.use(initReactI18next).init({
  lng: 'en',
  fallbackLng: 'en',
  resources: {
    en: {
      common: require('../../public/locales/en/common.json'),
    },
  },
});

export default i18n;
```

### Storybook

Add i18n decorator in `.storybook/preview.js`:

```javascript
import { I18nextProvider } from 'react-i18next';
import i18n from '../src/i18n';

export const decorators = [
  (Story) => (
    <I18nextProvider i18n={i18n}>
      <Story />
    </I18nextProvider>
  ),
];
```

### Testing Keycloak Theme

1. Start Keycloak with docker-compose:
   ```bash
   docker-compose up keycloak
   ```

2. Access Keycloak at http://localhost:8180

3. Test language switching:
   - Visit login page: http://localhost:8180/realms/marty/protocol/openid-connect/auth?client_id=marty-ui&redirect_uri=http://localhost:8080&kc_locale=de
   - Change `kc_locale` parameter to test different languages

## Translation Workflow

### For Developers

1. **Add strings in English first**
   - Update `public/locales/en/[namespace].json`
   - Use clear, descriptive keys
   - Add context comments for translators

2. **Use in code immediately**
   - Don't wait for translations
   - App will fall back to English

3. **Mark for translation**
   - Keep a list of new keys
   - Batch translation requests

### For Translators

1. **React translations**: Edit JSON files in `ui/public/locales/[lang]/`
2. **Keycloak translations**: Edit `.properties` files in `config/keycloak/themes/11id/login/messages/`
3. **Preserve placeholders**: Keep `{{variable}}` intact in translations
4. **Test in context**: Use language switcher to verify translations

### Translation Tools (Optional)

Consider using:
- **i18next-scanner**: Extract strings from code automatically
- **Lokalise/Crowdin**: Collaborative translation platforms
- **POEditor**: Translation management service

## Best Practices

### Keys and Namespaces

- Use **descriptive keys**: `userProfile.editButton` not `button1`
- Organize by **feature/domain**: `onboarding.roleSelection.title`
- Namespace by **scope**: `common` for shared, `console` for admin, etc.

### Writing Translatable Text

✅ **Do:**
- Keep sentences complete: "Welcome to {appName}"
- Use placeholders for dynamic content: "You have {{count}} items"
- Provide context in comments

❌ **Don't:**
- Concatenate strings: `t('hello') + ' ' + user.name` (breaks word order)
- Split sentences: "Click" + button + "to continue"
- Hardcode punctuation that varies by language

### Pluralization

Different languages have different plural rules:
- English: 1 item, 2+ items
- Japanese: No plural form
- Russian: Complex rules (1, 2-4, 5+)

Use i18next plural suffixes:

```json
{
  "item_one": "{{count}} item",
  "item_other": "{{count}} items"
}
```

### Date and Number Formatting

Use `Intl` API for locale-aware formatting:

```javascript
const date = new Date();
const formatted = new Intl.DateTimeFormat(i18n.language).format(date);

const number = 1234.56;
const formatted = new Intl.NumberFormat(i18n.language).format(number);
```

## Deployment

### Production Build

Translations are bundled with the app. Ensure all locale files are present:

```bash
npm run build
```

Verify locales directory is in build output:
```
dist/
└── locales/
    ├── en/
    ├── de/
    ├── ja/
    ├── es/
    └── fr/
```

### Keycloak Theme Deployment

The theme is mounted as a volume in docker-compose. For production:

1. Copy theme directory to Keycloak container
2. Ensure theme is set in realm config:
   ```json
   {
     "loginTheme": "11id",
     "emailTheme": "11id",
     "internationalizationEnabled": true,
     "supportedLocales": ["en", "de", "ja", "es", "fr"],
     "defaultLocale": "en"
   }
   ```

## Troubleshooting

### Translations not loading

- Check browser console for HTTP errors
- Verify locale files exist in `public/locales/`
- Check network tab for `/locales/[lang]/[namespace].json` requests

### Fallback to English

- Normal behavior when translation missing
- Check `debug: true` in i18n config for warnings

### Keycloak not showing languages

- Verify `locales=en,de,ja,es,fr` in `theme.properties`
- Check `internationalizationEnabled` in realm config
- Restart Keycloak after theme changes

### Language not persisting

- Check localStorage for `i18nextLng` key
- Verify cookies are enabled
- Check that `i18next-browser-languagedetector` is configured

## Resources

- [react-i18next documentation](https://react.i18next.com/)
- [i18next documentation](https://www.i18next.com/)
- [Keycloak theme documentation](https://www.keycloak.org/docs/latest/server_development/#_themes)
- [Material-UI localization](https://mui.com/material-ui/guides/localization/)

## Support

For questions about localization:
1. Check this guide first
2. Review existing translations for patterns
3. Ask in team chat or create an issue

import { Select, MenuItem, FormControl, Box } from '@mui/material';
import LanguageIcon from '@mui/icons-material/Language';
import { useTranslation } from 'react-i18next';

const languages = [
  { code: 'en', name: 'English', nativeName: 'English' },
  { code: 'de', name: 'German', nativeName: 'Deutsch' },
  { code: 'ja', name: 'Japanese', nativeName: '日本語' },
  { code: 'es', name: 'Spanish', nativeName: 'Español' },
  { code: 'fr', name: 'French', nativeName: 'Français' },
  { code: 'nl', name: 'Dutch', nativeName: 'Nederlands' },
];

function LanguageSwitcher({ variant = 'standard', sx = {}, compact = false }) {
  const { i18n } = useTranslation();
  const selectedLanguage = (i18n.resolvedLanguage || i18n.language || 'en').split('-')[0];

  const handleLanguageChange = (event) => {
    const newLanguage = event.target.value;
    i18n.changeLanguage(newLanguage);
  };

  return (
    <FormControl
      variant={variant}
      sx={{ minWidth: compact ? 72 : 120, ...sx }}
      data-testid="language-switcher"
      data-compact={compact ? 'true' : 'false'}
    >
      <Select
        value={selectedLanguage}
        onChange={handleLanguageChange}
        displayEmpty
        renderValue={compact ? (value) => String(value).toUpperCase() : undefined}
        startAdornment={
          <Box sx={{ display: 'flex', alignItems: 'center', mr: compact ? 0.5 : 1 }}>
            <LanguageIcon fontSize="small" />
          </Box>
        }
        sx={{
          '& .MuiSelect-select': {
            display: 'flex',
            alignItems: 'center',
            fontSize: compact ? '0.8125rem' : undefined,
            fontWeight: compact ? 600 : undefined,
          },
        }}
        data-testid="language-select"
      >
        {languages.map((language) => (
          <MenuItem key={language.code} value={language.code} data-testid={`language-option-${language.code}`}>
            {language.nativeName}
          </MenuItem>
        ))}
      </Select>
    </FormControl>
  );
}

export default LanguageSwitcher;

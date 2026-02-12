/**
 * Basics Step - Credential Template Wizard
 * 
 * Core information: name, credential type, VCT, and description.
 */

import {
  Box,
  Typography,
  TextField,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  FormHelperText,
} from '@mui/material';
import { useTranslation } from 'react-i18next';

const getCredentialTypes = (t) => [
  { value: 'VerifiableCredential', label: t('wizards.credentialTemplate.credentialTypeLabels.VerifiableCredential') },
  { value: 'VerifiableAttestation', label: t('wizards.credentialTemplate.credentialTypeLabels.VerifiableAttestation') },
  { value: 'mdoc', label: t('wizards.credentialTemplate.credentialTypeLabels.mdoc') },
  { value: 'OpenBadgeCredential', label: t('wizards.credentialTemplate.credentialTypeLabels.OpenBadgeCredential') },
];

const BasicsStep = ({ data, onChange }) => {
  const { t } = useTranslation('console');

  return (
    <Box>
      <Typography variant="h6" gutterBottom>
        {t('wizards.credentialTemplate.basicsStep.title')}
      </Typography>
      <Typography color="text.secondary" paragraph>
        {t('wizards.credentialTemplate.basicsStep.description')}
      </Typography>

      {/* Name */}
      <TextField
        fullWidth
        required
        label={t('wizards.credentialTemplate.basicsStep.fields.templateName')}
        value={data.name || ''}
        onChange={(e) => onChange({ name: e.target.value })}
        sx={{ mb: 3 }}
        helperText={t('wizards.credentialTemplate.basicsStep.helpers.templateName')}
      />

      {/* Credential Type */}
      <FormControl fullWidth required sx={{ mb: 3 }}>
        <InputLabel>{t('wizards.credentialTemplate.basicsStep.fields.credentialType')}</InputLabel>
        <Select
          value={data.credential_type || 'VerifiableCredential'}
          onChange={(e) => onChange({ credential_type: e.target.value })}
          label={t('wizards.credentialTemplate.basicsStep.fields.credentialType')}
        >
          {getCredentialTypes(t).map((type) => (
            <MenuItem key={type.value} value={type.value}>
              {type.label}
            </MenuItem>
          ))}
        </Select>
        <FormHelperText>
          {t('wizards.credentialTemplate.basicsStep.helpers.credentialType')}
        </FormHelperText>
      </FormControl>

      {/* VCT (Verifiable Credential Type) */}
      <TextField
        fullWidth
        required
        label={t('wizards.credentialTemplate.basicsStep.fields.vct')}
        value={data.vct || ''}
        onChange={(e) => onChange({ vct: e.target.value })}
        sx={{ mb: 3 }}
        placeholder={t('wizards.credentialTemplate.basicsStep.placeholders.vct')}
        helperText={t('wizards.credentialTemplate.basicsStep.helpers.vct')}
      />

      {/* Description */}
      <TextField
        fullWidth
        multiline
        rows={4}
        label={t('wizards.credentialTemplate.basicsStep.fields.description')}
        value={data.description || ''}
        onChange={(e) => onChange({ description: e.target.value })}
        helperText={t('wizards.credentialTemplate.basicsStep.helpers.description')}
      />
    </Box>
  );
};

export default BasicsStep;

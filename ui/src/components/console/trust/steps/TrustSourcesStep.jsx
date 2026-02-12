/**
 * Trust Sources Step - Trust Profile Wizard
 * 
 * Define trusted issuers (DIDs, certificate authorities, etc.)
 * This step is optional and can be skipped.
 */

import { useState } from 'react';
import {
  Box,
  Typography,
  TextField,
  Button,
  List,
  ListItem,
  ListItemText,
  IconButton,
  Chip,
  Alert,
} from '@mui/material';
import AddIcon from '@mui/icons-material/Add';
import DeleteIcon from '@mui/icons-material/Delete';
import InfoIcon from '@mui/icons-material/Info';
import { useTranslation } from 'react-i18next';

const TrustSourcesStep = ({ data, onChange }) => {
  const { t } = useTranslation('console');
  const [newIssuerDid, setNewIssuerDid] = useState('');

  const handleAddIssuer = () => {
    if (!newIssuerDid.trim()) return;

    const trustedIssuers = [...(data.trusted_issuers || [])];
    
    // Check for duplicates
    if (trustedIssuers.some((issuer) => issuer.did === newIssuerDid.trim())) {
      return;
    }

    trustedIssuers.push({
      did: newIssuerDid.trim(),
      name: '',
      added_at: new Date().toISOString(),
    });

    onChange({ trusted_issuers: trustedIssuers });
    setNewIssuerDid('');
  };

  const handleRemoveIssuer = (index) => {
    const trustedIssuers = [...(data.trusted_issuers || [])];
    trustedIssuers.splice(index, 1);
    onChange({ trusted_issuers: trustedIssuers });
  };

  const handleKeyPress = (e) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      handleAddIssuer();
    }
  };

  return (
    <Box>
      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1 }}>
        <Typography variant="h6">
          {t('wizards.trustProfile.trustSourcesStep.title')}
        </Typography>
        <Chip
          label={t('wizards.trustProfile.trustSourcesStep.optionalChip')}
          size="small"
          color="default"
          variant="outlined"
        />
      </Box>
      <Typography color="text.secondary" paragraph>
        {t('wizards.trustProfile.trustSourcesStep.description')}
      </Typography>

      <Alert severity="info" sx={{ mb: 3 }} icon={<InfoIcon />}>
        <Typography variant="body2" gutterBottom>
          {t('wizards.trustProfile.trustSourcesStep.infoAlert.body')}
        </Typography>
        <Typography variant="caption" color="text.secondary">
          <strong>{t('wizards.trustProfile.trustSourcesStep.infoAlert.skippingTitle')}</strong>{' '}
          {t('wizards.trustProfile.trustSourcesStep.infoAlert.skippingDescription')}
        </Typography>
      </Alert>

      {/* Example DIDs */}
      <Box sx={{ mb: 3, p: 2, bgcolor: 'grey.50', borderRadius: 1, border: 1, borderColor: 'grey.200' }}>
        <Typography variant="caption" color="text.secondary" gutterBottom display="block">
          {t('wizards.trustProfile.trustSourcesStep.examplesTitle')}
        </Typography>
        <Box sx={{ fontFamily: 'monospace', fontSize: '0.75rem', color: 'text.secondary' }}>
          <Box>• did:web:issuer.example.com</Box>
          <Box>• did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK</Box>
          <Box>• did:ion:EiClkZMDxPKqC9c-umQfTkR8vvZ9JPhl_xLDI9Nfk38w5A</Box>
        </Box>
      </Box>

      {/* Add Issuer DID */}
      <Box sx={{ display: 'flex', gap: 2, mb: 3 }}>
        <TextField
          fullWidth
          label={t('wizards.trustProfile.trustSourcesStep.issuerDid.label')}
          placeholder={t('wizards.trustProfile.trustSourcesStep.issuerDid.placeholder')}
          value={newIssuerDid}
          onChange={(e) => setNewIssuerDid(e.target.value)}
          onKeyPress={handleKeyPress}
          helperText={t('wizards.trustProfile.trustSourcesStep.issuerDid.helper')}
        />
        <Button
          variant="contained"
          startIcon={<AddIcon />}
          onClick={handleAddIssuer}
          disabled={!newIssuerDid.trim()}
          sx={{ minWidth: 120 }}
        >
          {t('wizards.trustProfile.trustSourcesStep.addButton')}
        </Button>
      </Box>

      {/* Issuer List */}
      {data.trusted_issuers && data.trusted_issuers.length > 0 ? (
        <Box>
          <Typography variant="subtitle2" gutterBottom>
            {t('wizards.trustProfile.trustSourcesStep.trustedIssuersTitle', {
              count: data.trusted_issuers.length,
            })}
          </Typography>
          <List>
            {data.trusted_issuers.map((issuer, index) => (
              <ListItem
                key={index}
                secondaryAction={
                  <IconButton
                    edge="end"
                    onClick={() => handleRemoveIssuer(index)}
                    color="error"
                  >
                    <DeleteIcon />
                  </IconButton>
                }
                sx={{ bgcolor: 'background.paper', mb: 1, borderRadius: 1 }}
              >
                <ListItemText
                  primary={
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                      <Typography
                        variant="body2"
                        sx={{
                          fontFamily: 'monospace',
                          wordBreak: 'break-all',
                        }}
                      >
                        {issuer.did}
                      </Typography>
                      {issuer.name && (
                        <Chip label={issuer.name} size="small" />
                      )}
                    </Box>
                  }
                />
              </ListItem>
            ))}
          </List>
        </Box>
      ) : (
        <Box
          sx={{
            p: 4,
            textAlign: 'center',
            border: '2px dashed',
            borderColor: 'divider',
            borderRadius: 1,
          }}
        >
          <Typography color="text.secondary">
            {t('wizards.trustProfile.trustSourcesStep.emptyState')}
          </Typography>
        </Box>
      )}

      {/* Future: Import from registry */}
      <Box sx={{ mt: 3, p: 2, bgcolor: 'action.hover', borderRadius: 1 }}>
        <Typography variant="body2" color="text.secondary">
          <strong>{t('wizards.trustProfile.trustSourcesStep.comingSoon.title')}</strong>{' '}
          {t('wizards.trustProfile.trustSourcesStep.comingSoon.description')}
        </Typography>
      </Box>
    </Box>
  );
};

export default TrustSourcesStep;

/**
 * Processing Fee Configuration
 *
 * Vendor component for configuring applicant processing fees.
 * Fees are charged to applicants when they apply for credentials.
 * Range: $0 (free) to $50 maximum.
 */

import { useState, useEffect } from 'react';
import { useTranslation } from 'react-i18next';
import {
  Box,
  Paper,
  Typography,
  TextField,
  Button,
  Slider,
  Alert,
  Card,
  CardContent,
  Grid,
  InputAdornment,
  FormControlLabel,
  Switch,
  Divider,
  List,
  ListItem,
  ListItemText,
  ListItemSecondaryAction,
  Chip,
} from '@mui/material';
import SaveIcon from '@mui/icons-material/Save';
import AttachMoneyIcon from '@mui/icons-material/AttachMoney';
import InfoIcon from '@mui/icons-material/Info';
import ReceiptIcon from '@mui/icons-material/Receipt';
import { useAuth } from '../../hooks/useAuth';
import { useNotifications } from '../../hooks/useNotifications';
import { usePayment } from '@marty/subscriptions';

// Fee limits (must match PaymentContext)
const MIN_FEE = 0;
const MAX_FEE = 50;

export default function ProcessingFeeConfig() {
  const { t } = useTranslation('vendor');
  const { organizationId } = useAuth();
  const { showSuccess, showError, showWarning } = useNotifications();
  const { validateProcessingFee, minProcessingFee, maxProcessingFee, isMockMode } = usePayment();
  
  const [defaultFee, setDefaultFee] = useState(25);
  const [credentialFees, setCredentialFees] = useState({});
  const [enablePerCredentialFees, setEnablePerCredentialFees] = useState(false);
  const [freeProcessing, setFreeProcessing] = useState(false);
  const [saving, setSaving] = useState(false);
  const [hasChanges, setHasChanges] = useState(false);

  // Credential type fee presets
  const CREDENTIAL_TYPES = [
    { id: 'passport', name: t('processingFeeConfig.credentialTypes.passport'), defaultFee: 25 },
    { id: 'visa', name: t('processingFeeConfig.credentialTypes.visa'), defaultFee: 35 },
    { id: 'permit', name: t('processingFeeConfig.credentialTypes.permit'), defaultFee: 40 },
    { id: 'license', name: t('processingFeeConfig.credentialTypes.license'), defaultFee: 15 },
    { id: 'certificate', name: t('processingFeeConfig.credentialTypes.certificate'), defaultFee: 10 },
  ];

  // Load current settings
  useEffect(() => {
    loadSettings();
  }, [organizationId]);

  const loadSettings = async () => {
    try {
      // TODO: Replace with actual API call
      // const response = await fetch(`/api/organizations/${organizationId}/settings/fees`);
      
      // Mock data
      setDefaultFee(25);
      setCredentialFees({
        passport: 25,
        visa: 35,
        permit: 40,
        license: 15,
        certificate: 10,
      });
      setEnablePerCredentialFees(false);
      setFreeProcessing(false);
    } catch (error) {
      console.error('Failed to load fee settings:', error);
      showError(t('processingFeeConfig.messages.loadFailed'));
    }
  };

  const handleSave = async () => {
    // Validate default fee
    const validation = validateProcessingFee(freeProcessing ? 0 : defaultFee);
    if (!validation.valid) {
      showError(validation.error);
      return;
    }

    // Validate per-credential fees if enabled
    if (enablePerCredentialFees && !freeProcessing) {
      for (const [credType, fee] of Object.entries(credentialFees)) {
        const credValidation = validateProcessingFee(fee);
        if (!credValidation.valid) {
          showError(t('processingFeeConfig.messages.invalidFee', { credType, error: credValidation.error }));
          return;
        }
      }
    }

    setSaving(true);
    try {
      // TODO: Replace with actual API call
      // await fetch(`/api/organizations/${organizationId}/settings/fees`, {
      //   method: 'PUT',
      //   body: JSON.stringify({
      //     default_fee: freeProcessing ? 0 : defaultFee,
      //     per_credential_fees: enablePerCredentialFees ? credentialFees : null,
      //     free_processing: freeProcessing,
      //   }),
      // });

      await new Promise((resolve) => setTimeout(resolve, 500)); // Simulate API
      
      setHasChanges(false);
      showSuccess(t('processingFeeConfig.messages.saveSuccess'));
    } catch (error) {
      console.error('Failed to save fee settings:', error);
      showError(t('processingFeeConfig.messages.saveFailed'));
    } finally {
      setSaving(false);
    }
  };

  const handleDefaultFeeChange = (value) => {
    const numValue = Math.min(MAX_FEE, Math.max(MIN_FEE, Number(value) || 0));
    setDefaultFee(numValue);
    setHasChanges(true);
  };

  const handleCredentialFeeChange = (credentialId, value) => {
    const numValue = Math.min(MAX_FEE, Math.max(MIN_FEE, Number(value) || 0));
    setCredentialFees((prev) => ({ ...prev, [credentialId]: numValue }));
    setHasChanges(true);
  };

  const handleFreeProcessingToggle = (enabled) => {
    setFreeProcessing(enabled);
    setHasChanges(true);
  };

  const handlePerCredentialToggle = (enabled) => {
    setEnablePerCredentialFees(enabled);
    setHasChanges(true);
  };

  const calculateEstimatedRevenue = () => {
    if (freeProcessing) return 0;
    // Estimate based on 100 applicants/month (mock)
    const avgFee = enablePerCredentialFees
      ? Object.values(credentialFees).reduce((a, b) => a + b, 0) / Object.keys(credentialFees).length
      : defaultFee;
    return avgFee * 100;
  };

  return (
    <Box sx={{ p: 3 }}>
      {/* Header */}
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
        <Box>
          <Typography variant="h5" component="h1" gutterBottom>
            {t('processingFeeConfig.title')}
          </Typography>
          <Typography variant="body2" color="textSecondary">
            {t('processingFeeConfig.description')}
          </Typography>
        </Box>
        <Button
          variant="contained"
          startIcon={<SaveIcon />}
          onClick={handleSave}
          disabled={saving || !hasChanges}
        >
          {saving ? t('processingFeeConfig.saving') : t('processingFeeConfig.saveButton')}
        </Button>
      </Box>

      {/* Mock Mode Alert */}
      {isMockMode && (
        <Alert severity="info" sx={{ mb: 3 }}>
          <Typography variant="body2">
            <strong>{t('processingFeeConfig.mockModeAlert')}</strong>
          </Typography>
        </Alert>
      )}

      <Grid container spacing={3}>
        {/* Fee Configuration */}
        <Grid item xs={12} md={8}>
          <Paper sx={{ p: 3 }}>
            {/* Free Processing Toggle */}
            <FormControlLabel
              control={
                <Switch
                  checked={freeProcessing}
                  onChange={(e) => handleFreeProcessingToggle(e.target.checked)}
                  color="primary"
                />
              }
              label={
                <Box>
                  <Typography variant="body1">{t('processingFeeConfig.freeProcessing.label')}</Typography>
                  <Typography variant="caption" color="textSecondary">
                    {t('processingFeeConfig.freeProcessing.description')}
                  </Typography>
                </Box>
              }
              sx={{ mb: 3 }}
            />

            <Divider sx={{ mb: 3 }} />

            {/* Default Fee */}
            <Box sx={{ mb: 4, opacity: freeProcessing ? 0.5 : 1 }}>
              <Typography variant="h6" gutterBottom>
                {t('processingFeeConfig.defaultFee.title')}
              </Typography>
              <Typography variant="body2" color="textSecondary" sx={{ mb: 2 }}>
                {t('processingFeeConfig.defaultFee.description')}
              </Typography>

              <Box sx={{ display: 'flex', alignItems: 'center', gap: 3 }}>
                <TextField
                  type="number"
                  value={freeProcessing ? 0 : defaultFee}
                  onChange={(e) => handleDefaultFeeChange(e.target.value)}
                  disabled={freeProcessing}
                  InputProps={{
                    startAdornment: <InputAdornment position="start">$</InputAdornment>,
                    inputProps: { min: MIN_FEE, max: MAX_FEE, step: 0.5 },
                  }}
                  sx={{ width: 120 }}
                />
                <Slider
                  value={freeProcessing ? 0 : defaultFee}
                  onChange={(e, value) => handleDefaultFeeChange(value)}
                  disabled={freeProcessing}
                  min={MIN_FEE}
                  max={MAX_FEE}
                  step={0.5}
                  marks={[
                    { value: 0, label: '$0' },
                    { value: 25, label: '$25' },
                    { value: 50, label: '$50' },
                  ]}
                  valueLabelDisplay="auto"
                  valueLabelFormat={(v) => `$${v}`}
                  sx={{ flex: 1 }}
                />
              </Box>
            </Box>

            <Divider sx={{ mb: 3 }} />

            {/* Per-Credential Fees */}
            <Box sx={{ opacity: freeProcessing ? 0.5 : 1 }}>
              <FormControlLabel
                control={
                  <Switch
                    checked={enablePerCredentialFees}
                    onChange={(e) => handlePerCredentialToggle(e.target.checked)}
                    disabled={freeProcessing}
                    color="primary"
                  />
                }
                label={
                  <Box>
                    <Typography variant="body1">{t('processingFeeConfig.perCredentialFees.label')}</Typography>
                    <Typography variant="caption" color="textSecondary">
                      {t('processingFeeConfig.perCredentialFees.description')}
                    </Typography>
                  </Box>
                }
                sx={{ mb: 2 }}
              />

              {enablePerCredentialFees && !freeProcessing && (
                <List disablePadding>
                  {CREDENTIAL_TYPES.map((credType) => (
                    <ListItem key={credType.id} divider>
                      <ListItemText
                        primary={credType.name}
                        secondary={t('processingFeeConfig.perCredentialFees.default', { amount: credType.defaultFee })}
                      />
                      <ListItemSecondaryAction>
                        <TextField
                          type="number"
                          value={credentialFees[credType.id] ?? credType.defaultFee}
                          onChange={(e) => handleCredentialFeeChange(credType.id, e.target.value)}
                          size="small"
                          InputProps={{
                            startAdornment: <InputAdornment position="start">$</InputAdornment>,
                            inputProps: { min: MIN_FEE, max: MAX_FEE, step: 0.5 },
                          }}
                          sx={{ width: 100 }}
                        />
                      </ListItemSecondaryAction>
                    </ListItem>
                  ))}
                </List>
              )}
            </Box>
          </Paper>
        </Grid>

        {/* Summary Card */}
        <Grid item xs={12} md={4}>
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 2 }}>
                <ReceiptIcon color="primary" />
                <Typography variant="h6">{t('processingFeeConfig.summary.title')}</Typography>
              </Box>

              <Box sx={{ mb: 2 }}>
                <Typography variant="body2" color="textSecondary">
                  {t('processingFeeConfig.summary.currentConfig')}
                </Typography>
                <Chip
                  icon={<AttachMoneyIcon />}
                  label={freeProcessing ? t('processingFeeConfig.summary.free') : t('processingFeeConfig.summary.defaultAmount', { amount: defaultFee })}
                  color={freeProcessing ? 'success' : 'primary'}
                  sx={{ mt: 1 }}
                />
              </Box>

              <Divider sx={{ my: 2 }} />

              <Box sx={{ mb: 2 }}>
                <Typography variant="body2" color="textSecondary">
                  {t('processingFeeConfig.summary.feeRange')}
                </Typography>
                <Typography variant="h5">
                  ${minProcessingFee} - ${maxProcessingFee}
                </Typography>
              </Box>

              <Box>
                <Typography variant="body2" color="textSecondary">
                  {t('processingFeeConfig.summary.estimatedRevenue')}
                </Typography>
                <Typography variant="h5" color="success.main">
                  ${calculateEstimatedRevenue().toFixed(2)}
                </Typography>
                <Typography variant="caption" color="textSecondary">
                  {t('processingFeeConfig.summary.revenueNote')}
                </Typography>
              </Box>
            </CardContent>
          </Card>

          {/* Info Card */}
          <Card sx={{ mt: 2 }}>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1 }}>
                <InfoIcon color="info" />
                <Typography variant="subtitle2">{t('processingFeeConfig.info.title')}</Typography>
              </Box>
              <Typography variant="body2" color="textSecondary">
                {t('processingFeeConfig.info.description')}
              </Typography>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

    </Box>
  );
}

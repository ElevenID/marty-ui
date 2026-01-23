/**
 * Processing Fee Configuration
 *
 * Vendor component for configuring applicant processing fees.
 * Fees are charged to applicants when they apply for credentials.
 * Range: $0 (free) to $50 maximum.
 */

import React, { useState, useEffect } from 'react';
import {
  Box,
  Paper,
  Typography,
  TextField,
  Button,
  Slider,
  Alert,
  Snackbar,
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
import { usePayment } from '../../contexts/PaymentContext';

// Fee limits (must match PaymentContext)
const MIN_FEE = 0;
const MAX_FEE = 50;

// Credential type fee presets
const CREDENTIAL_TYPES = [
  { id: 'passport', name: 'Passport Application', defaultFee: 25 },
  { id: 'visa', name: 'Visa Application', defaultFee: 35 },
  { id: 'permit', name: 'Work Permit', defaultFee: 40 },
  { id: 'license', name: 'License Renewal', defaultFee: 15 },
  { id: 'certificate', name: 'Certificate Request', defaultFee: 10 },
];

export default function ProcessingFeeConfig() {
  const { organizationId, organizationName } = useAuth();
  const { validateProcessingFee, minProcessingFee, maxProcessingFee, isMockMode } = usePayment();
  
  const [defaultFee, setDefaultFee] = useState(25);
  const [credentialFees, setCredentialFees] = useState({});
  const [enablePerCredentialFees, setEnablePerCredentialFees] = useState(false);
  const [freeProcessing, setFreeProcessing] = useState(false);
  const [saving, setSaving] = useState(false);
  const [hasChanges, setHasChanges] = useState(false);
  const [snackbar, setSnackbar] = useState({ open: false, message: '', severity: 'success' });

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
      setSnackbar({ open: true, message: 'Failed to load settings', severity: 'error' });
    }
  };

  const handleSave = async () => {
    // Validate default fee
    const validation = validateProcessingFee(freeProcessing ? 0 : defaultFee);
    if (!validation.valid) {
      setSnackbar({ open: true, message: validation.error, severity: 'error' });
      return;
    }

    // Validate per-credential fees if enabled
    if (enablePerCredentialFees && !freeProcessing) {
      for (const [credType, fee] of Object.entries(credentialFees)) {
        const credValidation = validateProcessingFee(fee);
        if (!credValidation.valid) {
          setSnackbar({
            open: true,
            message: `Invalid fee for ${credType}: ${credValidation.error}`,
            severity: 'error',
          });
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
      setSnackbar({ open: true, message: 'Fee settings saved successfully', severity: 'success' });
    } catch (error) {
      console.error('Failed to save fee settings:', error);
      setSnackbar({ open: true, message: 'Failed to save settings', severity: 'error' });
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
            Processing Fees
          </Typography>
          <Typography variant="body2" color="textSecondary">
            Configure fees charged to applicants when they apply for credentials.
          </Typography>
        </Box>
        <Button
          variant="contained"
          startIcon={<SaveIcon />}
          onClick={handleSave}
          disabled={saving || !hasChanges}
        >
          {saving ? 'Saving...' : 'Save Changes'}
        </Button>
      </Box>

      {/* Mock Mode Alert */}
      {isMockMode && (
        <Alert severity="info" sx={{ mb: 3 }}>
          <Typography variant="body2">
            <strong>Development Mode:</strong> Payments are mocked. No real charges will be made.
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
                  <Typography variant="body1">Free Processing</Typography>
                  <Typography variant="caption" color="textSecondary">
                    Waive all processing fees for applicants
                  </Typography>
                </Box>
              }
              sx={{ mb: 3 }}
            />

            <Divider sx={{ mb: 3 }} />

            {/* Default Fee */}
            <Box sx={{ mb: 4, opacity: freeProcessing ? 0.5 : 1 }}>
              <Typography variant="h6" gutterBottom>
                Default Processing Fee
              </Typography>
              <Typography variant="body2" color="textSecondary" sx={{ mb: 2 }}>
                This fee is charged to all applicants unless per-credential fees are configured.
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
                    <Typography variant="body1">Per-Credential Fees</Typography>
                    <Typography variant="caption" color="textSecondary">
                      Set different fees for each credential type
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
                        secondary={`Default: $${credType.defaultFee}`}
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
                <Typography variant="h6">Fee Summary</Typography>
              </Box>

              <Box sx={{ mb: 2 }}>
                <Typography variant="body2" color="textSecondary">
                  Current Configuration
                </Typography>
                <Chip
                  icon={<AttachMoneyIcon />}
                  label={freeProcessing ? 'Free' : `$${defaultFee} default`}
                  color={freeProcessing ? 'success' : 'primary'}
                  sx={{ mt: 1 }}
                />
              </Box>

              <Divider sx={{ my: 2 }} />

              <Box sx={{ mb: 2 }}>
                <Typography variant="body2" color="textSecondary">
                  Fee Range
                </Typography>
                <Typography variant="h5">
                  ${minProcessingFee} - ${maxProcessingFee}
                </Typography>
              </Box>

              <Box>
                <Typography variant="body2" color="textSecondary">
                  Estimated Monthly Revenue
                </Typography>
                <Typography variant="h5" color="success.main">
                  ${calculateEstimatedRevenue().toFixed(2)}
                </Typography>
                <Typography variant="caption" color="textSecondary">
                  Based on ~100 applicants/month
                </Typography>
              </Box>
            </CardContent>
          </Card>

          {/* Info Card */}
          <Card sx={{ mt: 2 }}>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1 }}>
                <InfoIcon color="info" />
                <Typography variant="subtitle2">Payment Processing</Typography>
              </Box>
              <Typography variant="body2" color="textSecondary">
                Processing fees are collected via Square at the time of application. Funds are
                deposited to your connected Square account minus Square&apos;s transaction fees
                (2.6% + $0.10).
              </Typography>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Snackbar */}
      <Snackbar
        open={snackbar.open}
        autoHideDuration={4000}
        onClose={() => setSnackbar({ ...snackbar, open: false })}
      >
        <Alert severity={snackbar.severity} onClose={() => setSnackbar({ ...snackbar, open: false })}>
          {snackbar.message}
        </Alert>
      </Snackbar>
    </Box>
  );
}

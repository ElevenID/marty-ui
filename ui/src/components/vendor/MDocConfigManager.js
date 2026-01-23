/**
 * mDoc Configuration Manager
 *
 * Admin component for configuring mDoc/mDL credential types with:
 * - Field selection and requirements
 * - Validity periods
 * - Issuance policies
 * - Application form configuration
 */

import React, { useState, useEffect } from 'react';
import {
  Box,
  Paper,
  Typography,
  Button,
  Tabs,
  Tab,
  Card,
  CardContent,
  Grid,
  Switch,
  FormControlLabel,
  TextField,
  Select,
  MenuItem,
  FormControl,
  InputLabel,
  Chip,
  Divider,
  Alert,
  Snackbar,
  Skeleton,
  List,
  ListItem,
  ListItemText,
  ListItemIcon,
  ListItemSecondaryAction,
  Checkbox,
} from '@mui/material';
import SaveIcon from '@mui/icons-material/Save';
import RefreshIcon from '@mui/icons-material/Refresh';
import DirectionsCarIcon from '@mui/icons-material/DirectionsCar';
import BadgeIcon from '@mui/icons-material/Badge';
import FlightIcon from '@mui/icons-material/Flight';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import DragIndicatorIcon from '@mui/icons-material/DragIndicator';
import { useAuth } from '../../hooks/useAuth';
import { TemplateActions } from './TemplateActions';

const API_URL = process.env.REACT_APP_API_URL || '';

// mDoc credential types
const MDOC_TYPES = {
  'org.iso.18013.5.1.mDL': {
    id: 'org.iso.18013.5.1.mDL',
    name: 'Mobile Driver\'s License (mDL)',
    description: 'ISO/IEC 18013-5 compliant mobile driving license',
    icon: <DirectionsCarIcon />,
    namespace: 'org.iso.18013.5.1',
    defaultFields: {
      required: ['family_name', 'given_name', 'birth_date', 'issue_date', 'expiry_date', 'document_number', 'portrait'],
      optional: ['driving_privileges', 'resident_address', 'age_over_18', 'age_over_21', 'nationality', 'eye_color', 'hair_color', 'height', 'weight']
    }
  },
  'org.iso.23220.photoid.1': {
    id: 'org.iso.23220.photoid.1',
    name: 'Photo ID',
    description: 'ISO 23220 Photo ID credential',
    icon: <BadgeIcon />,
    namespace: 'org.iso.23220.photoid.1',
    defaultFields: {
      required: ['family_name', 'given_name', 'birth_date', 'portrait'],
      optional: ['nationality', 'document_number', 'issue_date', 'expiry_date']
    }
  },
  'org.iso.18013.5.1.travelVisa': {
    id: 'org.iso.18013.5.1.travelVisa',
    name: 'Travel Visa',
    description: 'Digital travel visa credential',
    icon: <FlightIcon />,
    namespace: 'org.iso.18013.5.1',
    defaultFields: {
      required: ['family_name', 'given_name', 'birth_date', 'nationality', 'passport_number'],
      optional: ['visa_type', 'entry_count', 'validity_start', 'validity_end', 'purpose']
    }
  }
};

// All possible mDoc fields with metadata
const MDOC_FIELDS = {
  family_name: { label: 'Family Name', type: 'text', required: true },
  given_name: { label: 'Given Name', type: 'text', required: true },
  birth_date: { label: 'Date of Birth', type: 'date', required: true },
  issue_date: { label: 'Issue Date', type: 'date', required: false },
  expiry_date: { label: 'Expiry Date', type: 'date', required: false },
  document_number: { label: 'Document Number', type: 'text', required: false },
  portrait: { label: 'Portrait Photo', type: 'image', required: true },
  driving_privileges: { label: 'Driving Privileges', type: 'array', required: false },
  resident_address: { label: 'Resident Address', type: 'address', required: false },
  age_over_18: { label: 'Age Over 18', type: 'boolean', required: false, derived: true },
  age_over_21: { label: 'Age Over 21', type: 'boolean', required: false, derived: true },
  nationality: { label: 'Nationality', type: 'text', required: false },
  eye_color: { label: 'Eye Color', type: 'select', required: false },
  hair_color: { label: 'Hair Color', type: 'select', required: false },
  height: { label: 'Height', type: 'number', required: false },
  weight: { label: 'Weight', type: 'number', required: false },
  passport_number: { label: 'Passport Number', type: 'text', required: false },
  visa_type: { label: 'Visa Type', type: 'select', required: false },
  entry_count: { label: 'Entry Count', type: 'select', required: false },
  validity_start: { label: 'Validity Start', type: 'date', required: false },
  validity_end: { label: 'Validity End', type: 'date', required: false },
  purpose: { label: 'Purpose of Visit', type: 'text', required: false },
  issuing_country: { label: 'Issuing Country', type: 'text', required: false },
  issuing_authority: { label: 'Issuing Authority', type: 'text', required: false },
};

function TabPanel({ children, value, index, ...other }) {
  return (
    <div
      role="tabpanel"
      hidden={value !== index}
      id={`mdoc-tabpanel-${index}`}
      {...other}
    >
      {value === index && <Box sx={{ py: 3 }}>{children}</Box>}
    </div>
  );
}

export default function MDocConfigManager() {
  const { organizationId } = useAuth();
  const [activeTab, setActiveTab] = useState(0);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [snackbar, setSnackbar] = useState({ open: false, message: '', severity: 'success' });
  
  // Enabled credential types
  const [enabledTypes, setEnabledTypes] = useState({});
  
  // Configuration for each type
  const [typeConfigs, setTypeConfigs] = useState({});
  
  // Currently selected type for detailed config
  const [selectedType, setSelectedType] = useState('org.iso.18013.5.1.mDL');
  
  // Current config for template actions
  const [currentConfig, setCurrentConfig] = useState(null);

  useEffect(() => {
    fetchConfiguration();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [organizationId]);

  const fetchConfiguration = async () => {
    setLoading(true);
    try {
      const response = await fetch(`${API_URL}/api/organizations/${organizationId}/mdoc-config`, {
        credentials: 'include',
      });
      
      if (response.ok) {
        const data = await response.json();
        setEnabledTypes(data.enabled_types || {});
        setTypeConfigs(data.type_configs || {});
      } else {
        // Initialize with defaults
        const defaultEnabled = { 'org.iso.18013.5.1.mDL': true };
        const defaultConfigs = {
          'org.iso.18013.5.1.mDL': {
            fields: MDOC_TYPES['org.iso.18013.5.1.mDL'].defaultFields,
            validityDays: 365 * 4,
            requireIdentityVerification: true,
            requireDocumentVerification: true,
            allowRenewal: true,
            renewalWindowDays: 90,
            processingFee: 25.00,
          }
        };
        setEnabledTypes(defaultEnabled);
        setTypeConfigs(defaultConfigs);
      }
    } catch (error) {
      console.error('Failed to fetch mDoc configuration:', error);
      setSnackbar({ open: true, message: 'Failed to load configuration', severity: 'error' });
    } finally {
      setLoading(false);
    }
  };

  const handleSaveConfiguration = async () => {
    setSaving(true);
    try {
      const response = await fetch(`${API_URL}/api/organizations/${organizationId}/mdoc-config`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({
          enabled_types: enabledTypes,
          type_configs: typeConfigs,
        }),
      });

      if (response.ok) {
        setSnackbar({ open: true, message: 'Configuration saved successfully', severity: 'success' });
      } else {
        throw new Error('Failed to save configuration');
      }
    } catch (error) {
      console.error('Failed to save configuration:', error);
      setSnackbar({ open: true, message: 'Failed to save configuration', severity: 'error' });
    } finally {
      setSaving(false);
    }
  };

  const handleToggleType = (typeId) => {
    setEnabledTypes(prev => ({
      ...prev,
      [typeId]: !prev[typeId]
    }));
    
    // Initialize config if enabling
    if (!enabledTypes[typeId] && !typeConfigs[typeId]) {
      setTypeConfigs(prev => ({
        ...prev,
        [typeId]: {
          fields: MDOC_TYPES[typeId].defaultFields,
          validityDays: 365 * 4,
          requireIdentityVerification: true,
          requireDocumentVerification: false,
          allowRenewal: true,
          renewalWindowDays: 90,
          processingFee: 25.00,
        }
      }));
    }
  };

  const handleConfigChange = (field, value) => {
    setTypeConfigs(prev => ({
      ...prev,
      [selectedType]: {
        ...prev[selectedType],
        [field]: value
      }
    }));
  };

  const handleFieldToggle = (fieldName, isRequired) => {
    setTypeConfigs(prev => {
      const currentFields = prev[selectedType]?.fields || { required: [], optional: [] };
      const newRequired = [...currentFields.required];
      const newOptional = [...currentFields.optional];
      
      // Remove from both arrays first
      const reqIdx = newRequired.indexOf(fieldName);
      const optIdx = newOptional.indexOf(fieldName);
      if (reqIdx > -1) newRequired.splice(reqIdx, 1);
      if (optIdx > -1) newOptional.splice(optIdx, 1);
      
      // Add to appropriate array
      if (isRequired) {
        newRequired.push(fieldName);
      } else if (isRequired === false) {
        newOptional.push(fieldName);
      }
      // If isRequired is null, field is disabled (removed from both)
      
      return {
        ...prev,
        [selectedType]: {
          ...prev[selectedType],
          fields: { required: newRequired, optional: newOptional }
        }
      };
    });
  };

  const currentFields = (typeConfigs[selectedType] || {}).fields || { required: [], optional: [] };

  if (loading) {
    return (
      <Box sx={{ p: 3 }} data-testid="mdoc-config-loading">
        <Skeleton variant="text" height={60} width="50%" />
        <Skeleton variant="rectangular" height={400} sx={{ mt: 2 }} />
      </Box>
    );
  }

  return (
    <Box sx={{ p: 3 }} data-testid="mdoc-config-manager">
      {/* Header */}
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
        <Box>
          <Typography variant="h4" component="h1" data-testid="page-title">
            mDoc Configuration
          </Typography>
          <Typography variant="body2" color="text.secondary">
            Configure mobile document credential types for your organization
          </Typography>
        </Box>
        <Box sx={{ display: 'flex', gap: 2 }}>
          <Button
            variant="outlined"
            startIcon={<RefreshIcon />}
            onClick={fetchConfiguration}
            data-testid="refresh-config-btn"
          >
            Refresh
          </Button>
          <Button
            variant="contained"
            startIcon={<SaveIcon />}
            onClick={handleSaveConfiguration}
            disabled={saving}
            data-testid="save-config-btn"
          >
            {saving ? 'Saving...' : 'Save Configuration'}
          </Button>
        </Box>
      </Box>

      {/* Template Actions */}
      {selectedType && enabledTypes[selectedType] && (
        <Box sx={{ mb: 3 }}>
          <TemplateActions
            configId={{
              orgId: organizationId,
              typeId: selectedType,
            }}
            configData={currentConfig}
            onStatusChange={(updatedConfig) => {
              setCurrentConfig(updatedConfig);
              setSnackbar({
                open: true,
                message: 'Template status updated',
                severity: 'success',
              });
            }}
          />
        </Box>
      )}

      <Snackbar
        open={snackbar.open}
        autoHideDuration={5000}
        onClose={() => setSnackbar(s => ({ ...s, open: false }))}
      >
        <Alert severity={snackbar.severity} data-testid="config-saved-toast">
          {snackbar.message}
        </Alert>
      </Snackbar>

      {/* Tabs */}
      <Paper sx={{ mb: 3 }}>
        <Tabs value={activeTab} onChange={(e, v) => setActiveTab(v)} data-testid="config-tabs">
          <Tab label="Credential Types" data-testid="credential-types-tab" />
          <Tab label="Application Form" data-testid="form-builder-tab" />
          <Tab label="Issuance Policy" data-testid="issuance-policy-tab" />
        </Tabs>
      </Paper>

      {/* Tab 1: Credential Types */}
      <TabPanel value={activeTab} index={0}>
        <Grid container spacing={3}>
          {Object.entries(MDOC_TYPES).map(([typeId, typeInfo]) => (
            <Grid item xs={12} md={4} key={typeId}>
              <Card 
                sx={{ 
                  height: '100%',
                  border: enabledTypes[typeId] ? '2px solid' : '1px solid',
                  borderColor: enabledTypes[typeId] ? 'primary.main' : 'divider'
                }}
                data-testid={`credential-type-${typeId.split('.').pop()}`}
              >
                <CardContent>
                  <Box sx={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between' }}>
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 2 }}>
                      {React.cloneElement(typeInfo.icon, { color: enabledTypes[typeId] ? 'primary' : 'disabled' })}
                      <Typography variant="h6">{typeInfo.name}</Typography>
                    </Box>
                    <Switch
                      checked={!!enabledTypes[typeId]}
                      onChange={() => handleToggleType(typeId)}
                      data-testid={`enable-${typeId.split('.').pop()}-toggle`}
                    />
                  </Box>
                  <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                    {typeInfo.description}
                  </Typography>
                  {enabledTypes[typeId] && (
                    <Box>
                      <Chip
                        size="small"
                        icon={<CheckCircleIcon />}
                        label="Enabled"
                        color="success"
                        sx={{ mr: 1 }}
                        data-testid={`${typeId.split('.').pop()}-enabled-badge`}
                      />
                      <Button
                        size="small"
                        onClick={() => {
                          setSelectedType(typeId);
                          setActiveTab(1);
                        }}
                        data-testid={`configure-${typeId.split('.').pop()}-btn`}
                      >
                        Configure
                      </Button>
                    </Box>
                  )}
                </CardContent>
              </Card>
            </Grid>
          ))}
        </Grid>

        {/* Active Types Summary */}
        <Paper sx={{ mt: 3, p: 2 }} data-testid="active-credential-types">
          <Typography variant="subtitle2" color="text.secondary" gutterBottom>
            Active Credential Types
          </Typography>
          <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
            {Object.entries(enabledTypes)
              .filter(([, enabled]) => enabled)
              .map(([typeId]) => (
                <Chip
                  key={typeId}
                  label={MDOC_TYPES[typeId]?.name || typeId}
                  icon={MDOC_TYPES[typeId]?.icon}
                  color="primary"
                  variant="outlined"
                />
              ))}
            {!Object.values(enabledTypes).some(v => v) && (
              <Typography variant="body2" color="text.secondary">
                No credential types enabled
              </Typography>
            )}
          </Box>
        </Paper>
      </TabPanel>

      {/* Tab 2: Application Form Builder */}
      <TabPanel value={activeTab} index={1}>
        <Box sx={{ mb: 3 }}>
          <FormControl sx={{ minWidth: 300 }}>
            <InputLabel>Credential Type</InputLabel>
            <Select
              value={selectedType}
              onChange={(e) => setSelectedType(e.target.value)}
              label="Credential Type"
              data-testid="credential-type-select"
            >
              {Object.entries(MDOC_TYPES).map(([typeId, typeInfo]) => (
                <MenuItem key={typeId} value={typeId} disabled={!enabledTypes[typeId]}>
                  {typeInfo.name} {!enabledTypes[typeId] && '(Disabled)'}
                </MenuItem>
              ))}
            </Select>
          </FormControl>
        </Box>

        {!enabledTypes[selectedType] && (
          <Alert severity="warning" sx={{ mb: 3 }}>
            This credential type is not enabled. Enable it in the Credential Types tab first.
          </Alert>
        )}

        <Grid container spacing={3}>
          {/* Field Configuration */}
          <Grid item xs={12} md={8}>
            <Paper sx={{ p: 2 }}>
              <Typography variant="h6" gutterBottom>
                Application Form Fields
              </Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                Configure which fields are required, optional, or excluded from the application form.
              </Typography>

              <List>
                {Object.entries(MDOC_FIELDS).map(([fieldName, fieldInfo]) => {
                  const isRequired = currentFields.required.includes(fieldName);
                  const isOptional = currentFields.optional.includes(fieldName);
                  const isIncluded = isRequired || isOptional;

                  return (
                    <ListItem 
                      key={fieldName}
                      sx={{ 
                        borderRadius: 1,
                        mb: 1,
                        bgcolor: isIncluded ? 'action.hover' : 'transparent'
                      }}
                      data-testid={`field-${fieldName}`}
                    >
                      <ListItemIcon>
                        <DragIndicatorIcon color="disabled" />
                      </ListItemIcon>
                      <ListItemText
                        primary={fieldInfo.label}
                        secondary={`Type: ${fieldInfo.type}${fieldInfo.derived ? ' (Derived)' : ''}`}
                      />
                      <ListItemSecondaryAction>
                        <FormControl size="small" sx={{ minWidth: 120 }}>
                          <Select
                            value={isRequired ? 'required' : isOptional ? 'optional' : 'disabled'}
                            onChange={(e) => {
                              const value = e.target.value;
                              handleFieldToggle(
                                fieldName,
                                value === 'required' ? true : value === 'optional' ? false : null
                              );
                            }}
                            size="small"
                          >
                            <MenuItem value="required">Required</MenuItem>
                            <MenuItem value="optional">Optional</MenuItem>
                            <MenuItem value="disabled">Disabled</MenuItem>
                          </Select>
                        </FormControl>
                      </ListItemSecondaryAction>
                    </ListItem>
                  );
                })}
              </List>
            </Paper>
          </Grid>

          {/* Preview */}
          <Grid item xs={12} md={4}>
            <Paper sx={{ p: 2, position: 'sticky', top: 20 }}>
              <Typography variant="h6" gutterBottom>
                Form Preview
              </Typography>
              <Divider sx={{ mb: 2 }} />
              
              <Typography variant="subtitle2" color="text.secondary" sx={{ mb: 1 }}>
                Required Fields ({currentFields.required.length})
              </Typography>
              <Box sx={{ mb: 2 }}>
                {currentFields.required.map(f => (
                  <Chip key={f} label={MDOC_FIELDS[f]?.label || f} size="small" sx={{ m: 0.25 }} color="primary" />
                ))}
              </Box>
              
              <Typography variant="subtitle2" color="text.secondary" sx={{ mb: 1 }}>
                Optional Fields ({currentFields.optional.length})
              </Typography>
              <Box>
                {currentFields.optional.map(f => (
                  <Chip key={f} label={MDOC_FIELDS[f]?.label || f} size="small" sx={{ m: 0.25 }} variant="outlined" />
                ))}
              </Box>
            </Paper>
          </Grid>
        </Grid>
      </TabPanel>

      {/* Tab 3: Issuance Policy */}
      <TabPanel value={activeTab} index={2}>
        <Box sx={{ mb: 3 }}>
          <FormControl sx={{ minWidth: 300 }}>
            <InputLabel>Credential Type</InputLabel>
            <Select
              value={selectedType}
              onChange={(e) => setSelectedType(e.target.value)}
              label="Credential Type"
            >
              {Object.entries(MDOC_TYPES).map(([typeId, typeInfo]) => (
                <MenuItem key={typeId} value={typeId} disabled={!enabledTypes[typeId]}>
                  {typeInfo.name}
                </MenuItem>
              ))}
            </Select>
          </FormControl>
        </Box>

        <Grid container spacing={3}>
          {/* Validity & Verification */}
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3 }}>
              <Typography variant="h6" gutterBottom>
                Validity & Verification
              </Typography>

              <TextField
                fullWidth
                type="number"
                label="Validity Period (years)"
                value={Math.floor((currentConfig?.validityDays || 1460) / 365)}
                onChange={(e) => handleConfigChange('validityDays', parseInt(e.target.value) * 365)}
                sx={{ mb: 3 }}
                inputProps={{ min: 1, max: 10 }}
                data-testid="validity-years-input"
              />

              <FormControlLabel
                control={
                  <Checkbox
                    checked={currentConfig?.requireIdentityVerification || false}
                    onChange={(e) => handleConfigChange('requireIdentityVerification', e.target.checked)}
                    data-testid="require-identity-verification"
                  />
                }
                label="Require Identity Verification"
              />

              <FormControlLabel
                control={
                  <Checkbox
                    checked={currentConfig?.requireDocumentVerification || false}
                    onChange={(e) => handleConfigChange('requireDocumentVerification', e.target.checked)}
                    data-testid="require-document-verification"
                  />
                }
                label="Require Document Verification"
              />
            </Paper>
          </Grid>

          {/* Renewal Settings */}
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3 }}>
              <Typography variant="h6" gutterBottom>
                Renewal Settings
              </Typography>

              <FormControlLabel
                control={
                  <Checkbox
                    checked={currentConfig?.allowRenewal || false}
                    onChange={(e) => handleConfigChange('allowRenewal', e.target.checked)}
                    data-testid="allow-renewal"
                  />
                }
                label="Allow Credential Renewal"
              />

              {currentConfig?.allowRenewal && (
                <TextField
                  fullWidth
                  type="number"
                  label="Renewal Window (days before expiry)"
                  value={currentConfig?.renewalWindowDays || 90}
                  onChange={(e) => handleConfigChange('renewalWindowDays', parseInt(e.target.value))}
                  sx={{ mt: 2 }}
                  inputProps={{ min: 7, max: 365 }}
                  data-testid="renewal-window-days"
                />
              )}
            </Paper>
          </Grid>

          {/* Processing Fee */}
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3 }}>
              <Typography variant="h6" gutterBottom>
                Processing Fee
              </Typography>

              <TextField
                fullWidth
                type="number"
                label="Processing Fee ($)"
                value={currentConfig?.processingFee || 0}
                onChange={(e) => handleConfigChange('processingFee', parseFloat(e.target.value))}
                inputProps={{ min: 0, step: 0.01 }}
                data-testid="processing-fee-input"
              />
            </Paper>
          </Grid>
        </Grid>

        <Box sx={{ mt: 3 }}>
          <Button
            variant="contained"
            startIcon={<SaveIcon />}
            onClick={handleSaveConfiguration}
            disabled={saving}
            data-testid="save-policy-btn"
          >
            {saving ? 'Saving...' : 'Save Policy'}
          </Button>
        </Box>
      </TabPanel>
    </Box>
  );
}

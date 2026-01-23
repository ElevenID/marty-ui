/**
 * Credential Configuration Manager
 *
 * Vendor component for configuring credential types that the organization
 * will offer to applicants (e.g., Travel Visa, Passport, Driver's License).
 */

import React, { useState, useEffect, useCallback } from 'react';
import {
  Box,
  Paper,
  Typography,
  Button,
  Chip,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  TextField,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  FormGroup,
  FormControlLabel,
  Checkbox,
  Alert,
  Snackbar,
  Skeleton,
  Switch,
  Stack,
  Divider,
  Card,
  CardContent,
  Grid,
} from '@mui/material';
import AddIcon from '@mui/icons-material/Add';
import EditIcon from '@mui/icons-material/Edit';
import DeleteIcon from '@mui/icons-material/Delete';
import VerifiedUserIcon from '@mui/icons-material/VerifiedUser';
import FlightIcon from '@mui/icons-material/Flight';
import BadgeIcon from '@mui/icons-material/Badge';
import DirectionsCarIcon from '@mui/icons-material/DirectionsCar';
import CreditCardIcon from '@mui/icons-material/CreditCard';
import RefreshIcon from '@mui/icons-material/Refresh';
import EmojiEventsIcon from '@mui/icons-material/EmojiEvents';
import { useAuth } from '../../hooks/useAuth';

// API base URL
const API_URL = process.env.REACT_APP_API_URL || '';

// Available credential types with icons
const CREDENTIAL_TYPES = [
  { id: 'travel_visa', label: 'Travel Visa', icon: <FlightIcon />, color: 'primary' },
  { id: 'passport', label: 'Passport', icon: <BadgeIcon />, color: 'secondary' },
  { id: 'drivers_license', label: "Driver's License", icon: <DirectionsCarIcon />, color: 'info' },
  { id: 'access_badge', label: 'Access Badge', icon: <CreditCardIcon />, color: 'warning' },
  { id: 'national_id', label: 'National ID', icon: <VerifiedUserIcon />, color: 'success' },
  { id: 'dtc', label: 'Digital Travel Credential', icon: <FlightIcon />, color: 'default' },
  { id: 'open_badge', label: 'Open Badge', icon: <EmojiEventsIcon />, color: 'info' },
];

/**
 * Get icon for credential type
 */
function getCredentialIcon(type) {
  const found = CREDENTIAL_TYPES.find(t => t.id === type);
  return found ? found.icon : <VerifiedUserIcon />;
}

/**
 * Get color for credential type
 */
function getCredentialColor(type) {
  const found = CREDENTIAL_TYPES.find(t => t.id === type);
  return found ? found.color : 'default';
}

function getCredentialLabel(type) {
  const found = CREDENTIAL_TYPES.find(t => t.id === type);
  return found ? found.label : type;
}

export default function CredentialConfigManager() {
  const { organizationId } = useAuth();
  const [configs, setConfigs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [snackbar, setSnackbar] = useState({ open: false, message: '', severity: 'success' });

  // Dialog state
  const [dialogOpen, setDialogOpen] = useState(false);
  const [editingConfig, setEditingConfig] = useState(null);
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false);
  const [configToDelete, setConfigToDelete] = useState(null);

  // Form state
  const [formData, setFormData] = useState({
    credential_type: '',
    display_name: '',
    validity_days: 365,
    required_fields: [],
    optional_fields: [],
    is_active: true,
  });
  const [availableFields, setAvailableFields] = useState({ required: [], optional: [] });
  const [loadingDefaults, setLoadingDefaults] = useState(false);

  /**
   * Fetch credential configurations
   */
  const fetchConfigs = useCallback(async () => {
    if (!organizationId) return;

    setLoading(true);
    setError(null);

    try {
      const response = await fetch(
        `${API_URL}/api/organizations/${organizationId}/credential-types`,
        {
          credentials: 'include',
        }
      );

      if (!response.ok) {
        throw new Error(`Failed to fetch configurations: ${response.status}`);
      }

      const data = await response.json();
      setConfigs(data.credential_types || []);
    } catch (err) {
      console.error('Error fetching credential configs:', err);
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }, [organizationId]);

  /**
   * Fetch default fields for a credential type
   */
  const fetchDefaultFields = async (credentialType) => {
    setLoadingDefaults(true);
    try {
      const response = await fetch(
        `${API_URL}/api/organizations/credential-types/defaults/${credentialType}`,
        {
          credentials: 'include',
        }
      );

      if (response.ok) {
        const data = await response.json();
        setAvailableFields({
          required: data.required_fields || [],
          optional: data.optional_fields || [],
        });
        // Pre-select defaults
        setFormData(prev => ({
          ...prev,
          required_fields: data.required_fields || [],
          optional_fields: [],
          display_name: prev.display_name || getCredentialLabel(credentialType),
        }));
      }
    } catch (err) {
      console.error('Error fetching default fields:', err);
    } finally {
      setLoadingDefaults(false);
    }
  };

  useEffect(() => {
    fetchConfigs();
  }, [fetchConfigs]);

  /**
   * Handle opening the create/edit dialog
   */
  const handleOpenDialog = (config = null) => {
    if (config) {
      // Edit mode
      setEditingConfig(config);
      setFormData({
        credential_type: config.credential_type,
        display_name: config.display_name,
        validity_days: config.validity_days,
        required_fields: config.required_fields || [],
        optional_fields: config.optional_fields || [],
        is_active: config.is_active,
      });
      // Fetch fields for this type
      fetchDefaultFields(config.credential_type);
    } else {
      // Create mode
      setEditingConfig(null);
      setFormData({
        credential_type: '',
        display_name: '',
        validity_days: 365,
        required_fields: [],
        optional_fields: [],
        is_active: true,
      });
      setAvailableFields({ required: [], optional: [] });
    }
    setDialogOpen(true);
  };

  const handleCloseDialog = () => {
    setDialogOpen(false);
    setEditingConfig(null);
    setFormData({
      credential_type: '',
      display_name: '',
      validity_days: 365,
      required_fields: [],
      optional_fields: [],
      is_active: true,
    });
  };

  /**
   * Handle credential type change
   */
  const handleTypeChange = (event) => {
    const type = event.target.value;
    setFormData(prev => ({ ...prev, credential_type: type }));
    if (type) {
      fetchDefaultFields(type);
    }
  };

  /**
   * Toggle a field in required/optional
   */
  const handleFieldToggle = (field, isRequired) => {
    const listKey = isRequired ? 'required_fields' : 'optional_fields';
    const currentList = formData[listKey];
    const newList = currentList.includes(field)
      ? currentList.filter(f => f !== field)
      : [...currentList, field];
    setFormData(prev => ({ ...prev, [listKey]: newList }));
  };

  /**
   * Submit the form
   */
  const handleSubmit = async () => {
    try {
      const url = editingConfig
        ? `${API_URL}/api/organizations/${organizationId}/credential-types/${editingConfig.id}`
        : `${API_URL}/api/organizations/${organizationId}/credential-types`;

      const method = editingConfig ? 'PUT' : 'POST';

      const response = await fetch(url, {
        method,
        headers: {
          'Content-Type': 'application/json',
        },
        credentials: 'include',
        body: JSON.stringify(formData),
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.detail || 'Failed to save configuration');
      }

      setSnackbar({
        open: true,
        message: editingConfig
          ? 'Credential configuration updated successfully'
          : 'Credential configuration created successfully',
        severity: 'success',
      });

      handleCloseDialog();
      fetchConfigs();
    } catch (err) {
      setSnackbar({
        open: true,
        message: err.message,
        severity: 'error',
      });
    }
  };

  /**
   * Handle delete
   */
  const handleDelete = async () => {
    if (!configToDelete) return;

    try {
      const response = await fetch(
        `${API_URL}/api/organizations/${organizationId}/credential-types/${configToDelete.id}`,
        {
          method: 'DELETE',
          credentials: 'include',
        }
      );

      if (!response.ok) {
        throw new Error('Failed to delete configuration');
      }

      setSnackbar({
        open: true,
        message: 'Credential configuration deleted',
        severity: 'success',
      });

      setDeleteDialogOpen(false);
      setConfigToDelete(null);
      fetchConfigs();
    } catch (err) {
      setSnackbar({
        open: true,
        message: err.message,
        severity: 'error',
      });
    }
  };

  /**
   * Toggle active status
   */
  const handleToggleActive = async (config) => {
    try {
      const response = await fetch(
        `${API_URL}/api/organizations/${organizationId}/credential-types/${config.id}`,
        {
          method: 'PUT',
          headers: {
            'Content-Type': 'application/json',
          },
          credentials: 'include',
          body: JSON.stringify({ is_active: !config.is_active }),
        }
      );

      if (!response.ok) {
        throw new Error('Failed to update configuration');
      }

      fetchConfigs();
    } catch (err) {
      setSnackbar({
        open: true,
        message: err.message,
        severity: 'error',
      });
    }
  };

  // Determine which types are already configured
  const configuredTypes = configs.map(c => c.credential_type);
  const availableTypes = CREDENTIAL_TYPES.filter(t => !configuredTypes.includes(t.id));

  if (loading) {
    return (
      <Box sx={{ p: 3 }} data-testid="credential-config-loading">
        <Typography variant="h4" gutterBottom>
          Credential Types
        </Typography>
        <Paper sx={{ p: 2, mt: 2 }}>
          {[1, 2, 3].map(i => (
            <Skeleton key={i} height={60} sx={{ mb: 1 }} />
          ))}
        </Paper>
      </Box>
    );
  }

  return (
    <Box sx={{ p: 3 }} data-testid="credential-config-manager">
      {/* Header */}
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
        <Box>
          <Typography variant="h4" component="h1" gutterBottom>
            Credential Types
          </Typography>
          <Typography variant="body1" color="textSecondary">
            Configure the types of credentials your organization will issue to applicants.
          </Typography>
        </Box>
        <Box>
          <Button
            startIcon={<RefreshIcon />}
            onClick={fetchConfigs}
            sx={{ mr: 1 }}
            data-testid="refresh-configs-btn"
          >
            Refresh
          </Button>
          <Button
            variant="contained"
            startIcon={<AddIcon />}
            onClick={() => handleOpenDialog()}
            disabled={availableTypes.length === 0}
            data-testid="add-credential-type-btn"
          >
            Add Credential Type
          </Button>
        </Box>
      </Box>

      {error && (
        <Alert severity="error" sx={{ mb: 2 }} data-testid="config-error">
          {error}
        </Alert>
      )}

      {/* Configurations List */}
      {configs.length === 0 ? (
        <Paper sx={{ p: 4, textAlign: 'center' }} data-testid="no-configs-message">
          <VerifiedUserIcon sx={{ fontSize: 64, color: 'text.secondary', mb: 2 }} />
          <Typography variant="h6" gutterBottom>
            No Credential Types Configured
          </Typography>
          <Typography variant="body2" color="textSecondary" sx={{ mb: 2 }}>
            Add credential types that your organization will offer to applicants.
          </Typography>
          <Button
            variant="contained"
            startIcon={<AddIcon />}
            onClick={() => handleOpenDialog()}
            data-testid="add-first-credential-btn"
          >
            Add Your First Credential Type
          </Button>
        </Paper>
      ) : (
        <Grid container spacing={3} data-testid="credential-configs-grid">
          {configs.map((config) => (
            <Grid item xs={12} md={6} lg={4} key={config.id}>
              <Card
                sx={{
                  height: '100%',
                  opacity: config.is_active ? 1 : 0.7,
                  position: 'relative',
                }}
                data-testid={`credential-config-card-${config.credential_type}`}
              >
                <CardContent>
                  <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', mb: 2 }}>
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                      <Box
                        sx={{
                          backgroundColor: `${getCredentialColor(config.credential_type)}.light`,
                          borderRadius: 1,
                          p: 1,
                          display: 'flex',
                        }}
                      >
                        {React.cloneElement(getCredentialIcon(config.credential_type), {
                          color: getCredentialColor(config.credential_type),
                        })}
                      </Box>
                      <Box>
                        <Typography variant="h6" component="div">
                          {config.display_name}
                        </Typography>
                        <Chip
                          label={config.credential_type.replace('_', ' ')}
                          size="small"
                          color={getCredentialColor(config.credential_type)}
                          variant="outlined"
                        />
                      </Box>
                    </Box>
                    <Switch
                      checked={config.is_active}
                      onChange={() => handleToggleActive(config)}
                      size="small"
                      data-testid={`toggle-active-${config.credential_type}`}
                    />
                  </Box>

                  <Divider sx={{ my: 1 }} />

                  <Typography variant="body2" color="textSecondary" gutterBottom>
                    Validity: {config.validity_days} days
                  </Typography>

                  <Typography variant="body2" color="textSecondary" gutterBottom>
                    Required Fields: {(config.required_fields || []).length}
                  </Typography>

                  <Typography variant="body2" color="textSecondary">
                    Optional Fields: {(config.optional_fields || []).length}
                  </Typography>

                  <Divider sx={{ my: 2 }} />

                  <Box sx={{ display: 'flex', gap: 1 }}>
                    <Button
                      size="small"
                      startIcon={<EditIcon />}
                      onClick={() => handleOpenDialog(config)}
                      data-testid={`edit-${config.credential_type}`}
                    >
                      Edit
                    </Button>
                    <Button
                      size="small"
                      color="error"
                      startIcon={<DeleteIcon />}
                      onClick={() => {
                        setConfigToDelete(config);
                        setDeleteDialogOpen(true);
                      }}
                      data-testid={`delete-${config.credential_type}`}
                    >
                      Delete
                    </Button>
                  </Box>
                </CardContent>
              </Card>
            </Grid>
          ))}
        </Grid>
      )}

      {/* Create/Edit Dialog */}
      <Dialog
        open={dialogOpen}
        onClose={handleCloseDialog}
        maxWidth="sm"
        fullWidth
        data-testid="credential-config-dialog"
      >
        <DialogTitle>
          {editingConfig ? 'Edit Credential Type' : 'Add Credential Type'}
        </DialogTitle>
        <DialogContent>
          <Stack spacing={3} sx={{ mt: 1 }}>
            <FormControl fullWidth disabled={!!editingConfig}>
              <InputLabel>Credential Type</InputLabel>
              <Select
                value={formData.credential_type}
                onChange={handleTypeChange}
                label="Credential Type"
                data-testid="credential-type-select"
              >
                {(editingConfig ? CREDENTIAL_TYPES : availableTypes).map((type) => (
                  <MenuItem key={type.id} value={type.id}>
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                      {type.icon}
                      {type.label}
                    </Box>
                  </MenuItem>
                ))}
              </Select>
            </FormControl>

            <TextField
              label="Display Name"
              value={formData.display_name}
              onChange={(e) => setFormData(prev => ({ ...prev, display_name: e.target.value }))}
              fullWidth
              required
              helperText="Name shown to applicants"
              data-testid="display-name-input"
            />

            <TextField
              label="Validity (days)"
              type="number"
              value={formData.validity_days}
              onChange={(e) => setFormData(prev => ({ ...prev, validity_days: parseInt(e.target.value) || 365 }))}
              fullWidth
              inputProps={{ min: 1, max: 3650 }}
              helperText="How long credentials are valid"
              data-testid="validity-days-input"
            />

            {loadingDefaults ? (
              <Skeleton height={100} />
            ) : formData.credential_type && (
              <>
                <Box>
                  <Typography variant="subtitle2" gutterBottom>
                    Required Fields
                  </Typography>
                  <FormGroup row>
                    {[...availableFields.required, ...availableFields.optional].map((field) => (
                      <FormControlLabel
                        key={field}
                        control={
                          <Checkbox
                            checked={formData.required_fields.includes(field)}
                            onChange={() => handleFieldToggle(field, true)}
                            size="small"
                          />
                        }
                        label={field.replace(/_/g, ' ')}
                      />
                    ))}
                  </FormGroup>
                </Box>

                <Box>
                  <Typography variant="subtitle2" gutterBottom>
                    Optional Fields
                  </Typography>
                  <FormGroup row>
                    {[...availableFields.required, ...availableFields.optional]
                      .filter(f => !formData.required_fields.includes(f))
                      .map((field) => (
                        <FormControlLabel
                          key={field}
                          control={
                            <Checkbox
                              checked={formData.optional_fields.includes(field)}
                              onChange={() => handleFieldToggle(field, false)}
                              size="small"
                            />
                          }
                          label={field.replace(/_/g, ' ')}
                        />
                      ))}
                  </FormGroup>
                </Box>
              </>
            )}

            <FormControlLabel
              control={
                <Switch
                  checked={formData.is_active}
                  onChange={(e) => setFormData(prev => ({ ...prev, is_active: e.target.checked }))}
                />
              }
              label="Active (available to applicants)"
              data-testid="is-active-switch"
            />
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={handleCloseDialog}>Cancel</Button>
          <Button
            variant="contained"
            onClick={handleSubmit}
            disabled={!formData.credential_type || !formData.display_name}
            data-testid="save-credential-config-btn"
          >
            {editingConfig ? 'Update' : 'Create'}
          </Button>
        </DialogActions>
      </Dialog>

      {/* Delete Confirmation Dialog */}
      <Dialog
        open={deleteDialogOpen}
        onClose={() => setDeleteDialogOpen(false)}
        data-testid="delete-confirm-dialog"
      >
        <DialogTitle>Delete Credential Type?</DialogTitle>
        <DialogContent>
          <Typography>
            Are you sure you want to delete the "{configToDelete?.display_name}" credential type?
            This action cannot be undone.
          </Typography>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setDeleteDialogOpen(false)}>Cancel</Button>
          <Button
            color="error"
            variant="contained"
            onClick={handleDelete}
            data-testid="confirm-delete-btn"
          >
            Delete
          </Button>
        </DialogActions>
      </Dialog>

      {/* Snackbar for notifications */}
      <Snackbar
        open={snackbar.open}
        autoHideDuration={6000}
        onClose={() => setSnackbar({ ...snackbar, open: false })}
        anchorOrigin={{ vertical: 'bottom', horizontal: 'right' }}
      >
        <Alert
          onClose={() => setSnackbar({ ...snackbar, open: false })}
          severity={snackbar.severity}
          variant="filled"
        >
          {snackbar.message}
        </Alert>
      </Snackbar>
    </Box>
  );
}

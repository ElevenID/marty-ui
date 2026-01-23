/**
 * API Key Manager
 *
 * Vendor component for managing API keys and their scopes.
 * Supports creating, viewing, revoking, and regenerating API keys.
 */

import React, { useState, useEffect, useCallback } from 'react';
import {
  Box,
  Paper,
  Typography,
  Button,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Chip,
  IconButton,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  TextField,
  FormControl,
  FormLabel,
  FormGroup,
  FormControlLabel,
  Checkbox,
  Alert,
  Snackbar,
  Tooltip,
  Menu,
  MenuItem,
  ListItemIcon,
  ListItemText,
  Skeleton,
  Switch,
  Stack,
} from '@mui/material';
import { DateTimePicker } from '@mui/x-date-pickers/DateTimePicker';
import { LocalizationProvider } from '@mui/x-date-pickers/LocalizationProvider';
import { AdapterDateFns } from '@mui/x-date-pickers/AdapterDateFns';
import AddIcon from '@mui/icons-material/Add';
import ContentCopyIcon from '@mui/icons-material/ContentCopy';
import DeleteIcon from '@mui/icons-material/Delete';
import MoreVertIcon from '@mui/icons-material/MoreVert';
import RefreshIcon from '@mui/icons-material/Refresh';
import VisibilityOffIcon from '@mui/icons-material/VisibilityOff';
import WarningIcon from '@mui/icons-material/Warning';
import { useAuth } from '../../hooks/useAuth';
import {
  listApiKeys,
  createApiKey,
  revokeApiKey,
  deleteApiKey,
  getErrorMessage,
} from '../../services/apiKeysApi';

// Available API key scopes
const API_SCOPES = [
  { id: 'read:credentials', label: 'Read Credentials', description: 'View credential data' },
  { id: 'write:credentials', label: 'Write Credentials', description: 'Issue and manage credentials' },
  { id: 'read:trust_registry', label: 'Read Trust Registry', description: 'Query trust registry' },
  { id: 'write:trust_registry', label: 'Write Trust Registry', description: 'Update trust registry entries' },
  { id: 'read:revocation', label: 'Read Revocation', description: 'Check revocation status' },
  { id: 'write:revocation', label: 'Write Revocation', description: 'Revoke credentials' },
  { id: 'manage:webhooks', label: 'Manage Webhooks', description: 'Configure webhook endpoints' },
  { id: 'verify:presentations', label: 'Verify Presentations', description: 'Verify credential presentations' },
];

/**
 * Format date for display
 */
function formatDate(dateString) {
  if (!dateString) return 'Never';
  return new Date(dateString).toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });
}

/**
 * Mask API key for display
 */
function maskApiKey(key, showFull = false) {
  if (showFull) return key;
  if (!key || key.length < 12) return '••••••••';
  return `${key.slice(0, 8)}••••••••${key.slice(-4)}`;
}

export default function APIKeyManager() {
  const { organizationId } = useAuth();
  const [apiKeys, setApiKeys] = useState([]);
  const [loading, setLoading] = useState(true);
  const [createDialogOpen, setCreateDialogOpen] = useState(false);
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false);
  const [selectedKey, setSelectedKey] = useState(null);
  const [newKeyVisible, setNewKeyVisible] = useState(null);
  const [snackbar, setSnackbar] = useState({ open: false, message: '', severity: 'success' });
  const [anchorEl, setAnchorEl] = useState(null);
  const [menuKeyId, setMenuKeyId] = useState(null);

  // Filter toggles
  const [showRevoked, setShowRevoked] = useState(false);
  const [showExpired, setShowExpired] = useState(false);

  // New key form state
  const [newKeyName, setNewKeyName] = useState('');
  const [newKeyScopes, setNewKeyScopes] = useState([]);
  const [newKeyExpiry, setNewKeyExpiry] = useState(null);

  // Fetch API keys
  const fetchApiKeys = useCallback(async () => {
    if (!organizationId) return;
    setLoading(true);
    try {
      const keys = await listApiKeys(organizationId, {
        includeRevoked: showRevoked,
        includeExpired: showExpired,
      });
      setApiKeys(keys);
    } catch (error) {
      console.error('Failed to fetch API keys:', error);
      setSnackbar({ open: true, message: getErrorMessage(error) || 'Failed to load API keys', severity: 'error' });
    } finally {
      setLoading(false);
    }
  }, [organizationId, showRevoked, showExpired]);

  // Fetch API keys on mount and when filters change
  useEffect(() => {
    fetchApiKeys();
  }, [fetchApiKeys]);

  const handleCreateKey = async () => {
    if (!newKeyName.trim()) {
      setSnackbar({ open: true, message: 'Please enter a key name', severity: 'warning' });
      return;
    }
    if (newKeyScopes.length === 0) {
      setSnackbar({ open: true, message: 'Please select at least one scope', severity: 'warning' });
      return;
    }

    try {
      const data = await createApiKey(organizationId, {
        name: newKeyName,
        scopes: newKeyScopes,
        expiresAt: newKeyExpiry ? new Date(newKeyExpiry).toISOString() : null,
      });

      // The response includes the full key only on creation (field name is 'key')
      const newKey = {
        ...data,
        full_key: data.key, // The plain text key returned only on creation
      };

      setApiKeys([newKey, ...apiKeys]);
      setNewKeyVisible(newKey);
      setCreateDialogOpen(false);
      resetForm();
      setSnackbar({ open: true, message: 'API key created successfully', severity: 'success' });
    } catch (error) {
      console.error('Failed to create API key:', error);
      setSnackbar({ open: true, message: getErrorMessage(error) || 'Failed to create API key', severity: 'error' });
    }
  };

  const handleDeleteKey = async () => {
    if (!selectedKey) return;

    try {
      await deleteApiKey(organizationId, selectedKey.id);

      setApiKeys(apiKeys.filter((k) => k.id !== selectedKey.id));
      setDeleteDialogOpen(false);
      setSelectedKey(null);
      setSnackbar({ open: true, message: 'API key deleted', severity: 'success' });
    } catch (error) {
      console.error('Failed to delete API key:', error);
      setSnackbar({ open: true, message: getErrorMessage(error) || 'Failed to delete API key', severity: 'error' });
    }
  };

  const handleRevokeKey = async (keyId) => {
    try {
      const updatedKey = await revokeApiKey(organizationId, keyId);
      setApiKeys(apiKeys.map((k) => (k.id === keyId ? updatedKey : k)));
      setSnackbar({ open: true, message: 'API key revoked', severity: 'success' });
    } catch (error) {
      console.error('Failed to revoke API key:', error);
      setSnackbar({ open: true, message: getErrorMessage(error) || 'Failed to revoke API key', severity: 'error' });
    }
  };

  const handleRegenerateKey = async (keyId) => {
    // Regenerate by deleting the old key and creating a new one with same settings
    const oldKey = apiKeys.find((k) => k.id === keyId);
    if (!oldKey) return;

    try {
      // Delete the old key
      await deleteApiKey(organizationId, keyId);

      // Create a new key with the same settings
      const data = await createApiKey(organizationId, {
        name: oldKey.name,
        scopes: oldKey.scopes,
        expiresAt: oldKey.expires_at,
      });

      const newKey = {
        ...data,
        full_key: data.key,
      };

      setApiKeys([newKey, ...apiKeys.filter((k) => k.id !== keyId)]);
      setNewKeyVisible(newKey);
      setSnackbar({ open: true, message: 'API key regenerated', severity: 'success' });
    } catch (error) {
      console.error('Failed to regenerate API key:', error);
      setSnackbar({ open: true, message: getErrorMessage(error) || 'Failed to regenerate API key', severity: 'error' });
    }
  };

  const handleCopyKey = async (key) => {
    try {
      if (navigator?.clipboard?.writeText) {
        await navigator.clipboard.writeText(key);
        setSnackbar({ open: true, message: 'API key copied to clipboard', severity: 'success' });
        return;
      }

      // Fallback for insecure contexts without navigator.clipboard.
      const textArea = document.createElement('textarea');
      textArea.value = key;
      textArea.setAttribute('readonly', '');
      textArea.style.position = 'absolute';
      textArea.style.left = '-9999px';
      document.body.appendChild(textArea);
      textArea.select();
      const success = document.execCommand('copy');
      document.body.removeChild(textArea);

      if (success) {
        setSnackbar({ open: true, message: 'API key copied to clipboard', severity: 'success' });
      } else {
        setSnackbar({ open: true, message: 'Copy not supported in this browser', severity: 'warning' });
      }
    } catch (error) {
      console.error('Failed to copy API key:', error);
      setSnackbar({ open: true, message: 'Failed to copy API key', severity: 'error' });
    }
  };

  const handleScopeChange = (scopeId) => {
    setNewKeyScopes((prev) =>
      prev.includes(scopeId) ? prev.filter((s) => s !== scopeId) : [...prev, scopeId]
    );
  };

  const resetForm = () => {
    setNewKeyName('');
    setNewKeyScopes([]);
    setNewKeyExpiry(null);
  };

  const handleMenuOpen = (event, keyId) => {
    setAnchorEl(event.currentTarget);
    setMenuKeyId(keyId);
  };

  const handleMenuClose = () => {
    setAnchorEl(null);
    setMenuKeyId(null);
  };

  return (
    <Box sx={{ p: 3 }}>
      {/* Header */}
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
        <Box>
          <Typography variant="h5" component="h1" gutterBottom>
            API Keys
          </Typography>
          <Typography variant="body2" color="textSecondary">
            Manage API keys for programmatic access to Marty services.
          </Typography>
        </Box>
        <Button
          variant="contained"
          startIcon={<AddIcon />}
          onClick={() => setCreateDialogOpen(true)}
        >
          Create API Key
        </Button>
      </Box>

      {/* Filter Controls */}
      <Stack direction="row" spacing={3} sx={{ mb: 2 }}>
        <FormControlLabel
          control={
            <Switch
              checked={showRevoked}
              onChange={(e) => setShowRevoked(e.target.checked)}
              size="small"
            />
          }
          label="Show revoked keys"
        />
        <FormControlLabel
          control={
            <Switch
              checked={showExpired}
              onChange={(e) => setShowExpired(e.target.checked)}
              size="small"
            />
          }
          label="Show expired keys"
        />
      </Stack>

      {/* New Key Alert */}
      {newKeyVisible && (
        <Alert
          severity="success"
          sx={{ mb: 3 }}
          action={
            <Button
              color="inherit"
              size="small"
              startIcon={<ContentCopyIcon />}
              onClick={() => handleCopyKey(newKeyVisible.full_key)}
            >
              Copy
            </Button>
          }
          onClose={() => setNewKeyVisible(null)}
        >
          <Typography variant="subtitle2">New API Key Created</Typography>
          <Typography variant="body2" sx={{ fontFamily: 'monospace', mt: 1 }}>
            {newKeyVisible.full_key}
          </Typography>
          <Typography variant="caption" color="warning.main" sx={{ display: 'flex', alignItems: 'center', mt: 1 }}>
            <WarningIcon fontSize="small" sx={{ mr: 0.5 }} />
            Save this key now. You won&apos;t be able to see it again!
          </Typography>
        </Alert>
      )}

      {/* API Keys Table */}
      <TableContainer component={Paper}>
        <Table>
          <TableHead>
            <TableRow>
              <TableCell>Name</TableCell>
              <TableCell>Key</TableCell>
              <TableCell>Scopes</TableCell>
              <TableCell>Created</TableCell>
              <TableCell>Last Used</TableCell>
              <TableCell>Expires</TableCell>
              <TableCell>Status</TableCell>
              <TableCell align="right">Actions</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {/* Loading Skeleton */}
            {loading && (
              <>
                {[1, 2, 3].map((n) => (
                  <TableRow key={`skeleton-${n}`}>
                    <TableCell><Skeleton variant="text" width={120} /></TableCell>
                    <TableCell><Skeleton variant="text" width={100} /></TableCell>
                    <TableCell><Skeleton variant="rectangular" width={80} height={24} /></TableCell>
                    <TableCell><Skeleton variant="text" width={100} /></TableCell>
                    <TableCell><Skeleton variant="text" width={100} /></TableCell>
                    <TableCell><Skeleton variant="text" width={100} /></TableCell>
                    <TableCell><Skeleton variant="rectangular" width={60} height={24} /></TableCell>
                    <TableCell align="right"><Skeleton variant="circular" width={24} height={24} /></TableCell>
                  </TableRow>
                ))}
              </>
            )}
            {/* Actual Data */}
            {!loading && apiKeys.map((apiKey) => (
              <TableRow key={apiKey.id} hover>
                <TableCell>
                  <Typography variant="body2" fontWeight="medium">
                    {apiKey.name}
                  </Typography>
                </TableCell>
                <TableCell>
                  <Typography variant="body2" fontFamily="monospace" color="textSecondary">
                    {maskApiKey(apiKey.key_prefix + '...')}
                  </Typography>
                </TableCell>
                <TableCell>
                  <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5 }}>
                    {apiKey.scopes.slice(0, 2).map((scope) => (
                      <Chip key={scope} label={scope.split(':')[1]} size="small" variant="outlined" />
                    ))}
                    {apiKey.scopes.length > 2 && (
                      <Tooltip title={apiKey.scopes.slice(2).join(', ')}>
                        <Chip label={`+${apiKey.scopes.length - 2}`} size="small" />
                      </Tooltip>
                    )}
                  </Box>
                </TableCell>
                <TableCell>
                  <Typography variant="body2" color="textSecondary">
                    {formatDate(apiKey.created_at)}
                  </Typography>
                </TableCell>
                <TableCell>
                  <Typography variant="body2" color="textSecondary">
                    {formatDate(apiKey.last_used_at)}
                  </Typography>
                </TableCell>
                <TableCell>
                  <Typography variant="body2" color={apiKey.expires_at ? 'warning.main' : 'textSecondary'}>
                    {apiKey.expires_at ? formatDate(apiKey.expires_at) : 'Never'}
                  </Typography>
                </TableCell>
                <TableCell>
                  <Chip
                    label={apiKey.is_active ? 'Active' : 'Revoked'}
                    color={apiKey.is_active ? 'success' : 'default'}
                    size="small"
                  />
                </TableCell>
                <TableCell align="right">
                  <IconButton
                    size="small"
                    onClick={(e) => handleMenuOpen(e, apiKey.id)}
                    aria-label="Key actions"
                    data-testid="key-actions-menu"
                  >
                    <MoreVertIcon />
                  </IconButton>
                </TableCell>
              </TableRow>
            ))}
            {apiKeys.length === 0 && !loading && (
              <TableRow>
                <TableCell colSpan={8} align="center" sx={{ py: 4 }}>
                  <Typography color="textSecondary">No API keys yet. Create one to get started.</Typography>
                </TableCell>
              </TableRow>
            )}
          </TableBody>
        </Table>
      </TableContainer>

      {/* Actions Menu */}
      <Menu anchorEl={anchorEl} open={Boolean(anchorEl)} onClose={handleMenuClose}>
        <MenuItem
          onClick={() => {
            handleRegenerateKey(menuKeyId);
            handleMenuClose();
          }}
        >
          <ListItemIcon>
            <RefreshIcon fontSize="small" />
          </ListItemIcon>
          <ListItemText>Regenerate</ListItemText>
        </MenuItem>
        <MenuItem
          onClick={() => {
            handleRevokeKey(menuKeyId);
            handleMenuClose();
          }}
          disabled={!apiKeys.find((k) => k.id === menuKeyId)?.is_active}
        >
          <ListItemIcon>
            <VisibilityOffIcon fontSize="small" />
          </ListItemIcon>
          <ListItemText>Revoke</ListItemText>
        </MenuItem>
        <MenuItem
          onClick={() => {
            const key = apiKeys.find((k) => k.id === menuKeyId);
            setSelectedKey(key);
            setDeleteDialogOpen(true);
            handleMenuClose();
          }}
          sx={{ color: 'error.main' }}
        >
          <ListItemIcon>
            <DeleteIcon fontSize="small" color="error" />
          </ListItemIcon>
          <ListItemText>Delete</ListItemText>
        </MenuItem>
      </Menu>

      {/* Create Dialog */}
      <Dialog open={createDialogOpen} onClose={() => setCreateDialogOpen(false)} maxWidth="sm" fullWidth>
        <DialogTitle>Create API Key</DialogTitle>
        <DialogContent>
          <TextField
            autoFocus
            margin="dense"
            label="Key Name"
            fullWidth
            variant="outlined"
            value={newKeyName}
            onChange={(e) => setNewKeyName(e.target.value)}
            placeholder="e.g., Production API Key"
            sx={{ mb: 3 }}
          />

          <FormControl component="fieldset" sx={{ mb: 3 }}>
            <FormLabel component="legend">Permissions</FormLabel>
            <FormGroup>
              {API_SCOPES.map((scope) => (
                <FormControlLabel
                  key={scope.id}
                  control={
                    <Checkbox
                      checked={newKeyScopes.includes(scope.id)}
                      onChange={() => handleScopeChange(scope.id)}
                    />
                  }
                  label={
                    <Box>
                      <Typography variant="body2">{scope.label}</Typography>
                      <Typography variant="caption" color="textSecondary">
                        {scope.description}
                      </Typography>
                    </Box>
                  }
                />
              ))}
            </FormGroup>
          </FormControl>

          <LocalizationProvider dateAdapter={AdapterDateFns}>
            <DateTimePicker
              label="Expiration Date (Optional)"
              value={newKeyExpiry}
              onChange={(newValue) => setNewKeyExpiry(newValue)}
              slotProps={{
                textField: {
                  fullWidth: true,
                  variant: 'outlined',
                  helperText: 'Leave empty for no expiration',
                },
              }}
              minDateTime={new Date()}
            />
          </LocalizationProvider>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setCreateDialogOpen(false)}>Cancel</Button>
          <Button onClick={handleCreateKey} variant="contained">
            Create Key
          </Button>
        </DialogActions>
      </Dialog>

      {/* Delete Confirmation Dialog */}
      <Dialog open={deleteDialogOpen} onClose={() => setDeleteDialogOpen(false)}>
        <DialogTitle>Delete API Key?</DialogTitle>
        <DialogContent>
          <Typography>
            Are you sure you want to delete &quot;{selectedKey?.name}&quot;? This action cannot be undone.
            Any applications using this key will lose access.
          </Typography>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setDeleteDialogOpen(false)}>Cancel</Button>
          <Button onClick={handleDeleteKey} color="error" variant="contained">
            Delete
          </Button>
        </DialogActions>
      </Dialog>

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

/**
 * API Key Manager
 *
 * Vendor component for managing API keys and their scopes.
 * Supports creating, viewing, revoking, and regenerating API keys.
 */

import { useState, useEffect, useCallback } from 'react';
import { useTranslation } from 'react-i18next';
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
import { useNotifications } from '../../hooks/useNotifications';
import { useDialog } from '../../hooks/useDialog';
import { ConfirmDeleteDialog } from '../common';
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
  const { t } = useTranslation('vendor');
  const { organizationId } = useAuth();
  const { showSuccess, showError, showWarning } = useNotifications();
  const createDialog = useDialog();
  const deleteDialog = useDialog();
  const [apiKeys, setApiKeys] = useState([]);
  const [loading, setLoading] = useState(true);
  const [newKeyVisible, setNewKeyVisible] = useState(null);
  const [anchorEl, setAnchorEl] = useState(null);
  const [menuKeyId, setMenuKeyId] = useState(null);

  // API Scopes (dynamic to access t)
  const API_SCOPES = [
    { id: 'read:credentials', label: t('apiKeyManager.scopes.readCredentials.label'), description: t('apiKeyManager.scopes.readCredentials.description') },
    { id: 'write:credentials', label: t('apiKeyManager.scopes.writeCredentials.label'), description: t('apiKeyManager.scopes.writeCredentials.description') },
    { id: 'read:trust_registry', label: t('apiKeyManager.scopes.readTrustRegistry.label'), description: t('apiKeyManager.scopes.readTrustRegistry.description') },
    { id: 'write:trust_registry', label: t('apiKeyManager.scopes.writeTrustRegistry.label'), description: t('apiKeyManager.scopes.writeTrustRegistry.description') },
    { id: 'read:revocation', label: t('apiKeyManager.scopes.readRevocation.label'), description: t('apiKeyManager.scopes.readRevocation.description') },
    { id: 'write:revocation', label: t('apiKeyManager.scopes.writeRevocation.label'), description: t('apiKeyManager.scopes.writeRevocation.description') },
    { id: 'manage:webhooks', label: t('apiKeyManager.scopes.manageWebhooks.label'), description: t('apiKeyManager.scopes.manageWebhooks.description') },
    { id: 'verify:presentations', label: t('apiKeyManager.scopes.verifyPresentations.label'), description: t('apiKeyManager.scopes.verifyPresentations.description') },
  ];

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
      showError(getErrorMessage(error) || 'Failed to load API keys');
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
      showWarning('Please enter a key name');
      return;
    }
    if (newKeyScopes.length === 0) {
      showWarning('Please select at least one scope');
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
      createDialog.close();
      resetForm();
      showSuccess(t('apiKeyManager.snackbars.createSuccess'));
    } catch (error) {
      console.error('Failed to create API key:', error);
      showError(getErrorMessage(error) || t('apiKeyManager.snackbars.createFailed'));
    }
  };

  const handleDeleteKey = async () => {
    const keyToDelete = deleteDialog.data;
    if (!keyToDelete) return;

    try {
      await deleteApiKey(organizationId, keyToDelete.id);

      setApiKeys(apiKeys.filter((k) => k.id !== keyToDelete.id));
      deleteDialog.close();
      showSuccess(t('apiKeyManager.snackbars.deleteSuccess'));
    } catch (error) {
      console.error('Failed to delete API key:', error);
      showError(getErrorMessage(error) || t('apiKeyManager.snackbars.deleteFailed'));
    }
  };

  const handleRevokeKey = async (keyId) => {
    try {
      const updatedKey = await revokeApiKey(organizationId, keyId);
      setApiKeys(apiKeys.map((k) => (k.id === keyId ? updatedKey : k)));
      showSuccess(t('apiKeyManager.snackbars.revokeSuccess'));
    } catch (error) {
      console.error('Failed to revoke API key:', error);
      showError(getErrorMessage(error) || t('apiKeyManager.snackbars.revokeFailed'));
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
      showSuccess(t('apiKeyManager.snackbars.regenerateSuccess'));
    } catch (error) {
      console.error('Failed to regenerate API key:', error);
      showError(getErrorMessage(error) || t('apiKeyManager.snackbars.regenerateFailed'));
    }
  };

  const handleCopyKey = async (key) => {
    try {
      if (navigator?.clipboard?.writeText) {
        await navigator.clipboard.writeText(key);
        showSuccess(t('apiKeyManager.snackbars.copiedToClipboard'));
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
        showSuccess(t('apiKeyManager.snackbars.copiedToClipboard'));
      } else {
        showWarning(t('apiKeyManager.snackbars.copyNotSupported'));
      }
    } catch (error) {
      console.error('Failed to copy API key:', error);
      showError(t('apiKeyManager.snackbars.copyFailed'));
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
            {t('apiKeyManager.title')}
          </Typography>
          <Typography variant="body2" color="textSecondary">
            {t('apiKeyManager.description')}
          </Typography>
        </Box>
        <Button
          variant="contained"
          startIcon={<AddIcon />}
          onClick={() => createDialog.open()}
        >
          {t('apiKeyManager.createButton')}
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
          label={t('apiKeyManager.filters.showRevoked')}
        />
        <FormControlLabel
          control={
            <Switch
              checked={showExpired}
              onChange={(e) => setShowExpired(e.target.checked)}
              size="small"
            />
          }
          label={t('apiKeyManager.filters.showExpired')}
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
              {t('apiKeyManager.newKeyAlert.copyButton')}
            </Button>
          }
          onClose={() => setNewKeyVisible(null)}
        >
          <Typography variant="subtitle2">{t('apiKeyManager.newKeyAlert.title')}</Typography>
          <Typography variant="body2" sx={{ fontFamily: 'monospace', mt: 1 }}>
            {newKeyVisible.full_key}
          </Typography>
          <Typography variant="caption" color="warning.main" sx={{ display: 'flex', alignItems: 'center', mt: 1 }}>
            <WarningIcon fontSize="small" sx={{ mr: 0.5 }} />
            {t('apiKeyManager.newKeyAlert.warning')}
          </Typography>
        </Alert>
      )}

      {/* API Keys Table */}
      <TableContainer component={Paper}>
        <Table>
          <TableHead>
            <TableRow>
              <TableCell>{t('apiKeyManager.table.name')}</TableCell>
              <TableCell>{t('apiKeyManager.table.key')}</TableCell>
              <TableCell>{t('apiKeyManager.table.scopes')}</TableCell>
              <TableCell>{t('apiKeyManager.table.created')}</TableCell>
              <TableCell>{t('apiKeyManager.table.lastUsed')}</TableCell>
              <TableCell>{t('apiKeyManager.table.expires')}</TableCell>
              <TableCell>{t('apiKeyManager.table.status')}</TableCell>
              <TableCell align="right">{t('apiKeyManager.table.actions')}</TableCell>
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
                    {formatDate(apiKey.created_at, t)}
                  </Typography>
                </TableCell>
                <TableCell>
                  <Typography variant="body2" color="textSecondary">
                    {formatDate(apiKey.last_used_at, t)}
                  </Typography>
                </TableCell>
                <TableCell>
                  <Typography variant="body2" color={apiKey.expires_at ? 'warning.main' : 'textSecondary'}>
                    {apiKey.expires_at ? formatDate(apiKey.expires_at, t) : t('apiKeyManager.table.never')}
                  </Typography>
                </TableCell>
                <TableCell>
                  <Chip
                    label={apiKey.is_active ? t('apiKeyManager.table.statusActive') : t('apiKeyManager.table.statusRevoked')}
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
                  <Typography color="textSecondary">{t('apiKeyManager.table.empty')}</Typography>
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
          <ListItemText>{t('apiKeyManager.menu.regenerate')}</ListItemText>
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
          <ListItemText>{t('apiKeyManager.menu.revoke')}</ListItemText>
        </MenuItem>
        <MenuItem
          onClick={() => {
            const key = apiKeys.find((k) => k.id === menuKeyId);
            deleteDialog.open(key);
            handleMenuClose();
          }}
          sx={{ color: 'error.main' }}
        >
          <ListItemIcon>
            <DeleteIcon fontSize="small" color="error" />
          </ListItemIcon>
          <ListItemText>{t('apiKeyManager.menu.delete')}</ListItemText>
        </MenuItem>
      </Menu>

      {/* Create Dialog */}
      <Dialog open={createDialog.isOpen} onClose={createDialog.close} maxWidth="sm" fullWidth>
        <DialogTitle>{t('apiKeyManager.createDialog.title')}</DialogTitle>
        <DialogContent>
          <TextField
            autoFocus
            margin="dense"
            label={t('apiKeyManager.createDialog.nameLabel')}
            fullWidth
            variant="outlined"
            value={newKeyName}
            onChange={(e) => setNewKeyName(e.target.value)}
            placeholder={t('apiKeyManager.createDialog.namePlaceholder')}
            sx={{ mb: 3 }}
          />

          <FormControl component="fieldset" sx={{ mb: 3 }}>
            <FormLabel component="legend">{t('apiKeyManager.createDialog.scopesLabel')}</FormLabel>
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
              label={t('apiKeyManager.createDialog.expiryLabel')}
              value={newKeyExpiry}
              onChange={(newValue) => setNewKeyExpiry(newValue)}
              slotProps={{
                textField: {
                  fullWidth: true,
                  variant: 'outlined',
                  helperText: t('apiKeyManager.createDialog.expiryHelper'),
                },
              }}
              minDateTime={new Date()}
            />
          </LocalizationProvider>
        </DialogContent>
        <DialogActions>
          <Button onClick={createDialog.close}>{t('apiKeyManager.createDialog.cancelButton')}</Button>
          <Button onClick={handleCreateKey} variant="contained">
            {t('apiKeyManager.createDialog.createButton')}
          </Button>
        </DialogActions>
      </Dialog>

      {/* Delete Confirmation Dialog */}
      <ConfirmDeleteDialog
        open={deleteDialog.isOpen}
        onClose={deleteDialog.close}
        onConfirm={handleDeleteKey}
        title={t('apiKeyManager.deleteDialog.title')}
        itemName={deleteDialog.data?.name}
      />
    </Box>
  );
}

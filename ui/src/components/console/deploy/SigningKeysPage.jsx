/**
 * Signing Keys Management Page
 * 
 * Manages cryptographic signing keys for credential issuance.
 * Features:
 * - List keys with status, expiry, algorithm
 * - Upload new keys
 * - Rotate keys
 * - Delete keys
 * - Configure HSM/Vault integration
 */

import React, { useState, useEffect } from 'react';
import { useTranslation } from 'react-i18next';
import {
  Box,
  Button,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
  IconButton,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  TextField,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Typography,
  Alert,
  Tooltip,
  Tabs,
  Tab,
  FormControlLabel,
  Switch,
} from '@mui/material';
import AddIcon from '@mui/icons-material/Add';
import RefreshIcon from '@mui/icons-material/Refresh';
import DeleteIcon from '@mui/icons-material/Delete';
import SettingsIcon from '@mui/icons-material/Settings';
import VpnKeyIcon from '@mui/icons-material/VpnKey';

import signingKeysApi from '../../../services/signingKeysApi';
import ResourcePage from '../../common/ResourcePage';
import EmptyState from '../../common/EmptyState';
import ErrorState from '../../common/ErrorState';
import StatusChip from '../../common/StatusChip';
import { TableSkeleton } from '../../common/skeletons';
import { PermissionButton } from '../../common/PermissionGate';
import { usePermissions } from '../../../hooks/usePermissions';
import { useNotifications } from '../../../hooks/useNotifications';

const getAlgorithms = (t) => [
  { value: 'ES256', label: t('deploy.signingKeys.algorithms.ES256') },
  { value: 'ES384', label: t('deploy.signingKeys.algorithms.ES384') },
  { value: 'RS256', label: t('deploy.signingKeys.algorithms.RS256') },
  { value: 'EdDSA', label: t('deploy.signingKeys.algorithms.EdDSA') },
];

const getKeyTypes = (t) => [
  { value: 'local', label: t('deploy.signingKeys.keyTypes.local') },
  { value: 'hsm', label: t('deploy.signingKeys.keyTypes.hsm') },
  { value: 'vault', label: t('deploy.signingKeys.keyTypes.vault') },
];

const getTabs = (t) => [
  { label: t('deploy.signingKeys.tabs.keys'), path: '/console/org/deploy/signing-keys' },
  { label: t('deploy.signingKeys.tabs.settings'), path: '/console/org/deploy/signing-keys/settings' },
];

const getBreadcrumbs = (t) => [
  { label: t('deploy.breadcrumbs.console'), path: '/console' },
  { label: t('deploy.breadcrumbs.deploy'), path: '/console/org/deploy' },
  { label: t('deploy.breadcrumbs.signingKeys'), path: '/console/org/deploy/signing-keys' },
];

export default function SigningKeysPage() {
  const { t } = useTranslation('console');
  const [keys, setKeys] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [uploadDialogOpen, setUploadDialogOpen] = useState(false);
  const [rotateDialogOpen, setRotateDialogOpen] = useState(false);
  const [settingsDialogOpen, setSettingsDialogOpen] = useState(false);
  const [selectedKey, setSelectedKey] = useState(null);
  const [currentTab, setCurrentTab] = useState(0);
  
  const [newKey, setNewKey] = useState({
    name: '',
    algorithm: 'ES256',
    public_key: '',
    key_type: 'local',
  });

  const [config, setConfig] = useState({
    hsm_enabled: false,
    hsm_settings: {},
    vault_enabled: false,
    vault_settings: {},
  });

  const { canCreate, canDelete, canExecute } = usePermissions();
  const { showNotification } = useNotifications();

  useEffect(() => {
    loadKeys();
    if (currentTab === 1) {
      loadConfig();
    }
  }, [currentTab]);

  const loadKeys = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await signingKeysApi.listSigningKeys();
      setKeys(Array.isArray(data) ? data : data.keys || []);
    } catch (err) {
      console.error('Failed to load signing keys:', err);
      setError(err);
    } finally {
      setLoading(false);
    }
  };

  const loadConfig = async () => {
    try {
      const data = await signingKeysApi.getKeyManagementConfig();
      setConfig(data);
    } catch (err) {
      console.error('Failed to load key management config:', err);
      showNotification?.(t('deploy.signingKeys.notifications.loadSettingsError'), 'error');
    }
  };

  const handleUploadKey = async () => {
    try {
      await signingKeysApi.createSigningKey(newKey);
      showNotification?.(t('deploy.signingKeys.notifications.uploadSuccess'), 'success');
      setUploadDialogOpen(false);
      setNewKey({
        name: '',
        algorithm: 'ES256',
        public_key: '',
        key_type: 'local',
      });
      loadKeys();
    } catch (err) {
      console.error('Failed to upload key:', err);
      showNotification?.(t('deploy.signingKeys.notifications.uploadError'), 'error');
    }
  };

  const handleRotateKey = async (immediate = false) => {
    if (!selectedKey) return;
    
    try {
      await signingKeysApi.rotateSigningKey(selectedKey.id, { immediate });
      showNotification?.(t('deploy.signingKeys.notifications.rotateSuccess'), 'success');
      setRotateDialogOpen(false);
      setSelectedKey(null);
      loadKeys();
    } catch (err) {
      console.error('Failed to rotate key:', err);
      showNotification?.(t('deploy.signingKeys.notifications.rotateError'), 'error');
    }
  };

  const handleDeleteKey = async (keyId) => {
    if (!window.confirm(t('deploy.signingKeys.deleteConfirmation'))) {
      return;
    }

    try {
      await signingKeysApi.deleteSigningKey(keyId);
      showNotification?.(t('deploy.signingKeys.notifications.deleteSuccess'), 'success');
      loadKeys();
    } catch (err) {
      console.error('Failed to delete key:', err);
      showNotification?.(t('deploy.signingKeys.notifications.deleteError'), 'error');
    }
  };

  const handleSaveConfig = async () => {
    try {
      await signingKeysApi.updateKeyManagementConfig(config);
      showNotification?.(t('deploy.signingKeys.notifications.settingsSaveSuccess'), 'success');
      setSettingsDialogOpen(false);
    } catch (err) {
      console.error('Failed to save config:', err);
      showNotification?.(t('deploy.signingKeys.notifications.settingsSaveError'), 'error');
    }
  };

  const getStatusColor = (status) => {
    switch (status) {
      case 'valid':
      case 'active':
        return 'success';
      case 'expired':
      case 'deprecated':
        return 'warning';
      case 'invalid':
      case 'revoked':
        return 'error';
      default:
        return 'default';
    }
  };

  const isExpiringSoon = (expiryDate) => {
    if (!expiryDate) return false;
    const now = new Date();
    const expiry = new Date(expiryDate);
    const daysUntilExpiry = (expiry - now) / (1000 * 60 * 60 * 24);
    return daysUntilExpiry <= 30 && daysUntilExpiry > 0;
  };

  return (
    <ResourcePage
      title={t('deploy.signingKeys.title')}
      description={t('deploy.signingKeys.description')}
      resourceName={t('deploy.signingKeys.resourceName')}
      tabs={getTabs(t)}
      breadcrumbs={getBreadcrumbs(t)}
      icon={<VpnKeyIcon />}
    >
      <Box>
        {/* Action buttons */}
        <Box sx={{ mb: 3, display: 'flex', gap: 2, justifyContent: 'flex-end' }}>
          <Button
            variant="outlined"
            startIcon={<SettingsIcon />}
            onClick={() => setSettingsDialogOpen(true)}
          >
            {t('deploy.signingKeys.hsmVaultSettings')}
          </Button>
          <PermissionButton
            resource="signing-key"
            action="create"
            variant="contained"
            startIcon={<AddIcon />}
            onClick={() => setUploadDialogOpen(true)}
          >
            {t('deploy.signingKeys.uploadKey')}
          </PermissionButton>
        </Box>

        {/* Content */}
        {loading ? (
          <TableSkeleton rows={5} columns={5} showActions={true} />
        ) : error ? (
          <ErrorState error={error} onRetry={loadKeys} variant="inline" />
        ) : keys.length === 0 ? (
          <EmptyState
            icon={VpnKeyIcon}
            title={t('deploy.signingKeys.emptyState.title')}
            description={t('deploy.signingKeys.emptyState.description')}
            whyItMatters={t('deploy.signingKeys.emptyState.whyItMatters')}
            actionLabel={t('deploy.signingKeys.emptyState.actionLabel')}
            onAction={() => setUploadDialogOpen(true)}
            docsUrl="https://docs.example.com/signing-keys"
          />
        ) : (
          <TableContainer component={Paper}>
            <Table>
              <TableHead>
                <TableRow>
                  <TableCell>{t('deploy.signingKeys.tableHeaders.keyId')}</TableCell>
                  <TableCell>{t('deploy.signingKeys.tableHeaders.name')}</TableCell>
                  <TableCell>{t('deploy.signingKeys.tableHeaders.algorithm')}</TableCell>
                  <TableCell>{t('deploy.signingKeys.tableHeaders.status')}</TableCell>
                  <TableCell>{t('deploy.signingKeys.tableHeaders.expiryDate')}</TableCell>
                  <TableCell>{t('deploy.signingKeys.tableHeaders.created')}</TableCell>
                  <TableCell align="right">{t('deploy.signingKeys.tableHeaders.actions')}</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {keys.map((key) => (
                  <TableRow key={key.id}>
                    <TableCell>
                      <Typography variant="body2" fontFamily="monospace">
                        {key.id.slice(0, 8)}...
                      </Typography>
                    </TableCell>
                    <TableCell>{key.name || t('deploy.signingKeys.unnamedKey')}</TableCell>
                    <TableCell>{key.algorithm}</TableCell>
                    <TableCell>
                      <StatusChip
                        status={key.status}
                        color={getStatusColor(key.status)}
                      />
                    </TableCell>
                    <TableCell>
                      {key.expiry_date ? (
                        <Box>
                          <Typography variant="body2">
                            {new Date(key.expiry_date).toLocaleDateString()}
                          </Typography>
                          {isExpiringSoon(key.expiry_date) && (
                            <Typography variant="caption" color="warning.main">
                              {t('deploy.signingKeys.expiringSoon')}
                            </Typography>
                          )}
                        </Box>
                      ) : (
                        '—'
                      )}
                    </TableCell>
                    <TableCell>
                      {new Date(key.created_at).toLocaleDateString()}
                    </TableCell>
                    <TableCell align="right">
                      <Box sx={{ display: 'flex', gap: 1, justifyContent: 'flex-end' }}>
                        {canExecute('signing-key') && key.status === 'active' && (
                          <Tooltip title={t('deploy.signingKeys.rotateKeyTooltip')}>
                            <IconButton
                              size="small"
                              onClick={() => {
                                setSelectedKey(key);
                                setRotateDialogOpen(true);
                              }}
                            >
                              <RefreshIcon fontSize="small" />
                            </IconButton>
                          </Tooltip>
                        )}
                        {canDelete('signing-key') && (
                          <Tooltip title={t('deploy.signingKeys.deleteKeyTooltip')}>
                            <IconButton
                              size="small"
                              color="error"
                              onClick={() => handleDeleteKey(key.id)}
                            >
                              <DeleteIcon fontSize="small" />
                            </IconButton>
                          </Tooltip>
                        )}
                      </Box>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        )}

        {/* Check for invalid keys warning */}
        {!loading && keys.some(k => k.status === 'invalid' || k.status === 'expired') && (
          <Alert severity="warning" sx={{ mt: 2 }}>
            {t('deploy.signingKeys.invalidKeysWarning')}
          </Alert>
        )}

        {/* Upload Key Dialog */}
        <Dialog open={uploadDialogOpen} onClose={() => setUploadDialogOpen(false)} maxWidth="sm" fullWidth>
          <DialogTitle>{t('deploy.signingKeys.uploadDialog.title')}</DialogTitle>
          <DialogContent>
            <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2, mt: 1 }}>
              <TextField
                label={t('deploy.signingKeys.uploadDialog.keyNameLabel')}
                value={newKey.name}
                onChange={(e) => setNewKey({ ...newKey, name: e.target.value })}
                fullWidth
                required
              />
              
              <FormControl fullWidth>
                <InputLabel>{t('deploy.signingKeys.uploadDialog.algorithmLabel')}</InputLabel>
                <Select
                  value={newKey.algorithm}
                  onChange={(e) => setNewKey({ ...newKey, algorithm: e.target.value })}
                  label={t('deploy.signingKeys.uploadDialog.algorithmLabel')}
                >
                  {getAlgorithms(t).map((algo) => (
                    <MenuItem key={algo.value} value={algo.value}>
                      {algo.label}
                    </MenuItem>
                  ))}
                </Select>
              </FormControl>

              <FormControl fullWidth>
                <InputLabel>{t('deploy.signingKeys.uploadDialog.keyTypeLabel')}</InputLabel>
                <Select
                  value={newKey.key_type}
                  onChange={(e) => setNewKey({ ...newKey, key_type: e.target.value })}
                  label={t('deploy.signingKeys.uploadDialog.keyTypeLabel')}
                >
                  {getKeyTypes(t).map((type) => (
                    <MenuItem key={type.value} value={type.value}>
                      {type.label}
                    </MenuItem>
                  ))}
                </Select>
              </FormControl>

              <TextField
                label={t('deploy.signingKeys.uploadDialog.publicKeyLabel')}
                value={newKey.public_key}
                onChange={(e) => setNewKey({ ...newKey, public_key: e.target.value })}
                fullWidth
                required
                multiline
                rows={8}
                placeholder={t('deploy.signingKeys.uploadDialog.publicKeyPlaceholder')}
                sx={{ fontFamily: 'monospace' }}
              />

              <Alert severity="info">
                {t('deploy.signingKeys.uploadDialog.infoMessage')}
              </Alert>
            </Box>
          </DialogContent>
          <DialogActions>
            <Button onClick={() => setUploadDialogOpen(false)}>{t('deploy.signingKeys.uploadDialog.cancel')}</Button>
            <Button
              onClick={handleUploadKey}
              variant="contained"
              disabled={!newKey.name || !newKey.public_key}
            >
              {t('deploy.signingKeys.uploadDialog.uploadButton')}
            </Button>
          </DialogActions>
        </Dialog>

        {/* Rotate Key Dialog */}
        <Dialog open={rotateDialogOpen} onClose={() => setRotateDialogOpen(false)} maxWidth="sm" fullWidth>
          <DialogTitle>{t('deploy.signingKeys.rotateDialog.title')}</DialogTitle>
          <DialogContent>
            <Box sx={{ mt: 1 }}>
              <Typography variant="body2" paragraph>
                {t('deploy.signingKeys.rotateDialog.description')}
              </Typography>
              
              {selectedKey && (
                <Alert severity="info" sx={{ mb: 2 }}>
                  <Typography variant="body2">
                    <strong>{t('deploy.signingKeys.rotateDialog.currentKeyLabel')}:</strong> {selectedKey.name || selectedKey.id}
                  </Typography>
                  <Typography variant="body2">
                    <strong>{t('deploy.signingKeys.rotateDialog.algorithmLabel')}:</strong> {selectedKey.algorithm}
                  </Typography>
                </Alert>
              )}

              <Typography variant="body2" color="text.secondary">
                {t('deploy.signingKeys.rotateDialog.strategyLabel')}
              </Typography>
            </Box>
          </DialogContent>
          <DialogActions>
            <Button onClick={() => setRotateDialogOpen(false)}>{t('deploy.signingKeys.rotateDialog.cancel')}</Button>
            <Button onClick={() => handleRotateKey(false)} variant="outlined">
              {t('deploy.signingKeys.rotateDialog.gradualRotation')}
            </Button>
            <Button onClick={() => handleRotateKey(true)} variant="contained" color="warning">
              {t('deploy.signingKeys.rotateDialog.immediateRotation')}
            </Button>
          </DialogActions>
        </Dialog>

        {/* HSM/Vault Settings Dialog */}
        <Dialog open={settingsDialogOpen} onClose={() => setSettingsDialogOpen(false)} maxWidth="md" fullWidth>
          <DialogTitle>{t('deploy.signingKeys.settingsDialog.title')}</DialogTitle>
          <DialogContent>
            <Box sx={{ display: 'flex', flexDirection: 'column', gap: 3, mt: 1 }}>
              {/* HSM Settings */}
              <Box>
                <FormControlLabel
                  control={
                    <Switch
                      checked={config.hsm_enabled}
                      onChange={(e) => setConfig({ ...config, hsm_enabled: e.target.checked })}
                    />
                  }
                  label={t('deploy.signingKeys.settingsDialog.hsmIntegrationLabel')}
                />
                {config.hsm_enabled && (
                  <Box sx={{ mt: 2, pl: 4 }}>
                    <Alert severity="info" sx={{ mb: 2 }}>
                      {t('deploy.signingKeys.settingsDialog.hsmConfigMessage')}
                    </Alert>
                    <Typography variant="body2" color="text.secondary">
                      {t('deploy.signingKeys.settingsDialog.hsmConfigPlaceholder')}
                    </Typography>
                  </Box>
                )}
              </Box>

              {/* Vault Settings */}
              <Box>
                <FormControlLabel
                  control={
                    <Switch
                      checked={config.vault_enabled}
                      onChange={(e) => setConfig({ ...config, vault_enabled: e.target.checked })}
                    />
                  }
                  label={t('deploy.signingKeys.settingsDialog.vaultIntegrationLabel')}
                />
                {config.vault_enabled && (
                  <Box sx={{ mt: 2, pl: 4 }}>
                    <Alert severity="info" sx={{ mb: 2 }}>
                      {t('deploy.signingKeys.settingsDialog.vaultConfigMessage')}
                    </Alert>
                    <Typography variant="body2" color="text.secondary">
                      {t('deploy.signingKeys.settingsDialog.vaultConfigPlaceholder')}
                    </Typography>
                  </Box>
                )}
              </Box>
            </Box>
          </DialogContent>
          <DialogActions>
            <Button onClick={() => setSettingsDialogOpen(false)}>{t('deploy.signingKeys.settingsDialog.cancel')}</Button>
            <Button onClick={handleSaveConfig} variant="contained">
              {t('deploy.signingKeys.settingsDialog.saveSettings')}
            </Button>
          </DialogActions>
        </Dialog>
      </Box>
    </ResourcePage>
  );
}

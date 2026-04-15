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
import { useAsyncData } from '../../../hooks/useAsyncData';
import { useDialog } from '../../../hooks/useDialog';

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
  const { data: signingKeysData, loading, error, reload: reloadKeys } = useAsyncData(async () => {
    const data = await signingKeysApi.listSigningKeys();
    const rawKeys = Array.isArray(data) ? data : data?.keys || [];
    if (!Array.isArray(rawKeys)) {
      return { keys: [], providerMetadata: null, domainConfig: null };
    }

    const normalizedKeys = rawKeys
      .filter((key) => key && typeof key === 'object')
      .map((key) => ({
        ...key,
        id: typeof key.id === 'string' && key.id.length > 0 ? key.id : 'unknown-key',
        name: typeof key.name === 'string' ? key.name : '',
        algorithm: typeof key.algorithm === 'string' ? key.algorithm : '-',
        status: typeof key.status === 'string' ? key.status : 'unknown',
        expiry_date: key.expiry_date ?? null,
        created_at: key.created_at ?? null,
      }));

    return {
      keys: normalizedKeys,
      providerMetadata: data?.provider_metadata || null,
      domainConfig: data?.domain_config || null,
    };
  }, []);
  const keys = Array.isArray(signingKeysData?.keys) ? signingKeysData.keys : [];
  const providerMetadata = signingKeysData?.providerMetadata || null;
  const domainConfig = signingKeysData?.domainConfig || null;
  const safeKeys = Array.isArray(keys) ? keys : [];
  const uploadDialog = useDialog();
  const rotateDialog = useDialog();
  const settingsDialog = useDialog();
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

  const { can } = usePermissions();
  const { showNotification } = useNotifications();
  const canManageSigningKeys = can('signing-key', 'create') && providerMetadata?.supports_upload !== false;
  const canDeleteSigningKeys = can('signing-key', 'delete') && providerMetadata?.supports_delete !== false;
  const canRotateSigningKeys = can('signing-key', 'create') && providerMetadata?.supports_rotation !== false;

  useEffect(() => {
    if (currentTab === 1) {
      loadConfig();
    }
  }, [currentTab]);

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
      uploadDialog.close();
      setNewKey({
        name: '',
        algorithm: 'ES256',
        public_key: '',
        key_type: 'local',
      });
      reloadKeys();
    } catch (err) {
      console.error('Failed to upload key:', err);
      showNotification?.(t('deploy.signingKeys.notifications.uploadError'), 'error');
    }
  };

  const handleRotateKey = async (immediate = false) => {
    const key = rotateDialog.data;
    if (!key) return;
    
    try {
      await signingKeysApi.rotateSigningKey(key.id, { immediate });
      showNotification?.(t('deploy.signingKeys.notifications.rotateSuccess'), 'success');
      rotateDialog.close();
      reloadKeys();
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
      reloadKeys();
    } catch (err) {
      console.error('Failed to delete key:', err);
      showNotification?.(t('deploy.signingKeys.notifications.deleteError'), 'error');
    }
  };

  const handleSaveConfig = async () => {
    try {
      await signingKeysApi.updateKeyManagementConfig(config);
      showNotification?.(t('deploy.signingKeys.notifications.settingsSaveSuccess'), 'success');
      settingsDialog.close();
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

  const formatDate = (value) => {
    if (!value) {
      return '-';
    }
    const parsed = new Date(value);
    if (Number.isNaN(parsed.getTime())) {
      return '-';
    }
    return parsed.toLocaleDateString();
  };

  return (
    <ResourcePage
      title={t('deploy.signingKeys.title')}
      description={t('deploy.signingKeys.description')}
      resourceName={t('deploy.signingKeys.resourceName')}
      tabs={getTabs(t)}
      breadcrumbs={getBreadcrumbs(t)}
      icon={<VpnKeyIcon />}
      pageTestId="deploy.signingKeys.page"
    >
      <Box>
        {/* Action buttons */}
        <Box sx={{ mb: 3, display: 'flex', gap: 2, justifyContent: 'flex-end' }}>
          <PermissionButton
            resource="signing-key"
            action="create"
            variant="outlined"
            startIcon={<SettingsIcon />}
            onClick={settingsDialog.open}
            data-testid="deploy.signingKeys.settings.action"
          >
            {t('deploy.signingKeys.hsmVaultSettings')}
          </PermissionButton>
          <PermissionButton
            resource="signing-key"
            action="create"
            variant="contained"
            startIcon={<AddIcon />}
            onClick={uploadDialog.open}
            data-testid="deploy.signingKeys.upload.action"
          >
            {t('deploy.signingKeys.uploadKey')}
          </PermissionButton>
        </Box>

        {/* Content */}
        {(providerMetadata || domainConfig) && (
          <Alert severity="info" sx={{ mb: 2 }}>
            <Typography variant="body2" sx={{ mb: 0.5 }}>
              Signing key source: {providerMetadata?.provider || 'unconfigured'} ({providerMetadata?.status || 'unknown'})
            </Typography>
            <Typography variant="body2" sx={{ mb: 0.5 }}>
              Marty domain: {domainConfig?.public_domain || '-'}
            </Typography>
            <Typography variant="body2">
              Issuer base URL: {domainConfig?.issuer_base_url || '-'}
            </Typography>
          </Alert>
        )}

        {loading ? (
          <TableSkeleton rows={5} columns={5} showActions={true} />
        ) : error ? (
          <ErrorState error={error} onRetry={reloadKeys} variant="inline" />
        ) : safeKeys.length === 0 ? (
          <EmptyState
            icon={VpnKeyIcon}
            title={t('deploy.signingKeys.emptyState.title')}
            description={t('deploy.signingKeys.emptyState.description')}
            whyItMatters={t('deploy.signingKeys.emptyState.whyItMatters')}
            actionLabel={t('deploy.signingKeys.emptyState.actionLabel')}
            onAction={canManageSigningKeys ? uploadDialog.open : undefined}
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
                {safeKeys.map((key) => (
                  <TableRow key={key.id}>
                    <TableCell>
                      <Typography variant="body2" fontFamily="monospace">
                        {String(key.id).slice(0, 8)}...
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
                            {formatDate(key.expiry_date)}
                          </Typography>
                          {isExpiringSoon(key.expiry_date) && (
                            <Typography variant="caption" color="warning.main">
                              {t('deploy.signingKeys.expiringSoon')}
                            </Typography>
                          )}
                        </Box>
                      ) : (
                        '-'
                      )}
                    </TableCell>
                    <TableCell>
                      {formatDate(key.created_at)}
                    </TableCell>
                    <TableCell align="right">
                      <Box sx={{ display: 'flex', gap: 1, justifyContent: 'flex-end' }}>
                        {canRotateSigningKeys && key.status === 'active' && (
                          <Tooltip title={t('deploy.signingKeys.rotateKeyTooltip')}>
                            <IconButton
                              size="small"
                              onClick={() => rotateDialog.open(key)}
                            >
                              <RefreshIcon fontSize="small" />
                            </IconButton>
                          </Tooltip>
                        )}
                        {canDeleteSigningKeys && (
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
        {!loading && safeKeys.some((k) => k.status === 'invalid' || k.status === 'expired') && (
          <Alert severity="warning" sx={{ mt: 2 }}>
            {t('deploy.signingKeys.invalidKeysWarning')}
          </Alert>
        )}

        {/* Upload Key Dialog */}
        <Dialog open={uploadDialog.isOpen} onClose={uploadDialog.close} maxWidth="sm" fullWidth>
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
            <Button onClick={uploadDialog.close}>{t('deploy.signingKeys.uploadDialog.cancel')}</Button>
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
        <Dialog open={rotateDialog.isOpen} onClose={rotateDialog.close} maxWidth="sm" fullWidth>
          <DialogTitle>{t('deploy.signingKeys.rotateDialog.title')}</DialogTitle>
          <DialogContent>
            <Box sx={{ mt: 1 }}>
              <Typography variant="body2" paragraph>
                {t('deploy.signingKeys.rotateDialog.description')}
              </Typography>
              
              {rotateDialog.data && (
                <Alert severity="info" sx={{ mb: 2 }}>
                  <Typography variant="body2">
                    <strong>{t('deploy.signingKeys.rotateDialog.currentKeyLabel')}:</strong> {rotateDialog.data.name || rotateDialog.data.id}
                  </Typography>
                  <Typography variant="body2">
                    <strong>{t('deploy.signingKeys.rotateDialog.algorithmLabel')}:</strong> {rotateDialog.data.algorithm}
                  </Typography>
                </Alert>
              )}

              <Typography variant="body2" color="text.secondary">
                {t('deploy.signingKeys.rotateDialog.strategyLabel')}
              </Typography>
            </Box>
          </DialogContent>
          <DialogActions>
            <Button onClick={rotateDialog.close}>{t('deploy.signingKeys.rotateDialog.cancel')}</Button>
            <Button onClick={() => handleRotateKey(false)} variant="outlined">
              {t('deploy.signingKeys.rotateDialog.gradualRotation')}
            </Button>
            <Button onClick={() => handleRotateKey(true)} variant="contained" color="warning">
              {t('deploy.signingKeys.rotateDialog.immediateRotation')}
            </Button>
          </DialogActions>
        </Dialog>

        {/* HSM/Vault Settings Dialog */}
        <Dialog open={settingsDialog.isOpen} onClose={settingsDialog.close} maxWidth="md" fullWidth>
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
            <Button onClick={settingsDialog.close}>{t('deploy.signingKeys.settingsDialog.cancel')}</Button>
            <Button onClick={handleSaveConfig} variant="contained">
              {t('deploy.signingKeys.settingsDialog.saveSettings')}
            </Button>
          </DialogActions>
        </Dialog>
      </Box>
    </ResourcePage>
  );
}

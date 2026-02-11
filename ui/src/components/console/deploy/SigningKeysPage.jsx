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

const ALGORITHMS = [
  { value: 'ES256', label: 'ES256 (ECDSA P-256)' },
  { value: 'ES384', label: 'ES384 (ECDSA P-384)' },
  { value: 'RS256', label: 'RS256 (RSA 2048)' },
  { value: 'EdDSA', label: 'EdDSA (Ed25519)' },
];

const KEY_TYPES = [
  { value: 'local', label: 'Local Key' },
  { value: 'hsm', label: 'HSM (Hardware Security Module)' },
  { value: 'vault', label: 'HashiCorp Vault' },
];

const TABS = [
  { label: 'Keys', path: '/console/deploy/signing-keys' },
  { label: 'Settings', path: '/console/deploy/signing-keys/settings' },
];

const BREADCRUMBS = [
  { label: 'Console', path: '/console' },
  { label: 'Deploy', path: '/console/deploy' },
  { label: 'Signing Keys', path: '/console/deploy/signing-keys' },
];

export default function SigningKeysPage() {
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
      showNotification?.('Failed to load settings', 'error');
    }
  };

  const handleUploadKey = async () => {
    try {
      await signingKeysApi.createSigningKey(newKey);
      showNotification?.('Signing key uploaded successfully', 'success');
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
      showNotification?.('Failed to upload signing key', 'error');
    }
  };

  const handleRotateKey = async (immediate = false) => {
    if (!selectedKey) return;
    
    try {
      await signingKeysApi.rotateSigningKey(selectedKey.id, { immediate });
      showNotification?.('Signing key rotated successfully', 'success');
      setRotateDialogOpen(false);
      setSelectedKey(null);
      loadKeys();
    } catch (err) {
      console.error('Failed to rotate key:', err);
      showNotification?.('Failed to rotate signing key', 'error');
    }
  };

  const handleDeleteKey = async (keyId) => {
    if (!window.confirm('Are you sure you want to delete this signing key? This action cannot be undone.')) {
      return;
    }

    try {
      await signingKeysApi.deleteSigningKey(keyId);
      showNotification?.('Signing key deleted successfully', 'success');
      loadKeys();
    } catch (err) {
      console.error('Failed to delete key:', err);
      showNotification?.('Failed to delete signing key', 'error');
    }
  };

  const handleSaveConfig = async () => {
    try {
      await signingKeysApi.updateKeyManagementConfig(config);
      showNotification?.('Settings saved successfully', 'success');
      setSettingsDialogOpen(false);
    } catch (err) {
      console.error('Failed to save config:', err);
      showNotification?.('Failed to save settings', 'error');
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
      title="Signing Keys"
      description="Manage cryptographic signing keys for credential issuance and verification"
      resourceName="Signing Keys"
      tabs={TABS}
      breadcrumbs={BREADCRUMBS}
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
            HSM/Vault Settings
          </Button>
          <PermissionButton
            resource="signing-key"
            action="create"
            variant="contained"
            startIcon={<AddIcon />}
            onClick={() => setUploadDialogOpen(true)}
          >
            Upload Key
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
            title="No signing keys configured"
            description="Signing keys are required to issue and verify credentials. Upload your first key to enable credential issuance."
            whyItMatters="Without valid signing keys, you cannot issue credentials or verify signatures."
            actionLabel="Upload Signing Key"
            onAction={() => setUploadDialogOpen(true)}
            docsUrl="https://docs.example.com/signing-keys"
          />
        ) : (
          <TableContainer component={Paper}>
            <Table>
              <TableHead>
                <TableRow>
                  <TableCell>Key ID</TableCell>
                  <TableCell>Name</TableCell>
                  <TableCell>Algorithm</TableCell>
                  <TableCell>Status</TableCell>
                  <TableCell>Expiry Date</TableCell>
                  <TableCell>Created</TableCell>
                  <TableCell align="right">Actions</TableCell>
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
                    <TableCell>{key.name || 'Unnamed Key'}</TableCell>
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
                              Expiring soon
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
                          <Tooltip title="Rotate key">
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
                          <Tooltip title="Delete key">
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
            You have invalid or expired signing keys. Credential issuance may be blocked until you rotate or upload valid keys.
          </Alert>
        )}

        {/* Upload Key Dialog */}
        <Dialog open={uploadDialogOpen} onClose={() => setUploadDialogOpen(false)} maxWidth="sm" fullWidth>
          <DialogTitle>Upload Signing Key</DialogTitle>
          <DialogContent>
            <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2, mt: 1 }}>
              <TextField
                label="Key Name"
                value={newKey.name}
                onChange={(e) => setNewKey({ ...newKey, name: e.target.value })}
                fullWidth
                required
              />
              
              <FormControl fullWidth>
                <InputLabel>Algorithm</InputLabel>
                <Select
                  value={newKey.algorithm}
                  onChange={(e) => setNewKey({ ...newKey, algorithm: e.target.value })}
                  label="Algorithm"
                >
                  {ALGORITHMS.map((algo) => (
                    <MenuItem key={algo.value} value={algo.value}>
                      {algo.label}
                    </MenuItem>
                  ))}
                </Select>
              </FormControl>

              <FormControl fullWidth>
                <InputLabel>Key Type</InputLabel>
                <Select
                  value={newKey.key_type}
                  onChange={(e) => setNewKey({ ...newKey, key_type: e.target.value })}
                  label="Key Type"
                >
                  {KEY_TYPES.map((type) => (
                    <MenuItem key={type.value} value={type.value}>
                      {type.label}
                    </MenuItem>
                  ))}
                </Select>
              </FormControl>

              <TextField
                label="Public Key (PEM format)"
                value={newKey.public_key}
                onChange={(e) => setNewKey({ ...newKey, public_key: e.target.value })}
                fullWidth
                required
                multiline
                rows={8}
                placeholder="-----BEGIN PUBLIC KEY-----&#10;...&#10;-----END PUBLIC KEY-----"
                sx={{ fontFamily: 'monospace' }}
              />

              <Alert severity="info">
                Store your private key securely. Only the public key is uploaded to the platform.
              </Alert>
            </Box>
          </DialogContent>
          <DialogActions>
            <Button onClick={() => setUploadDialogOpen(false)}>Cancel</Button>
            <Button
              onClick={handleUploadKey}
              variant="contained"
              disabled={!newKey.name || !newKey.public_key}
            >
              Upload Key
            </Button>
          </DialogActions>
        </Dialog>

        {/* Rotate Key Dialog */}
        <Dialog open={rotateDialogOpen} onClose={() => setRotateDialogOpen(false)} maxWidth="sm" fullWidth>
          <DialogTitle>Rotate Signing Key</DialogTitle>
          <DialogContent>
            <Box sx={{ mt: 1 }}>
              <Typography variant="body2" paragraph>
                Rotating a signing key will generate a new key and mark the current key as deprecated.
                The old key will remain valid for a grace period to avoid breaking existing credentials.
              </Typography>
              
              {selectedKey && (
                <Alert severity="info" sx={{ mb: 2 }}>
                  <Typography variant="body2">
                    <strong>Current Key:</strong> {selectedKey.name || selectedKey.id}
                  </Typography>
                  <Typography variant="body2">
                    <strong>Algorithm:</strong> {selectedKey.algorithm}
                  </Typography>
                </Alert>
              )}

              <Typography variant="body2" color="text.secondary">
                Choose rotation strategy:
              </Typography>
            </Box>
          </DialogContent>
          <DialogActions>
            <Button onClick={() => setRotateDialogOpen(false)}>Cancel</Button>
            <Button onClick={() => handleRotateKey(false)} variant="outlined">
              Gradual Rotation
            </Button>
            <Button onClick={() => handleRotateKey(true)} variant="contained" color="warning">
              Immediate Rotation
            </Button>
          </DialogActions>
        </Dialog>

        {/* HSM/Vault Settings Dialog */}
        <Dialog open={settingsDialogOpen} onClose={() => setSettingsDialogOpen(false)} maxWidth="md" fullWidth>
          <DialogTitle>Key Management Settings</DialogTitle>
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
                  label="Enable HSM Integration"
                />
                {config.hsm_enabled && (
                  <Box sx={{ mt: 2, pl: 4 }}>
                    <Alert severity="info" sx={{ mb: 2 }}>
                      Configure your Hardware Security Module connection settings here.
                    </Alert>
                    <Typography variant="body2" color="text.secondary">
                      HSM configuration options will be displayed here based on your HSM provider.
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
                  label="Enable HashiCorp Vault Integration"
                />
                {config.vault_enabled && (
                  <Box sx={{ mt: 2, pl: 4 }}>
                    <Alert severity="info" sx={{ mb: 2 }}>
                      Configure your HashiCorp Vault connection settings here.
                    </Alert>
                    <Typography variant="body2" color="text.secondary">
                      Vault configuration options will be displayed here.
                    </Typography>
                  </Box>
                )}
              </Box>
            </Box>
          </DialogContent>
          <DialogActions>
            <Button onClick={() => setSettingsDialogOpen(false)}>Cancel</Button>
            <Button onClick={handleSaveConfig} variant="contained">
              Save Settings
            </Button>
          </DialogActions>
        </Dialog>
      </Box>
    </ResourcePage>
  );
}

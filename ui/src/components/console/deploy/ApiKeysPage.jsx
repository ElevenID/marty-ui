/**
 * API Keys Page
 * 
 * Manages API keys for accessing identity services.
 */

import { useState } from 'react';
import { useAsyncData } from '../../../hooks/useAsyncData';
import {
  Box,
  Paper,
  Typography,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Chip,
  IconButton,
  Tooltip,
  Alert,
  LinearProgress,
  Button,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  TextField,
} from '@mui/material';
import ContentCopyIcon from '@mui/icons-material/ContentCopy';
import DeleteIcon from '@mui/icons-material/Delete';
import AddIcon from '@mui/icons-material/Add';
import { useTranslation } from 'react-i18next';
// import { Link } from 'react-router-dom';

import { ResourcePage } from '../../common';
import { useAuth } from '../../../hooks/useAuth';
import { listApiKeys, createApiKey, revokeApiKey } from '../../../services/apiKeysApi';

const getDeployTabs = (t) => [
  { label: t('deploy.deploymentProfiles'), path: '/console/org/deploy/profiles' },
  { label: t('deploy.apiKeys'), path: '/console/org/deploy/api-keys' },
  { label: t('deploy.lanesDevices'), path: '/console/org/deploy/lanes' },
  { label: t('deploy.webhooks'), path: '/console/org/deploy/webhooks' },
];

const getBreadcrumbs = (t) => [
  { label: t('deploy.breadcrumbs.console'), path: '/console' },
  { label: t('deploy.breadcrumbs.deploy'), path: '/console/org/deploy' },
  { label: t('deploy.breadcrumbs.apiKeys'), path: '/console/org/deploy/api-keys' },
];

function ApiKeysPage() {
  const { t } = useTranslation('console');
  const { organizationId } = useAuth();
  const { data: apiKeys = [], loading, error, reload } = useAsyncData(
    () => listApiKeys(organizationId),
    [organizationId]
  );
  const [createDialogOpen, setCreateDialogOpen] = useState(false);
  const [newKeyName, setNewKeyName] = useState('');
  const [createdKey, setCreatedKey] = useState(null);

  const handleCreateKey = async () => {
    try {
      const result = await createApiKey(organizationId, {
        name: newKeyName,
        scopes: [],
      });
      setCreatedKey(result);
      setNewKeyName('');
    } catch (err) {
      console.error('Failed to create API key:', err);
    }
  };

  const handleCopyKey = async (key) => {
    await navigator.clipboard.writeText(key);
  };

  return (
    <ResourcePage
      title={t('deploy.apiKeys')}
      description={t('deploy.apiKeysDescription')}
      tabs={getDeployTabs(t)}
      breadcrumbs={getBreadcrumbs(t)}
      actions={
        <Button
          variant="contained"
          startIcon={<AddIcon />}
          onClick={() => setCreateDialogOpen(true)}
        >
          {t('deploy.apiKeysPage.generateKey')}
        </Button>
      }
    >
      {error && (
        <Alert severity="error" sx={{ mb: 3 }}>
          {error?.message || String(error)}
        </Alert>
      )}

      {loading ? (
        <LinearProgress />
      ) : (
        <TableContainer component={Paper}>
          <Table>
            <TableHead>
              <TableRow>
                <TableCell>{t('deploy.apiKeysPage.tableHeaders.name')}</TableCell>
                <TableCell>{t('deploy.apiKeysPage.tableHeaders.keyPrefix')}</TableCell>
                <TableCell>{t('deploy.apiKeysPage.tableHeaders.scopes')}</TableCell>
                <TableCell>{t('deploy.apiKeysPage.tableHeaders.lastUsed')}</TableCell>
                <TableCell>{t('deploy.apiKeysPage.tableHeaders.created')}</TableCell>
                <TableCell>{t('deploy.apiKeysPage.tableHeaders.status')}</TableCell>
                <TableCell align="right">{t('deploy.apiKeysPage.tableHeaders.actions')}</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {apiKeys.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={7} align="center">
                    <Typography color="text.secondary" sx={{ py: 4 }}>
                      {t('deploy.apiKeysPage.empty')}
                    </Typography>
                  </TableCell>
                </TableRow>
              ) : (
                apiKeys.map((apiKey) => (
                  <TableRow key={apiKey.id} hover>
                    <TableCell>
                      <Typography variant="body2" fontWeight={500}>
                        {apiKey.name}
                      </Typography>
                    </TableCell>
                    <TableCell>
                      <Typography variant="body2" sx={{ fontFamily: 'monospace' }}>
                        {apiKey.keyPrefix}...
                      </Typography>
                    </TableCell>
                    <TableCell>
                      <Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>
                        {apiKey.scopes.slice(0, 2).map((scope) => (
                          <Chip key={scope} label={scope} size="small" variant="outlined" />
                        ))}
                        {apiKey.scopes.length > 2 && (
                          <Chip label={`+${apiKey.scopes.length - 2}`} size="small" />
                        )}
                      </Box>
                    </TableCell>
                    <TableCell>
                      {apiKey.lastUsed 
                        ? new Date(apiKey.lastUsed).toLocaleDateString()
                        : t('deploy.apiKeysPage.never')
                      }
                    </TableCell>
                    <TableCell>
                      {new Date(apiKey.createdAt).toLocaleDateString()}
                    </TableCell>
                    <TableCell>
                      <Chip 
                        label={apiKey.status === 'active' ? t('deploy.apiKeysPage.status.active') : t('deploy.apiKeysPage.status.revoked')} 
                        color={apiKey.status === 'active' ? 'success' : 'error'}
                        size="small" 
                      />
                    </TableCell>
                    <TableCell align="right">
                      <Tooltip title={t('deploy.apiKeysPage.actions.revokeKey')}>
                        <IconButton size="small" color="error" onClick={async () => {
                          await revokeApiKey(organizationId, apiKey.id);
                          reload();
                        }}>
                          <DeleteIcon fontSize="small" />
                        </IconButton>
                      </Tooltip>
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </TableContainer>
      )}

      {/* Create Key Dialog */}
      <Dialog 
        open={createDialogOpen} 
        onClose={() => {
          setCreateDialogOpen(false);
          setCreatedKey(null);
          setNewKeyName('');
        }}
        maxWidth="sm"
        fullWidth
      >
        <DialogTitle>
          {createdKey ? t('deploy.apiKeysPage.dialog.titleCreated') : t('deploy.apiKeysPage.dialog.titleCreate')}
        </DialogTitle>
        <DialogContent>
          {createdKey ? (
            <Box>
              <Alert severity="warning" sx={{ mb: 2 }}>
                {t('deploy.apiKeysPage.dialog.warning')}
              </Alert>
              <TextField
                fullWidth
                label={t('deploy.apiKeysPage.dialog.keyLabel')}
                value={createdKey.fullKey}
                InputProps={{
                  readOnly: true,
                  endAdornment: (
                    <IconButton onClick={() => handleCopyKey(createdKey.fullKey)}>
                      <ContentCopyIcon />
                    </IconButton>
                  ),
                  sx: { fontFamily: 'monospace' },
                }}
              />
            </Box>
          ) : (
            <TextField
              autoFocus
              margin="dense"
              label={t('deploy.apiKeysPage.dialog.nameLabel')}
              placeholder={t('deploy.apiKeysPage.dialog.namePlaceholder')}
              fullWidth
              value={newKeyName}
              onChange={(e) => setNewKeyName(e.target.value)}
            />
          )}
        </DialogContent>
        <DialogActions>
          {createdKey ? (
            <Button onClick={() => {
              setCreateDialogOpen(false);
              setCreatedKey(null);
            }}>
              {t('deploy.apiKeysPage.dialog.done')}
            </Button>
          ) : (
            <>
              <Button onClick={() => setCreateDialogOpen(false)}>{t('actions.cancel', { ns: 'common' })}</Button>
              <Button 
                variant="contained" 
                onClick={handleCreateKey}
                disabled={!newKeyName.trim()}
              >
                {t('deploy.apiKeysPage.dialog.generate')}
              </Button>
            </>
          )}
        </DialogActions>
      </Dialog>
    </ResourcePage>
  );
}

export default ApiKeysPage;

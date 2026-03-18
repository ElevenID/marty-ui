/**
 * Revocation Manager Component
 * 
 * Manages credential revocation operations:
 * - View active credentials
 * - Revoke individual credentials with reason codes
 * - Batch revocation via CSV upload
 * - View revocation history
 * - Manage status lists and CRL/OCSP updates
 * 
 * This component is embedded in the Trust Registry under the Revocations tab
 * because revocation is tied to the trust profile's revocation policy.
 */

import { useState, useEffect, useCallback } from 'react';
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
  TablePagination,
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
  Chip,
  Alert,
  CircularProgress,
  Stack,
  Tooltip,
  Tabs,
  Tab,
  InputAdornment,
} from '@mui/material';
import {
  Block as RevokeIcon,
  History as HistoryIcon,
  Upload as UploadIcon,
  Search as SearchIcon,
  Refresh as RefreshIcon,
  CheckCircle as ActiveIcon,
  Warning as WarningIcon,
} from '@mui/icons-material';
import { useAuth } from '../../hooks/useAuth';
import { useNotifications } from '../../hooks/useNotifications';
import {
  fetchIssuedCredentials,
  revokeCredential,
  batchRevokeCredentials,
  fetchRevocationHistory,
} from '../../application/vendor';

// Revocation reason codes (RFC 5280)
const REVOCATION_REASONS = [
  { value: 'unspecified', label: 'Unspecified' },
  { value: 'keyCompromise', label: 'Key Compromise' },
  { value: 'caCompromise', label: 'CA Compromise' },
  { value: 'affiliationChanged', label: 'Affiliation Changed' },
  { value: 'superseded', label: 'Superseded' },
  { value: 'cessationOfOperation', label: 'Cessation of Operation' },
  { value: 'certificateHold', label: 'Certificate Hold' },
  { value: 'privilegeWithdrawn', label: 'Privilege Withdrawn' },
  { value: 'aaCompromise', label: 'AA Compromise' },
];

/**
 * Tab Panel Component
 */
function TabPanel({ children, value, index }) {
  return (
    <div role="tabpanel" hidden={value !== index}>
      {value === index && <Box sx={{ py: 3 }}>{children}</Box>}
    </div>
  );
}

/**
 * Revoke Credential Dialog
 */
function RevokeDialog({ open, onClose, onRevoke, credential }) {
  const { t } = useTranslation('vendor');
  const [reason, setReason] = useState('unspecified');
  const [comments, setComments] = useState('');

  // Revocation reasons (dynamic to access t)
  const REVOCATION_REASONS = [
    { value: 'unspecified', label: t('revocationManager.reasons.unspecified') },
    { value: 'keyCompromise', label: t('revocationManager.reasons.keyCompromise') },
    { value: 'caCompromise', label: t('revocationManager.reasons.caCompromise') },
    { value: 'affiliationChanged', label: t('revocationManager.reasons.affiliationChanged') },
    { value: 'superseded', label: t('revocationManager.reasons.superseded') },
    { value: 'cessationOfOperation', label: t('revocationManager.reasons.cessationOfOperation') },
    { value: 'certificateHold', label: t('revocationManager.reasons.certificateHold') },
    { value: 'privilegeWithdrawn', label: t('revocationManager.reasons.privilegeWithdrawn') },
    { value: 'aaCompromise', label: t('revocationManager.reasons.aaCompromise') },
  ];

  const handleRevoke = () => {
    onRevoke(credential.id, reason, comments);
    setReason('unspecified');
    setComments('');
  };

  return (
    <Dialog open={open} onClose={onClose} maxWidth="sm" fullWidth>
      <DialogTitle>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          <WarningIcon color="warning" />
          Revoke Credential
        </Box>
      </DialogTitle>
      <DialogContent>
        <Stack spacing={3} sx={{ mt: 1 }}>
          <Alert severity="warning">
            This action will immediately revoke the credential. The holder will no longer be able to use it for
            verification.
          </Alert>

          <Box>
            <Typography variant="subtitle2" gutterBottom>
              Credential Details
            </Typography>
            <Typography variant="body2" color="text.secondary">
              ID: {credential?.id}
            </Typography>
            <Typography variant="body2" color="text.secondary">
              Type: {credential?.type}
            </Typography>
            <Typography variant="body2" color="text.secondary">
              Holder: {credential?.holder_email}
            </Typography>
          </Box>

          <FormControl fullWidth>
            <InputLabel>Revocation Reason</InputLabel>
            <Select value={reason} onChange={(e) => setReason(e.target.value)} label="Revocation Reason">
              {REVOCATION_REASONS.map((r) => (
                <MenuItem key={r.value} value={r.value}>
                  {r.label}
                </MenuItem>
              ))}
            </Select>
          </FormControl>

          <TextField
            fullWidth
            multiline
            rows={3}
            label="Comments (Optional)"
            value={comments}
            onChange={(e) => setComments(e.target.value)}
            helperText="Provide additional details about why this credential is being revoked"
          />
        </Stack>
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose}>Cancel</Button>
        <Button onClick={handleRevoke} color="error" variant="contained" startIcon={<RevokeIcon />}>
          Revoke Credential
        </Button>
      </DialogActions>
    </Dialog>
  );
}

/**
 * Batch Revocation Dialog
 */
function BatchRevokeDialog({ open, onClose, onBatchRevoke }) {
  const { t } = useTranslation('vendor');
  const [file, setFile] = useState(null);
  const [reason, setReason] = useState('unspecified');

  // Revocation reasons (dynamic to access t)
  const REVOCATION_REASONS = [
    { value: 'unspecified', label: t('revocationManager.reasons.unspecified') },
    { value: 'keyCompromise', label: t('revocationManager.reasons.keyCompromise') },
    { value: 'caCompromise', label: t('revocationManager.reasons.caCompromise') },
    { value: 'affiliationChanged', label: t('revocationManager.reasons.affiliationChanged') },
    { value: 'superseded', label: t('revocationManager.reasons.superseded') },
    { value: 'cessationOfOperation', label: t('revocationManager.reasons.cessationOfOperation') },
    { value: 'certificateHold', label: t('revocationManager.reasons.certificateHold') },
    { value: 'privilegeWithdrawn', label: t('revocationManager.reasons.privilegeWithdrawn') },
    { value: 'aaCompromise', label: t('revocationManager.reasons.aaCompromise') },
  ];

  const handleFileChange = (event) => {
    setFile(event.target.files[0]);
  };

  const handleSubmit = () => {
    if (file) {
      onBatchRevoke(file, reason);
      setFile(null);
    }
  };

  return (
    <Dialog open={open} onClose={onClose} maxWidth="sm" fullWidth>
      <DialogTitle>{t('revocationManager.batchTab.title')}</DialogTitle>
      <DialogContent>
        <Stack spacing={3} sx={{ mt: 1 }}>
          <Alert severity="info">
            {t('revocationManager.batchTab.instructions')}
          </Alert>

          <Box>
            <Typography variant="subtitle2" gutterBottom>
              {t('revocationManager.batchTab.csvFormatLabel')}
            </Typography>
            <Paper variant="outlined" sx={{ p: 1, bgcolor: 'grey.50', fontFamily: 'monospace', fontSize: 12 }}>
              credential_id
              <br />
              cred_abc123
              <br />
              cred_def456
              <br />
              cred_ghi789
            </Paper>
          </Box>

          <Button variant="outlined" component="label" startIcon={<UploadIcon />} fullWidth>
            {file ? file.name : t('revocationManager.batchTab.uploadButton')}
            <input type="file" accept=".csv" hidden onChange={handleFileChange} />
          </Button>

          <FormControl fullWidth>
            <InputLabel>{t('revocationManager.revokeDialog.reasonLabel')}</InputLabel>
            <Select value={reason} onChange={(e) => setReason(e.target.value)} label={t('revocationManager.revokeDialog.reasonLabel')}>
              {REVOCATION_REASONS.map((r) => (
                <MenuItem key={r.value} value={r.value}>
                  {r.label}
                </MenuItem>
              ))}
            </Select>
          </FormControl>
        </Stack>
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose}>{t('revocationManager.revokeDialog.cancelButton')}</Button>
        <Button
          onClick={handleSubmit}
          color="error"
          variant="contained"
          disabled={!file}
          startIcon={<RevokeIcon />}
        >
          {t('revocationManager.batchTab.revokeAllButton')}
        </Button>
      </DialogActions>
    </Dialog>
  );
}

/**
 * Active Credentials Tab
 */
function ActiveCredentialsTab({ organizationId }) {
  const { t } = useTranslation('vendor');
  const [credentials, setCredentials] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [page, setPage] = useState(0);
  const [rowsPerPage, setRowsPerPage] = useState(25);
  const [totalCount, setTotalCount] = useState(0);

  // Dialog state
  const [revokeDialogOpen, setRevokeDialogOpen] = useState(false);
  const [selectedCredential, setSelectedCredential] = useState(null);
  const [batchRevokeDialogOpen, setBatchRevokeDialogOpen] = useState(false);

  /**
   * Load active credentials
   */
  const loadCredentials = useCallback(async () => {
    setLoading(true);
    setError(null);

    try {
      const data = await fetchIssuedCredentials({
        organizationId,
        page: page + 1,
        perPage: rowsPerPage,
        searchQuery,
      });
      setCredentials(data.credentials || []);
      setTotalCount(data.total || 0);
    } catch (err) {
      console.error('Error loading credentials:', err);
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }, [organizationId, page, rowsPerPage, searchQuery]);

  useEffect(() => {
    loadCredentials();
  }, [loadCredentials]);

  /**
   * Handle revoke credential
   */
  const handleRevoke = async (credentialId, reason, comments) => {
    try {
      await revokeCredential({ credentialId, reason, comments });

      showSuccess(t('revocationManager.activeTab.snackbars.revokeSuccess'));

      setRevokeDialogOpen(false);
      setSelectedCredential(null);
      loadCredentials();
    } catch (err) {
      console.error('Error revoking credential:', err);
      showError(err.message);
    }
  };

  /**
   * Handle batch revoke
   */
  const handleBatchRevoke = async (file, reason) => {
    try {
      const data = await batchRevokeCredentials({ file, reason });
      showSuccess(t('revocationManager.activeTab.snackbars.batchSuccess', { count: data.count }));

      setBatchRevokeDialogOpen(false);
      loadCredentials();
    } catch (err) {
      console.error('Error batch revoking:', err);
      showError(err.message);
    }
  };

  return (
    <Box>
      {/* Controls */}
      <Stack direction="row" spacing={2} sx={{ mb: 3 }}>
        <TextField
          fullWidth
          placeholder={t('revocationManager.activeTab.searchPlaceholder')}
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          InputProps={{
            startAdornment: (
              <InputAdornment position="start">
                <SearchIcon />
              </InputAdornment>
            ),
          }}
        />
        <Button variant="outlined" startIcon={<RefreshIcon />} onClick={loadCredentials}>
          {t('revocationManager.activeTab.refreshButton')}
        </Button>
        <Button
          variant="outlined"
          color="error"
          startIcon={<UploadIcon />}
          onClick={() => setBatchRevokeDialogOpen(true)}
        >
          {t('revocationManager.activeTab.batchRevokeButton')}
        </Button>
      </Stack>

      {/* Error Alert */}
      {error && (
        <Alert severity="warning" sx={{ mb: 3 }} onClose={() => setError(null)}>
          {t('revocationManager.activeTab.loadFailed', { error })}
        </Alert>
      )}

      {/* Credentials Table */}
      <TableContainer component={Paper}>
        <Table>
          <TableHead>
            <TableRow>
              <TableCell>{t('revocationManager.activeTab.table.credentialId')}</TableCell>
              <TableCell>{t('revocationManager.activeTab.table.type')}</TableCell>
              <TableCell>{t('revocationManager.activeTab.table.holder')}</TableCell>
              <TableCell>{t('revocationManager.activeTab.table.issuedDate')}</TableCell>
              <TableCell>{t('revocationManager.activeTab.table.expiryDate')}</TableCell>
              <TableCell>{t('revocationManager.activeTab.table.status')}</TableCell>
              <TableCell align="right">{t('revocationManager.activeTab.table.actions')}</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {loading ? (
              <TableRow>
                <TableCell colSpan={7} align="center" sx={{ py: 8 }}>
                  <CircularProgress />
                </TableCell>
              </TableRow>
            ) : credentials.length === 0 ? (
              <TableRow>
                <TableCell colSpan={7} align="center" sx={{ py: 8 }}>
                  <Typography variant="body2" color="text.secondary">
                    {t('revocationManager.activeTab.empty')}
                  </Typography>
                </TableCell>
              </TableRow>
            ) : (
              credentials.map((cred) => (
                <TableRow key={cred.id} hover>
                  <TableCell>
                    <Typography variant="body2" sx={{ fontFamily: 'monospace', fontSize: 11 }}>
                      {cred.id}
                    </Typography>
                  </TableCell>
                  <TableCell>{cred.type}</TableCell>
                  <TableCell>{cred.holder_email}</TableCell>
                  <TableCell>{new Date(cred.issued_date).toLocaleDateString()}</TableCell>
                  <TableCell>{new Date(cred.expiry_date).toLocaleDateString()}</TableCell>
                  <TableCell>
                    <Chip icon={<ActiveIcon />} label={t('revocationManager.activeTab.table.statusActive')} color="success" size="small" />
                  </TableCell>
                  <TableCell align="right">
                    <Tooltip title={t('revocationManager.activeTab.revokeTooltip')}>
                      <IconButton
                        size="small"
                        color="error"
                        onClick={() => {
                          setSelectedCredential(cred);
                          setRevokeDialogOpen(true);
                        }}
                      >
                        <RevokeIcon fontSize="small" />
                      </IconButton>
                    </Tooltip>
                  </TableCell>
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
        <TablePagination
          component="div"
          count={totalCount}
          page={page}
          onPageChange={(e, newPage) => setPage(newPage)}
          rowsPerPage={rowsPerPage}
          onRowsPerPageChange={(e) => {
            setRowsPerPage(parseInt(e.target.value, 10));
            setPage(0);
          }}
          rowsPerPageOptions={[10, 25, 50, 100]}
        />
      </TableContainer>

      {/* Revoke Dialog */}
      <RevokeDialog
        open={revokeDialogOpen}
        onClose={() => setRevokeDialogOpen(false)}
        onRevoke={handleRevoke}
        credential={selectedCredential}
      />

      {/* Batch Revoke Dialog */}
      <BatchRevokeDialog
        open={batchRevokeDialogOpen}
        onClose={() => setBatchRevokeDialogOpen(false)}
        onBatchRevoke={handleBatchRevoke}
      />

    </Box>
  );
}

/**
 * Revocation History Tab
 */
function RevocationHistoryTab({ organizationId }) {
  const { t } = useTranslation('vendor');
  const [revocations, setRevocations] = useState([]);
  const [loading, setLoading] = useState(true);
  const [page, setPage] = useState(0);
  const [rowsPerPage, setRowsPerPage] = useState(25);

  useEffect(() => {
    if (!organizationId) return;
    setLoading(true);
    fetchRevocationHistory({ organizationId, limit: rowsPerPage, offset: page * rowsPerPage })
      .then((data) => setRevocations(data.revocations || data.items || []))
      .catch((err) => console.error('Failed to load revocation history:', err))
      .finally(() => setLoading(false));
  }, [organizationId, page, rowsPerPage]);

  return (
    <Box>
      <TableContainer component={Paper}>
        <Table>
          <TableHead>
            <TableRow>
              <TableCell>{t('revocationManager.historyTab.table.credentialId')}</TableCell>
              <TableCell>{t('revocationManager.historyTab.table.type')}</TableCell>
              <TableCell>{t('revocationManager.historyTab.table.revokedDate')}</TableCell>
              <TableCell>{t('revocationManager.historyTab.table.reason')}</TableCell>
              <TableCell>{t('revocationManager.historyTab.table.revokedBy')}</TableCell>
              <TableCell>{t('revocationManager.historyTab.table.comments')}</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {loading ? (
              <TableRow>
                <TableCell colSpan={6} align="center" sx={{ py: 8 }}>
                  <CircularProgress />
                </TableCell>
              </TableRow>
            ) : (
              revocations.map((rev) => (
                <TableRow key={rev.id} hover>
                  <TableCell>
                    <Typography variant="body2" sx={{ fontFamily: 'monospace', fontSize: 11 }}>
                      {rev.credential_id}
                    </Typography>
                  </TableCell>
                  <TableCell>{rev.type}</TableCell>
                  <TableCell>{new Date(rev.revoked_date).toLocaleDateString()}</TableCell>
                  <TableCell>
                    <Chip label={rev.reason} size="small" />
                  </TableCell>
                  <TableCell>{rev.revoked_by}</TableCell>
                  <TableCell>
                    <Typography variant="body2" noWrap>
                      {rev.comments || '-'}
                    </Typography>
                  </TableCell>
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
        <TablePagination
          component="div"
          count={50}
          page={page}
          onPageChange={(e, newPage) => setPage(newPage)}
          rowsPerPage={rowsPerPage}
          onRowsPerPageChange={(e) => setRowsPerPage(parseInt(e.target.value, 10))}
        />
      </TableContainer>
    </Box>
  );
}

/**
 * Main Revocation Manager Component
 */
export default function RevocationManager() {
  const { t } = useTranslation('vendor');
  const { organizationId } = useAuth();
  const { showSuccess, showError, showWarning } = useNotifications();
  const [currentTab, setCurrentTab] = useState(0);

  return (
    <Box>
      <Tabs value={currentTab} onChange={(e, v) => setCurrentTab(v)} sx={{ borderBottom: 1, borderColor: 'divider' }}>
        <Tab icon={<ActiveIcon />} iconPosition="start" label={t('revocationManager.tabs.active')} />
        <Tab icon={<HistoryIcon />} iconPosition="start" label={t('revocationManager.tabs.history')} />
      </Tabs>

      <TabPanel value={currentTab} index={0}>
        <ActiveCredentialsTab organizationId={organizationId} />
      </TabPanel>

      <TabPanel value={currentTab} index={1}>
        <RevocationHistoryTab organizationId={organizationId} />
      </TabPanel>
    </Box>
  );
}

/**
 * Generate mock credentials
 */
function generateMockCredentials() {
  const types = ['travel_visa', 'passport', 'drivers_license', 'access_badge'];
  return Array.from({ length: 25 }, (_, i) => ({
    id: `cred_${Math.random().toString(36).substring(2, 15)}`,
    type: types[i % types.length],
    holder_email: `user${i + 1}@example.com`,
    issued_date: new Date(Date.now() - i * 86400000).toISOString(),
    expiry_date: new Date(Date.now() + 90 * 86400000).toISOString(),
    status: 'active',
  }));
}

/**
 * Generate mock revocations
 */
function generateMockRevocations() {
  const reasons = ['keyCompromise', 'affiliationChanged', 'superseded'];
  return Array.from({ length: 10 }, (_, i) => ({
    id: `rev_${i}`,
    credential_id: `cred_${Math.random().toString(36).substring(2, 15)}`,
    type: 'travel_visa',
    revoked_date: new Date(Date.now() - i * 86400000).toISOString(),
    reason: reasons[i % reasons.length],
    revoked_by: 'admin@example.com',
    comments: i % 2 === 0 ? 'Holder requested revocation' : '',
  }));
}

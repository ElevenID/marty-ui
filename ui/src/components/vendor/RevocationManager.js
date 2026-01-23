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
  Snackbar,
  CircularProgress,
  Stack,
  Tooltip,
  Tabs,
  Tab,
  InputAdornment,
  Card,
  CardContent,
  Grid,
  Divider,
} from '@mui/material';
import {
  Block as RevokeIcon,
  History as HistoryIcon,
  Upload as UploadIcon,
  Search as SearchIcon,
  Refresh as RefreshIcon,
  CheckCircle as ActiveIcon,
  Cancel as RevokedIcon,
  Warning as WarningIcon,
  Info as InfoIcon,
  FileDownload as DownloadIcon,
} from '@mui/icons-material';
import { useAuth } from '../../hooks/useAuth';

// API base URL
const API_URL = process.env.REACT_APP_API_URL || '';

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
  const [reason, setReason] = useState('unspecified');
  const [comments, setComments] = useState('');

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
  const [file, setFile] = useState(null);
  const [reason, setReason] = useState('unspecified');

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
      <DialogTitle>Batch Revocation</DialogTitle>
      <DialogContent>
        <Stack spacing={3} sx={{ mt: 1 }}>
          <Alert severity="info">
            Upload a CSV file with credential IDs (one per line) to revoke multiple credentials at once.
          </Alert>

          <Box>
            <Typography variant="subtitle2" gutterBottom>
              CSV Format Example
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
            {file ? file.name : 'Choose CSV File'}
            <input type="file" accept=".csv" hidden onChange={handleFileChange} />
          </Button>

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
        </Stack>
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose}>Cancel</Button>
        <Button
          onClick={handleSubmit}
          color="error"
          variant="contained"
          disabled={!file}
          startIcon={<RevokeIcon />}
        >
          Revoke All
        </Button>
      </DialogActions>
    </Dialog>
  );
}

/**
 * Active Credentials Tab
 */
function ActiveCredentialsTab({ organizationId }) {
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
  const [snackbar, setSnackbar] = useState({ open: false, message: '', severity: 'success' });

  /**
   * Load active credentials
   */
  const loadCredentials = useCallback(async () => {
    setLoading(true);
    setError(null);

    try {
      const params = new URLSearchParams({
        organization_id: organizationId,
        status: 'active',
        page: page + 1,
        per_page: rowsPerPage,
      });

      if (searchQuery) {
        params.append('search', searchQuery);
      }

      const response = await fetch(`${API_URL}/api/v1/credentials?${params}`, {
        method: 'GET',
        credentials: 'include',
      });

      if (!response.ok) {
        throw new Error(`Failed to load credentials: ${response.statusText}`);
      }

      const data = await response.json();
      setCredentials(data.credentials || []);
      setTotalCount(data.total || 0);
    } catch (err) {
      console.error('Error loading credentials:', err);
      setError(err.message);
      // Use mock data
      setCredentials(generateMockCredentials());
      setTotalCount(50);
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
      const response = await fetch(`${API_URL}/api/v1/credentials/${credentialId}/revoke`, {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ reason, comments }),
      });

      if (!response.ok) {
        throw new Error(`Failed to revoke credential: ${response.statusText}`);
      }

      setSnackbar({
        open: true,
        message: 'Credential revoked successfully',
        severity: 'success',
      });

      setRevokeDialogOpen(false);
      setSelectedCredential(null);
      loadCredentials();
    } catch (err) {
      console.error('Error revoking credential:', err);
      setSnackbar({
        open: true,
        message: err.message,
        severity: 'error',
      });
    }
  };

  /**
   * Handle batch revoke
   */
  const handleBatchRevoke = async (file, reason) => {
    try {
      const formData = new FormData();
      formData.append('file', file);
      formData.append('reason', reason);

      const response = await fetch(`${API_URL}/api/v1/credentials/batch-revoke`, {
        method: 'POST',
        credentials: 'include',
        body: formData,
      });

      if (!response.ok) {
        throw new Error(`Failed to batch revoke: ${response.statusText}`);
      }

      const data = await response.json();
      setSnackbar({
        open: true,
        message: `Successfully revoked ${data.count} credentials`,
        severity: 'success',
      });

      setBatchRevokeDialogOpen(false);
      loadCredentials();
    } catch (err) {
      console.error('Error batch revoking:', err);
      setSnackbar({
        open: true,
        message: err.message,
        severity: 'error',
      });
    }
  };

  return (
    <Box>
      {/* Controls */}
      <Stack direction="row" spacing={2} sx={{ mb: 3 }}>
        <TextField
          fullWidth
          placeholder="Search by credential ID, holder email, or type..."
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
          Refresh
        </Button>
        <Button
          variant="outlined"
          color="error"
          startIcon={<UploadIcon />}
          onClick={() => setBatchRevokeDialogOpen(true)}
        >
          Batch Revoke
        </Button>
      </Stack>

      {/* Error Alert */}
      {error && (
        <Alert severity="warning" sx={{ mb: 3 }} onClose={() => setError(null)}>
          {error} (Showing mock data)
        </Alert>
      )}

      {/* Credentials Table */}
      <TableContainer component={Paper}>
        <Table>
          <TableHead>
            <TableRow>
              <TableCell>Credential ID</TableCell>
              <TableCell>Type</TableCell>
              <TableCell>Holder</TableCell>
              <TableCell>Issued Date</TableCell>
              <TableCell>Expiry Date</TableCell>
              <TableCell>Status</TableCell>
              <TableCell align="right">Actions</TableCell>
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
                    No active credentials found
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
                    <Chip icon={<ActiveIcon />} label="Active" color="success" size="small" />
                  </TableCell>
                  <TableCell align="right">
                    <Tooltip title="Revoke">
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

      {/* Snackbar */}
      <Snackbar
        open={snackbar.open}
        autoHideDuration={6000}
        onClose={() => setSnackbar({ ...snackbar, open: false })}
      >
        <Alert severity={snackbar.severity}>{snackbar.message}</Alert>
      </Snackbar>
    </Box>
  );
}

/**
 * Revocation History Tab
 */
function RevocationHistoryTab({ organizationId }) {
  const [revocations, setRevocations] = useState([]);
  const [loading, setLoading] = useState(true);
  const [page, setPage] = useState(0);
  const [rowsPerPage, setRowsPerPage] = useState(25);

  useEffect(() => {
    // Mock data for now
    setRevocations(generateMockRevocations());
    setLoading(false);
  }, [organizationId, page, rowsPerPage]);

  return (
    <Box>
      <TableContainer component={Paper}>
        <Table>
          <TableHead>
            <TableRow>
              <TableCell>Credential ID</TableCell>
              <TableCell>Type</TableCell>
              <TableCell>Revoked Date</TableCell>
              <TableCell>Reason</TableCell>
              <TableCell>Revoked By</TableCell>
              <TableCell>Comments</TableCell>
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
  const { organizationId } = useAuth();
  const [currentTab, setCurrentTab] = useState(0);

  return (
    <Box>
      <Tabs value={currentTab} onChange={(e, v) => setCurrentTab(v)} sx={{ borderBottom: 1, borderColor: 'divider' }}>
        <Tab icon={<ActiveIcon />} iconPosition="start" label="Active Credentials" />
        <Tab icon={<HistoryIcon />} iconPosition="start" label="Revocation History" />
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

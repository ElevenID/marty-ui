import { useState, useEffect } from 'react';
import { useDialog } from '../hooks/useDialog';
import { ConfirmDeleteDialog } from './common';
import {
  createCscaCertificate,
  deleteCscaCertificate,
  formatCscaDate,
  getCscaCertificateStatus,
  loadCscaCertificates,
} from '../application/admin';
import {
  Container,
  Paper,
  Typography,
  Box,
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
  Alert,
  CircularProgress,
  Grid,
  Divider
} from '@mui/material';
import {
  Security as SecurityIcon,
  Add as AddIcon,
  Delete as DeleteIcon,
  Visibility as ViewIcon,
  Refresh as RefreshIcon
} from '@mui/icons-material';

const CscaManager = () => {
  const [certificates, setCertificates] = useState([]);
  const [openDialog, setOpenDialog] = useState(false);
  const viewDialog = useDialog();
  const deleteDialog = useDialog();
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [success, setSuccess] = useState(null);
  
  // Form state
  const [subjectName, setSubjectName] = useState('');
  const [creating, setCreating] = useState(false);
  // deleting state removed — ConfirmDeleteDialog manages its own loading state

  const fetchCertificates = async () => {
    setLoading(true);
    setError(null);
    const result = await loadCscaCertificates();
    setCertificates(result.certificates);
    setError(result.error);
    setLoading(false);
  };

  useEffect(() => {
    fetchCertificates();
  }, []);

  const handleRefresh = () => {
    fetchCertificates();
  };

  const handleCreate = async () => {
    setCreating(true);
    const result = await createCscaCertificate({ subjectName });

    if (result.success) {
      setOpenDialog(false);
      setSubjectName('');
      await fetchCertificates();
    } else {
      setError(result.error);
    }

    setCreating(false);
  };

  const handleDelete = async () => {
    const result = await deleteCscaCertificate({
      certificate: deleteDialog.data,
    });

    if (!result.success) {
      setError(result.error);
      throw new Error(result.error);
    }

    setSuccess(result.successMessage);
    await fetchCertificates();
  };

  return (
    <Container maxWidth="lg">
      <Box sx={{ mb: 4, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <Box>
          <Typography variant="h4" component="h1" gutterBottom>
            <SecurityIcon sx={{ mr: 2, verticalAlign: 'middle' }} />
            CSCA Management
          </Typography>
          <Typography variant="subtitle1" color="text.secondary">
            Country Signing Certification Authority Management
          </Typography>
        </Box>
        <Button
          variant="contained"
          startIcon={<AddIcon />}
          onClick={() => setOpenDialog(true)}
        >
          Create Certificate
        </Button>
      </Box>

      {error && (
        <Alert severity="error" sx={{ mb: 2 }} onClose={() => setError(null)}>
          {error}
        </Alert>
      )}

      {success && (
        <Alert severity="success" sx={{ mb: 2 }} onClose={() => setSuccess(null)}>
          {success}
        </Alert>
      )}

      <Paper sx={{ width: '100%', mb: 2 }}>
        <Box sx={{ p: 2, display: 'flex', justifyContent: 'flex-end' }}>
          <IconButton onClick={handleRefresh} disabled={loading}>
            <RefreshIcon />
          </IconButton>
        </Box>
        <TableContainer>
          <Table>
            <TableHead>
              <TableRow>
                <TableCell>Subject</TableCell>
                <TableCell>Expiry Date</TableCell>
                <TableCell>Status</TableCell>
                <TableCell align="right">Actions</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {loading ? (
                <TableRow>
                  <TableCell colSpan={4} align="center">
                    <CircularProgress />
                  </TableCell>
                </TableRow>
              ) : certificates.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={4} align="center">
                    No certificates found
                  </TableCell>
                </TableRow>
              ) : (
                certificates.map((cert) => (
                  <TableRow key={cert.id}>
                    <TableCell>{cert.subject}</TableCell>
                    <TableCell>{cert.not_after}</TableCell>
                    <TableCell>
                      <Chip 
                        label={getCscaCertificateStatus(cert).label}
                        color={getCscaCertificateStatus(cert).color}
                        size="small"
                      />
                    </TableCell>
                    <TableCell align="right">
                      <IconButton size="small" onClick={() => viewDialog.open(cert)}><ViewIcon /></IconButton>
                      <IconButton size="small" color="error" onClick={() => deleteDialog.open(cert)}><DeleteIcon /></IconButton>
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </TableContainer>
      </Paper>

      <Dialog open={openDialog} onClose={() => setOpenDialog(false)} maxWidth="sm" fullWidth>
        <DialogTitle>Create New CSCA Certificate</DialogTitle>
        <DialogContent>
          <Box sx={{ mt: 2 }}>
            <TextField
              fullWidth
              label="Subject Name (CN)"
              margin="normal"
              value={subjectName}
              onChange={(e) => setSubjectName(e.target.value)}
              placeholder="e.g. C=US, O=Marty, CN=Marty Root CA"
            />
          </Box>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setOpenDialog(false)}>Cancel</Button>
          <Button 
            variant="contained" 
            onClick={handleCreate}
            disabled={!subjectName || creating}
          >
            {creating ? 'Creating...' : 'Create'}
          </Button>
        </DialogActions>
      </Dialog>

      {/* View Certificate Dialog */}
      <Dialog open={viewDialog.isOpen} onClose={viewDialog.close} maxWidth="sm" fullWidth>
        <DialogTitle>
          <Box display="flex" alignItems="center">
            <SecurityIcon sx={{ mr: 1 }} />
            Certificate Details
          </Box>
        </DialogTitle>
        <DialogContent>
          {viewDialog.data && (
            <Box>
              <Divider sx={{ my: 2 }} />
              <Grid container spacing={2}>
                <Grid item xs={12}>
                  <Typography variant="caption" color="text.secondary">ID</Typography>
                  <Typography fontFamily="monospace">{viewDialog.data.id}</Typography>
                </Grid>
                <Grid item xs={12}>
                  <Typography variant="caption" color="text.secondary">Subject</Typography>
                  <Typography>{viewDialog.data.subject}</Typography>
                </Grid>
                <Grid item xs={12}>
                  <Typography variant="caption" color="text.secondary">Issuer</Typography>
                  <Typography>{viewDialog.data.issuer || viewDialog.data.subject}</Typography>
                </Grid>
                <Grid item xs={6}>
                  <Typography variant="caption" color="text.secondary">Not Before</Typography>
                  <Typography>{formatCscaDate(viewDialog.data.not_before)}</Typography>
                </Grid>
                <Grid item xs={6}>
                  <Typography variant="caption" color="text.secondary">Not After</Typography>
                  <Typography>{formatCscaDate(viewDialog.data.not_after)}</Typography>
                </Grid>
                <Grid item xs={12}>
                  <Typography variant="caption" color="text.secondary">Serial Number</Typography>
                  <Typography fontFamily="monospace">{viewDialog.data.serial_number || 'N/A'}</Typography>
                </Grid>
                <Grid item xs={12}>
                  <Typography variant="caption" color="text.secondary">Status</Typography>
                  <Box sx={{ mt: 0.5 }}>
                    <Chip 
                      label={getCscaCertificateStatus(viewDialog.data).label}
                      color={getCscaCertificateStatus(viewDialog.data).color}
                    />
                  </Box>
                </Grid>
              </Grid>
            </Box>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={viewDialog.close}>Close</Button>
        </DialogActions>
      </Dialog>

      <ConfirmDeleteDialog
        open={deleteDialog.isOpen}
        onClose={deleteDialog.close}
        onConfirm={handleDelete}
        title="Confirm Delete"
        itemName={deleteDialog.data?.subject}
      />
    </Container>
  );
};

export default CscaManager;

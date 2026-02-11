/**
 * My Credentials Page
 * 
 * View issued credentials for applicant.
 */

import { useState, useEffect } from 'react';
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
} from '@mui/material';
import VisibilityIcon from '@mui/icons-material/Visibility';
import DownloadIcon from '@mui/icons-material/Download';
import QrCodeIcon from '@mui/icons-material/QrCode';

import { getMyCredentials } from '../../../services/applicantApi';

function MyCredentialsPage() {
  const [credentials, setCredentials] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    const loadCredentials = async () => {
      try {
        const result = await getMyCredentials();
        const creds = (result.credentials || result.documents || []).map(doc => ({
          id: doc.id,
          type: doc.document_type || doc.credential_type || 'Credential',
          issuer: doc.issuing_authority || doc.issuer || 'Issuer',
          issuedAt: doc.issued_at || doc.created_at,
          expiresAt: doc.expiry_date || doc.valid_until,
          status: doc.status?.toLowerCase() || 'active',
        }));
        setCredentials(creds);
      } catch (err) {
        console.error('Error loading credentials:', err);
        setError('Failed to load credentials');
      } finally {
        setLoading(false);
      }
    };
    loadCredentials();
  }, []);

  const getStatusColor = (status) => {
    switch (status) {
      case 'active':
        return 'success';
      case 'expired':
        return 'error';
      case 'revoked':
        return 'error';
      default:
        return 'default';
    }
  };

  return (
    <Box>
      <Typography variant="h4" gutterBottom>
        My Credentials
      </Typography>
      <Typography variant="body1" color="text.secondary" paragraph>
        Your issued digital credentials and their status.
      </Typography>

      {error && (
        <Alert severity="error" sx={{ mb: 3 }}>
          {error}
        </Alert>
      )}

      {loading ? (
        <LinearProgress />
      ) : (
        <TableContainer component={Paper}>
          <Table>
            <TableHead>
              <TableRow>
                <TableCell>Credential Type</TableCell>
                <TableCell>Issuer</TableCell>
                <TableCell>Issued Date</TableCell>
                <TableCell>Expires</TableCell>
                <TableCell>Status</TableCell>
                <TableCell align="right">Actions</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {credentials.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={6} align="center">
                    <Typography color="text.secondary" sx={{ py: 4 }}>
                      No credentials yet. Apply for a credential to get started.
                    </Typography>
                    <Button variant="contained" href="/credentials">
                      Browse Credentials
                    </Button>
                  </TableCell>
                </TableRow>
              ) : (
                credentials.map((cred) => (
                  <TableRow key={cred.id} hover>
                    <TableCell>
                      <Typography fontWeight={500}>{cred.type}</Typography>
                    </TableCell>
                    <TableCell>{cred.issuer}</TableCell>
                    <TableCell>
                      {new Date(cred.issuedAt).toLocaleDateString()}
                    </TableCell>
                    <TableCell>
                      {new Date(cred.expiresAt).toLocaleDateString()}
                    </TableCell>
                    <TableCell>
                      <Chip
                        label={cred.status}
                        color={getStatusColor(cred.status)}
                        size="small"
                      />
                    </TableCell>
                    <TableCell align="right">
                      <Tooltip title="View Details">
                        <IconButton size="small">
                          <VisibilityIcon fontSize="small" />
                        </IconButton>
                      </Tooltip>
                      <Tooltip title="Show QR Code">
                        <IconButton size="small" color="primary">
                          <QrCodeIcon fontSize="small" />
                        </IconButton>
                      </Tooltip>
                      <Tooltip title="Download">
                        <IconButton size="small">
                          <DownloadIcon fontSize="small" />
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
    </Box>
  );
}

export default MyCredentialsPage;

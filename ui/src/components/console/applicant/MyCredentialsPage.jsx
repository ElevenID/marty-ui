/**
 * My Credentials Page
 * 
 * View issued credentials for applicant.
 */

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
} from '@mui/material';
import { useTranslation } from 'react-i18next';
import VisibilityIcon from '@mui/icons-material/Visibility';
import DownloadIcon from '@mui/icons-material/Download';
import QrCodeIcon from '@mui/icons-material/QrCode';

import { getMyCredentials } from '../../../services/applicantApi';

function MyCredentialsPage() {
  const { t } = useTranslation('applicant');
  const { data: credentials = [], loading, error } = useAsyncData(async () => {
    const result = await getMyCredentials();
    return (result.credentials || result.documents || []).map(doc => ({
      id: doc.id,
      type: doc.document_type || doc.credential_type || 'Credential',
      issuer: doc.issuing_authority || doc.issuer || 'Issuer',
      issuedAt: doc.issued_at || doc.created_at,
      expiresAt: doc.expiry_date || doc.valid_until,
      status: doc.status?.toLowerCase() || 'active',
    }));
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
        {t('credentials.title')}
      </Typography>
      <Typography variant="body1" color="text.secondary" paragraph>
        {t('credentials.description')}
      </Typography>

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
                <TableCell>{t('credentials.tableHeaders.credentialType')}</TableCell>
                <TableCell>{t('credentials.tableHeaders.issuer')}</TableCell>
                <TableCell>{t('credentials.tableHeaders.issuedDate')}</TableCell>
                <TableCell>{t('credentials.tableHeaders.expires')}</TableCell>
                <TableCell>{t('credentials.tableHeaders.status')}</TableCell>
                <TableCell align="right">{t('credentials.tableHeaders.actions')}</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {credentials.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={6} align="center">
                    <Typography color="text.secondary" sx={{ py: 4 }}>
                      {t('credentials.empty.message')}
                    </Typography>
                    <Button variant="contained" href="/console/applicant/catalog">
                      {t('credentials.empty.browseButton')}
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
                      <Tooltip title={t('credentials.actions.viewDetails')}>
                        <IconButton size="small">
                          <VisibilityIcon fontSize="small" />
                        </IconButton>
                      </Tooltip>
                      <Tooltip title={t('credentials.actions.showQRCode')}>
                        <IconButton size="small" color="primary">
                          <QrCodeIcon fontSize="small" />
                        </IconButton>
                      </Tooltip>
                      <Tooltip title={t('credentials.actions.download')}>
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

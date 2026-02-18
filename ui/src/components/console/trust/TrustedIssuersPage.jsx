/**
 * Trusted Issuers Page
 * 
 * Manages trusted issuers across all trust profiles.
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
  TextField,
  InputAdornment,
} from '@mui/material';
import SearchIcon from '@mui/icons-material/Search';
import VisibilityIcon from '@mui/icons-material/Visibility';
import DeleteIcon from '@mui/icons-material/Delete';
import { Link } from 'react-router-dom';
import { useTranslation } from 'react-i18next';

import { ResourcePage, AddButton, EmptyState, EmptyStates } from '../../common';

const getTrustTabs = (t) => [
  { label: t('trust.trustProfiles'), path: '/console/org/trust/profiles' },
  { label: t('trust.trustedIssuers'), path: '/console/org/trust/issuers' },
  { label: t('trust.revocationProfiles'), path: '/console/org/trust/revocation' },
];

const getBreadcrumbs = (t) => [
  { label: t('trust.breadcrumbs.console'), path: '/console' },
  { label: t('trust.breadcrumbs.trust'), path: '/console/org/trust' },
  { label: t('trust.breadcrumbs.trustedIssuers'), path: '/console/org/trust/issuers' },
];

function TrustedIssuersPage() {
  const { t } = useTranslation('console');
  const [issuers, setIssuers] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [searchQuery, setSearchQuery] = useState('');

  useEffect(() => {
    // TODO: Fetch trusted issuers from API
    const loadIssuers = async () => {
      try {
        await new Promise((resolve) => setTimeout(resolve, 500));
        setIssuers([
          {
            id: 'ti-1',
            name: 'German Federal Government',
            country: 'DE',
            did: 'did:web:issuer.bundesdruckerei.de',
            trustProfile: 'EUDI Wallet Trust Profile',
            status: 'active',
          },
          {
            id: 'ti-2',
            name: 'French National Identity',
            country: 'FR',
            did: 'did:web:france-identite.gouv.fr',
            trustProfile: 'EUDI Wallet Trust Profile',
            status: 'active',
          },
          {
            id: 'ti-3',
            name: 'ICAO PKD Master List',
            country: 'INT',
            did: 'did:web:pkd.icao.int',
            trustProfile: 'ICAO PKD Profile',
            status: 'active',
          },
        ]);
      } catch (err) {
        setError(t('trust.trustedIssuersPage.error'));
      } finally {
        setLoading(false);
      }
    };
    loadIssuers();
  }, []);

  const filteredIssuers = issuers.filter(
    (issuer) =>
      issuer.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      issuer.did.toLowerCase().includes(searchQuery.toLowerCase())
  );

  return (
    <ResourcePage
      title={t('trust.trustedIssuers')}
      description={t('trust.trustedIssuersDescription')}
      tabs={getTrustTabs(t)}
      breadcrumbs={getBreadcrumbs(t)}
      actions={
        <AddButton 
          label={t('actions.add', { ns: 'common' })} 
          path="/console/org/trust/issuers/new" 
        />
      }
    >
      {error && (
        <Alert severity="error" sx={{ mb: 3 }}>
          {error}
        </Alert>
      )}

      {/* Search */}
      <Box sx={{ mb: 3 }}>
        <TextField
          placeholder={t('trust.trustedIssuersPage.searchPlaceholder')}
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          size="small"
          sx={{ width: 300 }}
          InputProps={{
            startAdornment: (
              <InputAdornment position="start">
                <SearchIcon color="action" />
              </InputAdornment>
            ),
          }}
        />
      </Box>

      {loading ? (
        <LinearProgress />
      ) : issuers.length === 0 ? (
        <EmptyState {...EmptyStates.trustedIssuers} />
      ) : (
        <TableContainer component={Paper}>
          <Table>
            <TableHead>
              <TableRow>
                <TableCell>{t('trust.trustedIssuersPage.tableHeaders.name')}</TableCell>
                <TableCell>{t('trust.trustedIssuersPage.tableHeaders.country')}</TableCell>
                <TableCell>{t('trust.trustedIssuersPage.tableHeaders.did')}</TableCell>
                <TableCell>{t('trust.trustedIssuersPage.tableHeaders.trustProfile')}</TableCell>
                <TableCell>{t('trust.trustedIssuersPage.tableHeaders.status')}</TableCell>
                <TableCell align="right">{t('trust.trustedIssuersPage.tableHeaders.actions')}</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {filteredIssuers.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={6} align="center">
                    <Typography color="text.secondary" sx={{ py: 4 }}>
                      {t('trust.trustedIssuersPage.empty')}
                    </Typography>
                  </TableCell>
                </TableRow>
              ) : (
                filteredIssuers.map((issuer) => (
                  <TableRow key={issuer.id} hover>
                    <TableCell>
                      <Typography variant="body2" fontWeight={500}>
                        {issuer.name}
                      </Typography>
                    </TableCell>
                    <TableCell>
                      <Chip label={issuer.country} size="small" variant="outlined" />
                    </TableCell>
                    <TableCell>
                      <Typography variant="body2" sx={{ fontFamily: 'monospace', fontSize: '0.75rem' }}>
                        {issuer.did.length > 40 ? `${issuer.did.substring(0, 40)}...` : issuer.did}
                      </Typography>
                    </TableCell>
                    <TableCell>{issuer.trustProfile}</TableCell>
                    <TableCell>
                      <Chip 
                        label={issuer.status === 'active' ? t('trust.trustedIssuersPage.status.active') : t('trust.trustedIssuersPage.status.inactive')} 
                        color={issuer.status === 'active' ? 'success' : 'default'}
                        size="small" 
                      />
                    </TableCell>
                    <TableCell align="right">
                      <Tooltip title={t('trust.trustedIssuersPage.actions.viewDetails')}>
                        <IconButton
                          component={Link}
                          to={`/console/org/trust/issuers/${issuer.id}`}
                          size="small"
                        >
                          <VisibilityIcon fontSize="small" />
                        </IconButton>
                      </Tooltip>
                      <Tooltip title={t('trust.trustedIssuersPage.actions.remove')}>
                        <IconButton size="small" color="error">
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
    </ResourcePage>
  );
}

export default TrustedIssuersPage;

/**
 * Revocation Profiles Page
 * 
 * Manages credential revocation profiles and status lists.
 */

import { useState, useEffect } from 'react';
import {
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
} from '@mui/material';
import EditIcon from '@mui/icons-material/Edit';
import VisibilityIcon from '@mui/icons-material/Visibility';
import { Link } from 'react-router-dom';
import { useTranslation } from 'react-i18next';

import { ResourcePage } from '../../common';
// TODO: Wire up when RevocationManager is available
// import RevocationManager from '../../vendor/RevocationManager';

const getTrustTabs = (t) => [
  { label: t('trust.trustProfiles'), path: '/console/trust/profiles' },
  { label: t('trust.trustedIssuers'), path: '/console/trust/issuers' },
  { label: t('trust.revocationProfiles'), path: '/console/trust/revocation' },
];

const getBreadcrumbs = (t) => [
  { label: t('trust.breadcrumbs.console'), path: '/console' },
  { label: t('trust.breadcrumbs.trust'), path: '/console/trust' },
  { label: t('trust.breadcrumbs.revocationProfiles'), path: '/console/trust/revocation' },
];

function RevocationProfilesPage() {
  const { t } = useTranslation('console');
  const [profiles, setProfiles] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    // TODO: Fetch revocation profiles from API
    const loadProfiles = async () => {
      try {
        await new Promise((resolve) => setTimeout(resolve, 500));
        setProfiles([
          {
            id: 'rp-1',
            name: 'Status List 2021 - Production',
            type: 'StatusList2021',
            credentialsTracked: 15234,
            revokedCount: 42,
            status: 'active',
            updatedAt: '2026-02-07T08:00:00Z',
          },
          {
            id: 'rp-2',
            name: 'Bitstring Status List - Beta',
            type: 'BitstringStatusList',
            credentialsTracked: 500,
            revokedCount: 3,
            status: 'active',
            updatedAt: '2026-02-06T16:30:00Z',
          },
        ]);
      } catch (err) {
        setError(t('trust.revocationProfilesPage.error'));
      } finally {
        setLoading(false);
      }
    };
    loadProfiles();
  }, []);

  return (
    <ResourcePage
      title={t('trust.revocationProfiles')}
      description={t('trust.revocationProfilesDescription')}
      resourceName={t('trust.revocationProfile')}
      buildPath="/console/trust/revocation/new"
      tabs={getTrustTabs(t)}
      breadcrumbs={getBreadcrumbs(t)}
    >
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
                <TableCell>{t('trust.revocationProfilesPage.tableHeaders.name')}</TableCell>
                <TableCell>{t('trust.revocationProfilesPage.tableHeaders.type')}</TableCell>
                <TableCell align="right">{t('trust.revocationProfilesPage.tableHeaders.credentialsTracked')}</TableCell>
                <TableCell align="right">{t('trust.revocationProfilesPage.tableHeaders.revoked')}</TableCell>
                <TableCell>{t('trust.revocationProfilesPage.tableHeaders.status')}</TableCell>
                <TableCell>{t('trust.revocationProfilesPage.tableHeaders.lastUpdated')}</TableCell>
                <TableCell align="right">{t('trust.revocationProfilesPage.tableHeaders.actions')}</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {profiles.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={7} align="center">
                    <Typography color="text.secondary" sx={{ py: 4 }}>
                      {t('trust.revocationProfilesPage.empty')}
                    </Typography>
                  </TableCell>
                </TableRow>
              ) : (
                profiles.map((profile) => (
                  <TableRow key={profile.id} hover>
                    <TableCell>
                      <Typography variant="body2" fontWeight={500}>
                        {profile.name}
                      </Typography>
                    </TableCell>
                    <TableCell>
                      <Chip label={profile.type} size="small" variant="outlined" />
                    </TableCell>
                    <TableCell align="right">
                      {profile.credentialsTracked.toLocaleString()}
                    </TableCell>
                    <TableCell align="right">
                      <Chip 
                        label={profile.revokedCount} 
                        size="small" 
                        color={profile.revokedCount > 0 ? 'warning' : 'default'}
                      />
                    </TableCell>
                    <TableCell>
                      <Chip 
                        label={profile.status === 'active' ? t('trust.revocationProfilesPage.status.active') : t('trust.revocationProfilesPage.status.inactive')} 
                        color={profile.status === 'active' ? 'success' : 'default'}
                        size="small" 
                      />
                    </TableCell>
                    <TableCell>
                      {new Date(profile.updatedAt).toLocaleDateString()}
                    </TableCell>
                    <TableCell align="right">
                      <Tooltip title={t('trust.revocationProfilesPage.actions.viewDetails')}>
                        <IconButton
                          component={Link}
                          to={`/console/trust/revocation/${profile.id}`}
                          size="small"
                        >
                          <VisibilityIcon fontSize="small" />
                        </IconButton>
                      </Tooltip>
                      <Tooltip title={t('trust.revocationProfilesPage.actions.edit')}>
                        <IconButton
                          component={Link}
                          to={`/console/trust/revocation/${profile.id}/edit`}
                          size="small"
                        >
                          <EditIcon fontSize="small" />
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

export default RevocationProfilesPage;

/**
 * Revocation Profiles Page
 *
 * Lists revocation profiles for the current organisation and allows review of
 * each profile's configuration (check mode, mechanisms, status list URL).
 */

import { useTranslation } from 'react-i18next';
import {
  Chip,
  IconButton,
  LinearProgress,
  Paper,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Tooltip,
  Typography,
} from '@mui/material';
import VisibilityIcon from '@mui/icons-material/Visibility';
import { Link } from 'react-router-dom';

import { ResourcePage, StatusChip, EmptyState, EmptyStates } from '../../common';
import { useAsyncData } from '../../../hooks/useAsyncData';
import { useAuth } from '../../../hooks/useAuth';
import { listRevocationProfiles } from '../../../services/presentationPolicyApi';

const getBreadcrumbs = (t) => [
  { label: t('trust.breadcrumbs.console'), path: '/console' },
  { label: t('trust.breadcrumbs.trust'), path: '/console/org/trust' },
  { label: t('trust.breadcrumbs.revocationProfiles'), path: '/console/org/trust/revocation' },
];

const isRevocationServiceUnavailable = (error) => {
  const status = Number(error?.status);
  return status === 502 || status === 503 || status === 504;
};

function RevocationProfilesPage() {
  const { t } = useTranslation('console');
  const { organizationId } = useAuth();

  const { data: profiles = [], loading, error } = useAsyncData(
    () =>
      organizationId
        ? listRevocationProfiles(
            { organization_id: organizationId },
            { retryConfig: { maxRetries: 0 } },
          ).catch((requestError) => {
            if (isRevocationServiceUnavailable(requestError)) {
              return [];
            }
            throw requestError;
          })
        : Promise.resolve([]),
    [organizationId],
  );

  const safeProfiles = Array.isArray(profiles) ? profiles : [];

  return (
    <ResourcePage
      title={t('trust.revocationProfiles')}
      description={t('trust.revocationProfilesDescription')}
      resourceName={t('trust.revocationProfile', 'Revocation Profile')}
      buildPath="/console/org/trust/revocation/new"
      newPath="/console/org/trust/revocation/new"
      breadcrumbs={getBreadcrumbs(t)}
    >
      {loading && <LinearProgress sx={{ mb: 2 }} />}

      {error && (
        <Typography color="error" sx={{ mb: 2 }}>
          {t('common.errorLoading', 'Failed to load revocation profiles.')}
        </Typography>
      )}

      {!loading && safeProfiles.length === 0 && (
        <EmptyState {...(EmptyStates.revocationProfiles ?? { title: t('trust.noRevocationProfiles', 'No revocation profiles configured.') })} />
      )}

      {safeProfiles.length > 0 && (
        <TableContainer component={Paper}>
          <Table>
            <TableHead>
              <TableRow>
                <TableCell>{t('common.name', 'Name')}</TableCell>
                <TableCell>{t('trust.checkMode', 'Check Mode')}</TableCell>
                <TableCell>{t('trust.mechanisms', 'Mechanisms')}</TableCell>
                <TableCell>{t('trust.statusListUrl', 'Status List URL')}</TableCell>
                <TableCell>{t('common.updated', 'Updated')}</TableCell>
                <TableCell align="right">{t('common.actions', 'Actions')}</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {safeProfiles.map((profile) => (
                <TableRow key={profile.id} hover>
                  <TableCell>
                    <Typography variant="body2" fontWeight={500}>
                      {profile.name}
                    </Typography>
                    <Typography variant="caption" color="text.secondary">
                      {profile.id}
                    </Typography>
                  </TableCell>
                  <TableCell>
                    <StatusChip status={profile.check_mode ?? '—'} />
                  </TableCell>
                  <TableCell>
                    {(profile.revocation_mechanism ?? []).map((m) => (
                      <Chip key={m} label={m} size="small" sx={{ mr: 0.5, mb: 0.5 }} />
                    ))}
                  </TableCell>
                  <TableCell>
                    <Typography
                      variant="caption"
                      sx={{ wordBreak: 'break-all', maxWidth: 240, display: 'block' }}
                    >
                      {profile.status_list_url ?? '—'}
                    </Typography>
                  </TableCell>
                  <TableCell>
                    {profile.updated_at
                      ? new Date(profile.updated_at).toLocaleDateString()
                      : '—'}
                  </TableCell>
                  <TableCell align="right">
                    <Tooltip title={t('common.view', 'View')}>
                      <IconButton
                        size="small"
                        component={Link}
                        to={`/console/org/trust/revocation/${profile.id}`}
                      >
                        <VisibilityIcon fontSize="small" />
                      </IconButton>
                    </Tooltip>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>
      )}
    </ResourcePage>
  );
}

export default RevocationProfilesPage;


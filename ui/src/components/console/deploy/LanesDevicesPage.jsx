/** The current user's native device registrations in the selected organization. */

import { useLayoutEffect, useRef, useState } from 'react';
import {
  Alert, Box, Button, Chip, InputAdornment, LinearProgress, Paper,
  Table, TableBody, TableCell, TableContainer, TableHead, TableRow,
  TextField, Typography,
} from '@mui/material';
import SearchIcon from '@mui/icons-material/Search';
import RefreshIcon from '@mui/icons-material/Refresh';
import { useTranslation } from 'react-i18next';

import { ResourcePage } from '../../common';
import { useAsyncData } from '../../../hooks/useAsyncData';
import { listOrganizationDevices } from '../../../services/devicesApi';
import { useAuth } from '../../../hooks/useAuth';
import { useConsole } from '../../../contexts/ConsoleContext';

const getDeployTabs = (t) => [
  { label: t('deploy.deploymentProfiles'), path: '/console/org/deploy/profiles' },
  { label: t('deploy.apiKeys'), path: '/console/org/deploy/api-keys' },
  { label: t('deploy.lanesDevices'), path: '/console/org/deploy/lanes' },
  { label: t('deploy.webhooks'), path: '/console/org/deploy/webhooks' },
];

const getBreadcrumbs = (t) => [
  { label: t('deploy.breadcrumbs.console'), path: '/console' },
  { label: t('deploy.breadcrumbs.deploy'), path: '/console/org/deploy' },
  { label: t('deploy.breadcrumbs.lanesDevices'), path: '/console/org/deploy/lanes' },
];

function RegisteredDevices({ organizationId, principalId }) {
  const { t } = useTranslation('applicant');
  const active = useRef(false);
  const request = useRef(0);
  const [searchQuery, setSearchQuery] = useState('');
  useLayoutEffect(() => {
    active.current = true;
    return () => { active.current = false; request.current += 1; };
  }, []);
  const { data, loading, error, reload } = useAsyncData(async () => {
    const generation = ++request.current;
    return listOrganizationDevices(organizationId, {
      userId: principalId,
      isCurrent: () => active.current && request.current === generation,
    });
  }, [organizationId, principalId]);
  const devices = data || [];
  const query = searchQuery.trim().toLocaleLowerCase();
  const filteredDevices = devices.filter(device => [device.device_id, device.device_model, device.platform]
    .some(value => typeof value === 'string' && value.toLocaleLowerCase().includes(query)));
  const formatDate = (value) => {
    const parsed = value ? new Date(value) : null;
    return parsed && !Number.isNaN(parsed.getTime()) ? parsed.toLocaleString() : t('devices.notReported');
  };

  return (
    <>
      <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 2, mb: 3, alignItems: 'center' }}>
        <TextField
          label={t('devices.searchLabel')}
          value={searchQuery}
          onChange={event => setSearchQuery(event.target.value)}
          size="small"
          sx={{ width: '100%', maxWidth: 440 }}
          slotProps={{ input: { startAdornment: <InputAdornment position="start"><SearchIcon /></InputAdornment> } }}
        />
        <Button startIcon={<RefreshIcon />} onClick={reload} disabled={loading}>
          {t('devices.refresh')}
        </Button>
      </Box>
      {loading ? <LinearProgress aria-label={t('devices.loading')} /> : error ? (
        <Alert severity="error" action={<Button color="inherit" onClick={reload}>{t('actions.retry', { ns: 'common' })}</Button>}>
          {error?.message?.trim() || t('devices.errorLoading')}
        </Alert>
      ) : filteredDevices.length === 0 ? (
        <Paper sx={{ p: 4, textAlign: 'center' }}>
          <Typography color="text.secondary">
            {query ? t('devices.noMatches') : t('deploy.lanesDevicesPage.noDevices', { ns: 'console' })}
          </Typography>
          {query && <Button onClick={() => setSearchQuery('')} sx={{ mt: 1 }}>{t('devices.clearSearch')}</Button>}
        </Paper>
      ) : (
        <TableContainer component={Paper} role="region" aria-label={t('devices.tableLabel')} tabIndex={0} sx={{ maxWidth: '100%' }}>
          <Table sx={{ minWidth: 680 }}>
            <TableHead>
              <TableRow>
                {['device', 'platform', 'appVersion', 'registered', 'lastSeen', 'status'].map(field => (
                  <TableCell key={field}>{t(`devices.tableHeaders.${field}`)}</TableCell>
                ))}
              </TableRow>
            </TableHead>
            <TableBody>
              {filteredDevices.map(device => (
                <TableRow key={device.id}>
                  <TableCell sx={{ overflowWrap: 'anywhere', maxWidth: 280 }}>
                    {device.device_model && <Typography variant="body2" sx={{ fontWeight: 500 }}>{device.device_model}</Typography>}
                    <Typography variant="body2">{device.device_id}</Typography>
                  </TableCell>
                  <TableCell>{device.platform.toUpperCase()}</TableCell>
                  <TableCell>{device.app_version || t('devices.notReported')}</TableCell>
                  <TableCell>{formatDate(device.created_at)}</TableCell>
                  <TableCell>{formatDate(device.last_seen_at)}</TableCell>
                  <TableCell>
                    <Chip size="small" label={t(device.is_active ? 'devices.status.active' : 'devices.status.inactive')} />
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>
      )}
    </>
  );
}

function LanesDevicesPage() {
  const { t } = useTranslation('console');
  const { user, isAuthenticated, isLoading } = useAuth();
  const { activeOrgId } = useConsole();
  const principalId = user?.user_id || user?.sub || user?.id || null;
  return (
    <ResourcePage
      title={t('deploy.lanesDevicesPage.title')}
      description={t('deploy.lanesDevicesPage.description')}
      tabs={getDeployTabs(t)}
      breadcrumbs={getBreadcrumbs(t)}
    >
      {isLoading ? <LinearProgress aria-label={t('devices.loading', { ns: 'applicant' })} />
        : !isAuthenticated || !principalId ? <Alert severity="info">{t('devices.signInRequired', { ns: 'applicant' })}</Alert>
          : !activeOrgId ? <Alert severity="info">{t('deploy.lanesDevicesPage.selectOrganization')}</Alert>
            : <RegisteredDevices key={JSON.stringify([principalId, activeOrgId])} organizationId={activeOrgId} principalId={principalId} />}
    </ResourcePage>
  );
}

export default LanesDevicesPage;

/**
 * Lanes & Devices Page
 * 
 * Manages lanes and devices across all deployment profiles.
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
  FormControl,
  InputLabel,
  Select,
  MenuItem,
} from '@mui/material';
import SearchIcon from '@mui/icons-material/Search';
import VisibilityIcon from '@mui/icons-material/Visibility';
import SettingsIcon from '@mui/icons-material/Settings';
import DevicesIcon from '@mui/icons-material/Devices';
import { Link } from 'react-router-dom';
import { useTranslation } from 'react-i18next';

import { ResourcePage, AddButton } from '../../common';

const getDeployTabs = (t) => [
  { label: t('deploy.deploymentProfiles'), path: '/console/deploy/profiles' },
  { label: t('deploy.apiKeys'), path: '/console/deploy/api-keys' },
  { label: t('deploy.lanesDevices'), path: '/console/deploy/lanes' },
  { label: t('deploy.webhooks'), path: '/console/deploy/webhooks' },
];

const getBreadcrumbs = (t) => [
  { label: t('deploy.breadcrumbs.console'), path: '/console' },
  { label: t('deploy.breadcrumbs.deploy'), path: '/console/deploy' },
  { label: t('deploy.breadcrumbs.lanesDevices'), path: '/console/deploy/lanes' },
];

function LanesDevicesPage() {
  const { t } = useTranslation('console');
  const [lanes, setLanes] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [deploymentFilter, setDeploymentFilter] = useState('all');

  useEffect(() => {
    // TODO: Fetch lanes from API
    const loadLanes = async () => {
      try {
        await new Promise((resolve) => setTimeout(resolve, 500));
        setLanes([
          {
            id: 'ln-1',
            name: 'Terminal 1 - Gate A1',
            deployment: 'Production - Airport Terminals',
            deploymentId: 'dp-1',
            deviceCount: 2,
            activeDevices: 2,
            lastActivity: '2026-02-07T08:45:00Z',
            status: 'online',
          },
          {
            id: 'ln-2',
            name: 'Terminal 1 - Gate A2',
            deployment: 'Production - Airport Terminals',
            deploymentId: 'dp-1',
            deviceCount: 2,
            activeDevices: 1,
            lastActivity: '2026-02-07T08:30:00Z',
            status: 'degraded',
          },
          {
            id: 'ln-3',
            name: 'Border Control - Lane 1',
            deployment: 'Production - Border Control',
            deploymentId: 'dp-2',
            deviceCount: 2,
            activeDevices: 2,
            lastActivity: '2026-02-07T09:00:00Z',
            status: 'online',
          },
          {
            id: 'ln-4',
            name: 'Test Lane',
            deployment: 'Test Environment',
            deploymentId: 'dp-3',
            deviceCount: 2,
            activeDevices: 0,
            lastActivity: '2026-02-06T17:00:00Z',
            status: 'offline',
          },
        ]);
      } catch (err) {
        setError(t('deploy.lanesDevicesPage.error'));
      } finally {
        setLoading(false);
      }
    };
    loadLanes();
  }, []);

  const getStatusColor = (status) => {
    switch (status) {
      case 'online':
        return 'success';
      case 'degraded':
        return 'warning';
      case 'offline':
        return 'error';
      default:
        return 'default';
    }
  };

  const getStatusLabel = (status) => {
    switch (status) {
      case 'online':
        return t('deploy.lanesDevicesPage.status.online');
      case 'degraded':
        return t('deploy.lanesDevicesPage.status.degraded');
      case 'offline':
        return t('deploy.lanesDevicesPage.status.offline');
      default:
        return status;
    }
  };

  const filteredLanes = lanes.filter((lane) => {
    const matchesSearch = lane.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      lane.deployment.toLowerCase().includes(searchQuery.toLowerCase());
    const matchesDeployment = deploymentFilter === 'all' || lane.deploymentId === deploymentFilter;
    return matchesSearch && matchesDeployment;
  });

  const deployments = [...new Set(lanes.map((l) => ({ id: l.deploymentId, name: l.deployment })))];

  return (
    <ResourcePage
      title={t('deploy.lanesDevicesPage.title')}
      description={t('deploy.lanesDevicesPage.description')}
      tabs={getDeployTabs(t)}
      breadcrumbs={getBreadcrumbs(t)}
      actions={
        <AddButton 
          label={t('deploy.lanesDevicesPage.addLane')} 
          path="/console/deploy/lanes/new" 
        />
      }
    >
      {error && (
        <Alert severity="error" sx={{ mb: 3 }}>
          {error}
        </Alert>
      )}

      {/* Filters */}
      <Box sx={{ display: 'flex', gap: 2, mb: 3 }}>
        <TextField
          placeholder={t('deploy.lanesDevicesPage.searchPlaceholder')}
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
        <FormControl size="small" sx={{ minWidth: 200 }}>
          <InputLabel>{t('deploy.lanesDevicesPage.deploymentFilter')}</InputLabel>
          <Select
            value={deploymentFilter}
            label={t('deploy.lanesDevicesPage.deploymentFilter')}
            onChange={(e) => setDeploymentFilter(e.target.value)}
          >
            <MenuItem value="all">{t('deploy.lanesDevicesPage.allDeploymentProfiles')}</MenuItem>
            {deployments.map((d) => (
              <MenuItem key={d.id} value={d.id}>{d.name}</MenuItem>
            ))}
          </Select>
        </FormControl>
      </Box>

      {loading ? (
        <LinearProgress />
      ) : (
        <TableContainer component={Paper}>
          <Table>
            <TableHead>
              <TableRow>
                <TableCell>{t('deploy.lanesDevicesPage.tableHeaders.lane')}</TableCell>
                <TableCell>{t('deploy.lanesDevicesPage.tableHeaders.deployment')}</TableCell>
                <TableCell>{t('deploy.lanesDevicesPage.tableHeaders.devices')}</TableCell>
                <TableCell>{t('deploy.lanesDevicesPage.tableHeaders.lastActivity')}</TableCell>
                <TableCell>{t('deploy.lanesDevicesPage.tableHeaders.status')}</TableCell>
                <TableCell align="right">{t('deploy.lanesDevicesPage.tableHeaders.actions')}</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {filteredLanes.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={6} align="center">
                    <Typography color="text.secondary" sx={{ py: 4 }}>
                      {searchQuery || deploymentFilter !== 'all' 
                        ? t('deploy.lanesDevicesPage.noMatchingLanes') 
                        : t('deploy.lanesDevicesPage.noLanes')}
                    </Typography>
                  </TableCell>
                </TableRow>
              ) : (
                filteredLanes.map((lane) => (
                  <TableRow key={lane.id} hover>
                    <TableCell>
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                        <DevicesIcon color="action" fontSize="small" />
                        <Typography variant="body2" fontWeight={500}>
                          {lane.name}
                        </Typography>
                      </Box>
                    </TableCell>
                    <TableCell>{lane.deployment}</TableCell>
                    <TableCell>
                      <Typography variant="body2">
                        {t('deploy.lanesDevicesPage.devicesActive', { active: lane.activeDevices, total: lane.deviceCount })}
                      </Typography>
                    </TableCell>
                    <TableCell>
                      {new Date(lane.lastActivity).toLocaleString()}
                    </TableCell>
                    <TableCell>
                      <Chip 
                        label={getStatusLabel(lane.status)} 
                        color={getStatusColor(lane.status)}
                        size="small" 
                      />
                    </TableCell>
                    <TableCell align="right">
                      <Tooltip title={t('deploy.lanesDevicesPage.actions.viewDevices')}>
                        <IconButton
                          component={Link}
                          to={`/console/deploy/lanes/${lane.id}`}
                          size="small"
                        >
                          <VisibilityIcon fontSize="small" />
                        </IconButton>
                      </Tooltip>
                      <Tooltip title={t('deploy.lanesDevicesPage.actions.configure')}>
                        <IconButton
                          component={Link}
                          to={`/console/deploy/lanes/${lane.id}/settings`}
                          size="small"
                        >
                          <SettingsIcon fontSize="small" />
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

export default LanesDevicesPage;

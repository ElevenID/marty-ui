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

import { ResourcePage, AddButton } from '../../common';

const DEPLOY_TABS = [
  { label: 'Deployment Profiles', path: '/console/deploy/profiles' },
  { label: 'API Keys', path: '/console/deploy/api-keys' },
  { label: 'Lanes & Devices', path: '/console/deploy/lanes' },
  { label: 'Webhooks', path: '/console/deploy/webhooks' },
];

const BREADCRUMBS = [
  { label: 'Console', path: '/console' },
  { label: 'Deploy', path: '/console/deploy' },
  { label: 'Lanes & Devices', path: '/console/deploy/lanes' },
];

function LanesDevicesPage() {
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
        setError('Failed to load lanes');
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

  const filteredLanes = lanes.filter((lane) => {
    const matchesSearch = lane.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      lane.deployment.toLowerCase().includes(searchQuery.toLowerCase());
    const matchesDeployment = deploymentFilter === 'all' || lane.deploymentId === deploymentFilter;
    return matchesSearch && matchesDeployment;
  });

  const deployments = [...new Set(lanes.map((l) => ({ id: l.deploymentId, name: l.deployment })))];

  return (
    <ResourcePage
      title="Lanes & Devices"
      description="Monitor and manage verification lanes and connected devices."
      tabs={DEPLOY_TABS}
      breadcrumbs={BREADCRUMBS}
      actions={
        <AddButton 
          label="Add Lane" 
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
          placeholder="Search lanes..."
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
          <InputLabel>Deployment</InputLabel>
          <Select
            value={deploymentFilter}
            label="Deployment"
            onChange={(e) => setDeploymentFilter(e.target.value)}
          >
            <MenuItem value="all">All Deployment Profiles</MenuItem>
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
                <TableCell>Lane</TableCell>
                <TableCell>Deployment</TableCell>
                <TableCell>Devices</TableCell>
                <TableCell>Last Activity</TableCell>
                <TableCell>Status</TableCell>
                <TableCell align="right">Actions</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {filteredLanes.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={6} align="center">
                    <Typography color="text.secondary" sx={{ py: 4 }}>
                      {searchQuery || deploymentFilter !== 'all' 
                        ? 'No lanes match your filters.' 
                        : 'No lanes configured.'}
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
                        {lane.activeDevices} / {lane.deviceCount} active
                      </Typography>
                    </TableCell>
                    <TableCell>
                      {new Date(lane.lastActivity).toLocaleString()}
                    </TableCell>
                    <TableCell>
                      <Chip 
                        label={lane.status.charAt(0).toUpperCase() + lane.status.slice(1)} 
                        color={getStatusColor(lane.status)}
                        size="small" 
                      />
                    </TableCell>
                    <TableCell align="right">
                      <Tooltip title="View Devices">
                        <IconButton
                          component={Link}
                          to={`/console/deploy/lanes/${lane.id}`}
                          size="small"
                        >
                          <VisibilityIcon fontSize="small" />
                        </IconButton>
                      </Tooltip>
                      <Tooltip title="Configure">
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

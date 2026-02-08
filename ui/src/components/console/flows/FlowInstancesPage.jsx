/**
 * Flow Instances Page
 * 
 * Displays running and completed flow instances.
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
  Button,
} from '@mui/material';
import SearchIcon from '@mui/icons-material/Search';
import VisibilityIcon from '@mui/icons-material/Visibility';
import RefreshIcon from '@mui/icons-material/Refresh';
import FastForwardIcon from '@mui/icons-material/FastForward';
import CancelIcon from '@mui/icons-material/Cancel';
import { Link } from 'react-router-dom';

import { ResourcePage, EmptyState, EmptyStates, StatusChip } from '../../common';

const FLOWS_TABS = [
  { label: 'Flow Definitions', path: '/console/flows/definitions' },
  { label: 'Flow Instances', path: '/console/flows/instances' },
];

const BREADCRUMBS = [
  { label: 'Console', path: '/console' },
  { label: 'Flows', path: '/console/flows' },
  { label: 'Flow Instances', path: '/console/flows/instances' },
];

function FlowInstancesPage() {
  const [instances, setInstances] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState('all');

  useEffect(() => {
    loadInstances();
  }, []);

  const loadInstances = async () => {
    setLoading(true);
    try {
      await new Promise((resolve) => setTimeout(resolve, 500));
      setInstances([
        {
          id: 'fi-1001',
          flowName: 'Age Verification Flow',
          flowId: 'fl-1',
          currentStep: 3,
          totalSteps: 3,
          status: 'completed',
          result: 'success',
          startedAt: '2026-02-07T09:15:00Z',
          completedAt: '2026-02-07T09:15:45Z',
        },
        {
          id: 'fi-1002',
          flowName: 'Full Identity Check',
          flowId: 'fl-2',
          currentStep: 3,
          totalSteps: 5,
          status: 'pending',
          result: null,
          startedAt: '2026-02-07T09:10:00Z',
          completedAt: null,
        },
        {
          id: 'fi-1003',
          flowName: 'Age Verification Flow',
          flowId: 'fl-1',
          currentStep: 2,
          totalSteps: 3,
          status: 'pending',
          result: null,
          startedAt: '2026-02-07T09:05:00Z',
          completedAt: null,
        },
        {
          id: 'fi-1004',
          flowName: 'mDL Issuance Flow',
          flowId: 'fl-3',
          currentStep: 7,
          totalSteps: 7,
          status: 'completed',
          result: 'success',
          startedAt: '2026-02-07T08:50:00Z',
          completedAt: '2026-02-07T09:02:00Z',
        },
        {
          id: 'fi-1005',
          flowName: 'Age Verification Flow',
          flowId: 'fl-1',
          currentStep: 1,
          totalSteps: 3,
          status: 'failed',
          result: 'credential_expired',
          startedAt: '2026-02-07T08:45:00Z',
          completedAt: '2026-02-07T08:45:30Z',
        },
      ]);
    } catch (err) {
      setError('Failed to load flow instances');
    } finally {
      setLoading(false);
    }
  };

  /**
   * Get effective status for display (considers result for completed flows)
   */
  const getEffectiveStatus = (status, result) => {
    if (status === 'completed' && result === 'success') return 'completed';
    if (status === 'failed' || (status === 'completed' && result !== 'success')) return 'failed';
    if (status === 'pending') return 'running';
    return status;
  };

  const filteredInstances = instances.filter((instance) => {
    const matchesSearch = instance.id.toLowerCase().includes(searchQuery.toLowerCase()) ||
      instance.flowName.toLowerCase().includes(searchQuery.toLowerCase());
    const matchesStatus = statusFilter === 'all' || instance.status === statusFilter;
    return matchesSearch && matchesStatus;
  });

  return (
    <ResourcePage
      title="Flow Instances"
      description="Monitor running verification and issuance flows."
      tabs={FLOWS_TABS}
      breadcrumbs={BREADCRUMBS}
      actions={
        <Button
          variant="outlined"
          startIcon={<RefreshIcon />}
          onClick={loadInstances}
          disabled={loading}
        >
          Refresh
        </Button>
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
          placeholder="Search by ID or flow name..."
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
        <FormControl size="small" sx={{ minWidth: 150 }}>
          <InputLabel>Status</InputLabel>
          <Select
            value={statusFilter}
            label="Status"
            onChange={(e) => setStatusFilter(e.target.value)}
          >
            <MenuItem value="all">All</MenuItem>
            <MenuItem value="pending">Pending</MenuItem>
            <MenuItem value="completed">Completed</MenuItem>
            <MenuItem value="failed">Failed</MenuItem>
          </Select>
        </FormControl>
      </Box>

      {loading ? (
        <LinearProgress />
      ) : instances.length === 0 ? (
        <EmptyState {...EmptyStates.flowInstances} />
      ) : (
        <TableContainer component={Paper}>
          <Table>
            <TableHead>
              <TableRow>
                <TableCell>Instance ID</TableCell>
                <TableCell>Flow</TableCell>
                <TableCell>Progress</TableCell>
                <TableCell>Started</TableCell>
                <TableCell>Completed</TableCell>
                <TableCell>Status</TableCell>
                <TableCell align="right">Actions</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {filteredInstances.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={7} align="center">
                    <Typography color="text.secondary" sx={{ py: 4 }}>
                      No instances match your filters. Try adjusting your search.
                    </Typography>
                  </TableCell>
                </TableRow>
              ) : (
                filteredInstances.map((instance) => (
                  <TableRow key={instance.id} hover>
                    <TableCell>
                      <Typography variant="body2" sx={{ fontFamily: 'monospace' }}>
                        {instance.id}
                      </Typography>
                    </TableCell>
                    <TableCell>
                      <Typography variant="body2" fontWeight={500}>
                        {instance.flowName}
                      </Typography>
                    </TableCell>
                    <TableCell>
                      <Typography variant="body2">
                        Step {instance.currentStep} / {instance.totalSteps}
                      </Typography>
                    </TableCell>
                    <TableCell>
                      {new Date(instance.startedAt).toLocaleString()}
                    </TableCell>
                    <TableCell>
                      {instance.completedAt 
                        ? new Date(instance.completedAt).toLocaleString()
                        : '-'
                      }
                    </TableCell>
                    <TableCell>
                      <StatusChip status={getEffectiveStatus(instance.status, instance.result)} />
                    </TableCell>
                    <TableCell align="right">
                      <Tooltip title="View Details">
                        <IconButton
                          component={Link}
                          to={`/console/flows/instances/${instance.id}`}
                          size="small"
                        >
                          <VisibilityIcon fontSize="small" />
                        </IconButton>
                      </Tooltip>
                      {instance.status === 'pending' && (
                        <>
                          <Tooltip title="Advance Flow">
                            <IconButton size="small" color="primary">
                              <FastForwardIcon fontSize="small" />
                            </IconButton>
                          </Tooltip>
                          <Tooltip title="Cancel">
                            <IconButton size="small" color="error">
                              <CancelIcon fontSize="small" />
                            </IconButton>
                          </Tooltip>
                        </>
                      )}
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

export default FlowInstancesPage;

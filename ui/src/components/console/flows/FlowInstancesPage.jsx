/**
 * Flow Instances Page
 * 
 * Displays running and completed flow instances.
 */

import { useState } from 'react';
import { useAsyncData } from '../../../hooks/useAsyncData';
import { useTranslation } from 'react-i18next';
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
import { useAuth } from '../../../hooks/useAuth';
import { listFlows, listFlowExecutions } from '../../../services/flowsApi';

const getFlowsTabs = (t) => [
  { label: t('flows.flowDefinitions'), path: '/console/org/flows/definitions' },
  { label: t('flows.flowInstances'), path: '/console/org/operate/flow-instances' },
];

const getBreadcrumbs = (t) => [
  { label: t('flows.breadcrumbs.console'), path: '/console' },
  { label: t('flows.breadcrumbs.flows'), path: '/console/org/operate' },
  { label: t('flows.breadcrumbs.flowInstances'), path: '/console/org/operate/flow-instances' },
];

function FlowInstancesPage() {
  const { t } = useTranslation('console');
  const { organizationId } = useAuth();
  const { data: instances = [], loading, error, reload: loadInstances } = useAsyncData(async () => {
    const flowsResponse = await listFlows({ organization_id: organizationId });
    const flows = Array.isArray(flowsResponse) ? flowsResponse : [];
    const allInstances = [];
    for (const flow of flows) {
      if (!flow?.id) {
        continue;
      }

      const executionsResponse = await listFlowExecutions(flow.id, { organization_id: organizationId });
      const executions = Array.isArray(executionsResponse) ? executionsResponse : [];
      for (const exec of executions) {
        allInstances.push({
          ...exec,
          id: exec?.id ? String(exec.id) : `unknown-${flow.id}`,
          flowName: typeof flow.name === 'string' ? flow.name : 'Unnamed Flow',
          flowId: flow.id,
          status: typeof exec?.status === 'string' ? exec.status : 'unknown',
        });
      }
    }
    return allInstances;
  }, [organizationId]);
  const safeInstances = Array.isArray(instances) ? instances : [];
  const [searchQuery, setSearchQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState('all');

  /**
   * Get effective status for display (considers result for completed flows)
   */
  const getEffectiveStatus = (status, result) => {
    if (status === 'completed' && result === 'success') return 'completed';
    if (status === 'failed' || (status === 'completed' && result !== 'success')) return 'failed';
    if (status === 'pending') return 'running';
    return status;
  };

  const filteredInstances = safeInstances.filter((instance) => {
    const normalizedId = String(instance.id || '').toLowerCase();
    const normalizedFlowName = String(instance.flowName || '').toLowerCase();
    const normalizedQuery = searchQuery.toLowerCase();
    const matchesSearch = normalizedId.includes(normalizedQuery) || normalizedFlowName.includes(normalizedQuery);
    const matchesStatus = statusFilter === 'all' || instance.status === statusFilter;
    return matchesSearch && matchesStatus;
  });

  return (
    <ResourcePage
      title={t('flows.flowInstances')}
      description={t('flows.flowInstancesDescription')}
      tabs={getFlowsTabs(t)}
      breadcrumbs={getBreadcrumbs(t)}
      actions={
        <Button
          variant="outlined"
          startIcon={<RefreshIcon />}
          onClick={loadInstances}
          disabled={loading}
        >
          {t('flows.refresh')}
        </Button>
      }
    >
      {error && (
        <Alert severity="error" sx={{ mb: 3 }}>
          {error?.message || String(error)}
        </Alert>
      )}

      {/* Filters */}
      <Box sx={{ display: 'flex', gap: 2, mb: 3 }}>
        <TextField
          placeholder={t('flows.searchPlaceholder')}
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
          <InputLabel>{t('flows.filters.status')}</InputLabel>
          <Select
            value={statusFilter}
            label={t('flows.filters.status')}
            onChange={(e) => setStatusFilter(e.target.value)}
          >
            <MenuItem value="all">{t('flows.filters.all')}</MenuItem>
            <MenuItem value="pending">{t('flows.filters.pending')}</MenuItem>
            <MenuItem value="completed">{t('flows.filters.completed')}</MenuItem>
            <MenuItem value="failed">{t('flows.filters.failed')}</MenuItem>
          </Select>
        </FormControl>
      </Box>

      {loading ? (
        <LinearProgress />
      ) : safeInstances.length === 0 ? (
        <EmptyState {...EmptyStates.flowInstances} />
      ) : (
        <TableContainer component={Paper}>
          <Table>
            <TableHead>
              <TableRow>
                <TableCell>{t('flows.tableHeaders.instanceId')}</TableCell>
                <TableCell>{t('flows.tableHeaders.flow')}</TableCell>
                <TableCell>{t('flows.tableHeaders.progress')}</TableCell>
                <TableCell>{t('flows.tableHeaders.started')}</TableCell>
                <TableCell>{t('flows.tableHeaders.completed')}</TableCell>
                <TableCell>{t('flows.tableHeaders.status')}</TableCell>
                <TableCell align="right">{t('flows.tableHeaders.actions')}</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {filteredInstances.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={7} align="center">
                    <Typography color="text.secondary" sx={{ py: 4 }}>
                      {t('flows.noMatchingInstances')}
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
                        {t('flows.progress', { current: instance.currentStep, total: instance.totalSteps })}
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
                      <Tooltip title={t('flows.actions.viewDetails')}>
                        <IconButton
                          component={Link}
                          to={`/console/org/operate/flow-instances/${instance.id}`}
                          size="small"
                        >
                          <VisibilityIcon fontSize="small" />
                        </IconButton>
                      </Tooltip>
                      {instance.status === 'pending' && (
                        <>
                          <Tooltip title={t('flows.actions.advanceFlow')}>
                            <IconButton size="small" color="primary">
                              <FastForwardIcon fontSize="small" />
                            </IconButton>
                          </Tooltip>
                          <Tooltip title={t('flows.actions.cancel')}>
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

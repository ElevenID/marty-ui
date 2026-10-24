import { useEffect, useMemo, useRef, useState } from 'react';
import { Link, useMatch, useParams } from 'react-router';
import {
  Alert,
  Box,
  Button,
  Chip,
  Divider,
  Dialog, DialogTitle, DialogContent, DialogContentText, DialogActions,
  FormControl,
  IconButton,
  InputAdornment,
  InputLabel,
  LinearProgress,
  Link as MuiLink,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  MenuItem,
  Paper,
  Select,
  Stack,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  TextField,
  Tooltip,
  Typography,
} from '@mui/material';
import AccountTreeIcon from '@mui/icons-material/AccountTree';
import AssignmentIcon from '@mui/icons-material/Assignment';
import BadgeIcon from '@mui/icons-material/Badge';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import LocalShippingIcon from '@mui/icons-material/LocalShipping';
import RefreshIcon from '@mui/icons-material/Refresh';
import SearchIcon from '@mui/icons-material/Search';
import VisibilityIcon from '@mui/icons-material/Visibility';
import WarningIcon from '@mui/icons-material/Warning';

import { ResourcePage, EmptyState, EmptyStates, StatusChip } from '../../common';
import { useConsole } from '../../../contexts/ConsoleContext';
import { useAsyncData } from '../../../hooks/useAsyncData';
import { usePermissions } from '../../../hooks/usePermissions';
import { advanceFlowInstance, cancelFlowExecution, getFlowInstance, listFlowInstances, listFlows } from '../../../services/flowsApi';

function requireInstanceScope(instance, organizationId, instanceId) {
  if (!instance?.id || instance.organization_id !== organizationId || (instanceId && instance.id !== instanceId)) {
    throw new Error('This flow instance is not available in the selected organization.');
  }
  return instance;
}

function ExecutionActions({ instance, organizationId, loading, reload }) {
  const { can, isLoading: grantsLoading } = usePermissions();
  const mounted = useRef(true);
  const [action, setAction] = useState(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [requiresRefresh, setRequiresRefresh] = useState(false);
  useEffect(() => { mounted.current = true; return () => { mounted.current = false; }; }, []);
  useEffect(() => { setAction(null); setError(''); setRequiresRefresh(false); }, [instance]);
  const advance = ['in_progress', 'awaiting_wallet'].includes(instance.status)
    && !grantsLoading && can('flow-instance', 'advance');
  const cancel = ['pending', 'in_progress', 'awaiting_wallet', 'awaiting_approval', 'awaiting_evidence'].includes(instance.status)
    && !grantsLoading && can('flow-instance', 'cancel');
  if (!advance && !cancel) return null;
  const disabled = loading || busy || requiresRefresh;
  const confirm = async () => {
    if (disabled || !action || (action === 'cancel' ? !cancel : !advance)) return;
    setBusy(true); setError('');
    try {
      const fresh = requireInstanceScope(await getFlowInstance(instance.id, { organizationId }), organizationId, instance.id);
      if (!mounted.current) return;
      const latest = normalizeInstance(fresh);
      if (latest.status !== instance.status || latest.currentStep !== instance.currentStep
        || latest.updated_at !== instance.updated_at) throw new Error('Execution changed. Refresh and review its current step.');
      const result = action === 'cancel'
        ? await cancelFlowExecution(instance.flowId, instance.id)
        : await advanceFlowInstance(instance.id, action);
      requireInstanceScope(result, organizationId, instance.id);
      if (mounted.current) { setAction(null); await reload(); }
    } catch (cause) {
      if (mounted.current) { setAction(null); setRequiresRefresh(true); setError(`${cause?.message || 'Outcome request failed.'} Refresh the execution before recording another outcome.`); }
    } finally { if (mounted.current) setBusy(false); }
  };
  const title = action === 'cancel' ? 'Cancel flow execution' : `Record ${action === 'failure' ? 'failed' : 'successful'} step`;
  return <Box>
    <Stack direction={{ xs: 'column', sm: 'row' }} spacing={1}>
      {advance && <><Button variant="outlined" disabled={disabled} onClick={() => setAction('success')}>Record successful step</Button>
        <Button variant="outlined" disabled={disabled} onClick={() => setAction('failure')}>Record failed step</Button></>}
      {cancel && <Button color="error" disabled={disabled} onClick={() => setAction('cancel')}>Cancel execution</Button>}
    </Stack>
    {error && <Alert severity="error" sx={{ mt: 2 }}>{error}</Alert>}
    <Dialog open={Boolean(action)} onClose={() => { if (!busy) setAction(null); }}>
      <DialogTitle>{title}</DialogTitle>
      <DialogContent><DialogContentText>
        {action === 'cancel' ? 'Cancel this flow execution. Credential offers and issued credentials are managed separately.'
          : `Record a ${action === 'failure' ? 'failed' : 'successful'} outcome for ${instance.currentStep || 'the current step'}. The flow follows its configured transition. This records a step outcome; it does not verify a credential.`}
      </DialogContentText></DialogContent>
      <DialogActions><Button disabled={busy} onClick={() => setAction(null)}>Back</Button>
        <Button disabled={busy || loading} onClick={confirm}>{action === 'cancel' ? 'Confirm cancellation' : 'Confirm outcome'}</Button></DialogActions>
    </Dialog>
  </Box>;
}

const OPERATE_TABS = [
  { label: 'Flow Instances', path: '/console/org/operate/flow-instances' },
  { label: 'Applications', path: '/console/org/operate/applications' },
  { label: 'Issued Credentials', path: '/console/org/operate/issuance' },
  { label: 'Verification Sessions', path: '/console/org/operate/verify' },
];

function readContext(instance) {
  return instance?.context_data && typeof instance.context_data === 'object' ? instance.context_data : {};
}

function normalizeInstance(instance, flow) {
  const context = readContext(instance);
  const physicalJob = context.physical_document_job && typeof context.physical_document_job === 'object'
    ? context.physical_document_job
    : null;
  const currentStepIndex = instance?.current_step_index ?? instance?.currentStepIndex;
  const totalSteps = flow?.resolved_steps?.length || Object.keys(instance?.step_results || {}).length || null;
  return {
    ...instance,
    id: String(instance?.id || ''),
    flowId: instance?.flow_id || instance?.flowId || flow?.id || null,
    flowName: flow?.name || instance?.metadata?.flow_definition_reference || 'Unknown flow',
    flowType: instance?.flow_type || flow?.flow_type || 'unknown',
    status: String(instance?.status || 'unknown').toLowerCase(),
    currentStep: instance?.current_step || instance?.currentStep || null,
    currentStepNumber: Number.isInteger(currentStepIndex) ? currentStepIndex + 1 : null,
    totalSteps,
    startedAt: instance?.started_at || instance?.startedAt || instance?.created_at || null,
    completedAt: instance?.completed_at || instance?.completedAt || null,
    applicationId: context.application_id || null,
    credentialId: instance?.issued_credential_id || context.issued_credential_id || null,
    externalReference: instance?.metadata?.external_reference || null,
    physicalJob,
  };
}

function formatDate(value) {
  if (!value) return 'Not completed';
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? 'Unavailable' : date.toLocaleString();
}

function displayStatus(status) {
  if (status === 'pending') return 'running';
  return status;
}

function RelatedRecord({ icon: Icon, label, value, path }) {
  if (!value) return null;
  return (
    <Box sx={{ minWidth: 0 }}>
      <Stack direction="row" spacing={1} alignItems="center">
        <Icon color="action" fontSize="small" />
        <Typography variant="caption" color="text.secondary">{label}</Typography>
      </Stack>
      {path ? (
        <MuiLink component={Link} to={path} variant="body2" sx={{ overflowWrap: 'anywhere' }}>{value}</MuiLink>
      ) : (
        <Typography variant="body2" sx={{ overflowWrap: 'anywhere' }}>{value}</Typography>
      )}
    </Box>
  );
}

function InstanceTimeline({ instance }) {
  const history = Array.isArray(instance.state_history) ? instance.state_history : [];
  const stepResults = instance.step_results && typeof instance.step_results === 'object' ? instance.step_results : {};
  const events = history.length > 0
    ? history.map((event, index) => ({
      id: `${event.timestamp || event.changed_at || index}-${index}`,
      label: event.to_status || event.status || event.state || 'State updated',
      detail: event.reason || event.from_status || null,
      timestamp: event.timestamp || event.changed_at || event.created_at || null,
      failed: String(event.to_status || event.status || '').toLowerCase().includes('fail'),
    }))
    : Object.entries(stepResults).map(([step, result], index) => ({
      id: `${step}-${index}`,
      label: step,
      detail: result?.status || result?.result || 'completed',
      timestamp: result?.completed_at || result?.timestamp || null,
      failed: String(result?.status || result?.result || '').toLowerCase().includes('fail'),
    }));

  if (events.length === 0) {
    return <Typography variant="body2" color="text.secondary">No runtime events have been recorded yet.</Typography>;
  }

  return (
    <List disablePadding>
      {events.map((event, index) => (
        <ListItem
          key={event.id}
          alignItems="flex-start"
          disableGutters
          sx={index < events.length - 1 ? { borderBottom: 1, borderColor: 'divider' } : undefined}
        >
          <ListItemIcon sx={{ minWidth: 36, mt: 0.25 }}>
            {event.failed ? <WarningIcon color="error" fontSize="small" /> : <CheckCircleIcon color="success" fontSize="small" />}
          </ListItemIcon>
          <ListItemText
            primary={String(event.label).replaceAll('_', ' ')}
            secondary={[event.detail, event.timestamp ? formatDate(event.timestamp) : null].filter(Boolean).join(' | ')}
            slotProps={{
              primary: { variant: 'body2', fontWeight: 600, textTransform: 'capitalize' },
              secondary: { variant: 'caption' }
            }} />
        </ListItem>
      ))}
    </List>
  );
}

function InstanceDetail({ instance, organizationId, loading, error, reload }) {
  const jobId = instance?.physicalJob?.id || instance?.physicalJob?.job_id || null;
  const jobStatus = instance?.physicalJob?.status || null;
  return (
    <ResourcePage
      title={instance ? `Flow Instance ${instance.id}` : 'Flow Instance'}
      description="Runtime state, protocol progress, and related product records."
      tabs={OPERATE_TABS}
      breadcrumbs={[
        { label: 'Console', path: '/console' },
        { label: 'Operate', path: '/console/org/operate' },
        { label: 'Flow Instances', path: '/console/org/operate/flow-instances' },
        { label: instance?.id || 'Instance', path: `/console/org/operate/flow-instances/${instance?.id || ''}` },
      ]}
      actions={<Button variant="outlined" startIcon={<RefreshIcon />} onClick={reload} disabled={loading}>Refresh</Button>}
    >
      {loading && <LinearProgress />}
      {error && <Alert severity="error">{error?.message || String(error)}</Alert>}
      {instance && (
        <Stack spacing={3}>
          <ExecutionActions instance={instance} organizationId={organizationId} loading={loading} reload={reload} />
          <Paper variant="outlined" sx={{ p: 3 }}>
            <Stack direction={{ xs: 'column', md: 'row' }} justifyContent="space-between" gap={2}>
              <Box>
                <Typography variant="overline" color="text.secondary">Current step</Typography>
                <Typography variant="h6">{instance.currentStep?.replaceAll('_', ' ') || 'Waiting to start'}</Typography>
                <Typography variant="body2" color="text.secondary">{instance.flowType.replaceAll('_', ' ')}</Typography>
              </Box>
              <StatusChip status={displayStatus(instance.status)} />
            </Stack>
            <Divider sx={{ my: 2 }} />
            <Box sx={{ display: 'grid', gridTemplateColumns: { xs: '1fr', sm: 'repeat(2, minmax(0, 1fr))', lg: 'repeat(4, minmax(0, 1fr))' }, gap: 2 }}>
              <RelatedRecord icon={AccountTreeIcon} label="Flow definition" value={instance.flowName} path={instance.flowId ? `/console/org/flows/definitions/${instance.flowId}` : null} />
              <RelatedRecord icon={AssignmentIcon} label="Application" value={instance.applicationId} path={instance.applicationId ? `/console/org/operate/applications/${instance.applicationId}` : null} />
              <RelatedRecord icon={BadgeIcon} label="Issued credential" value={instance.credentialId} path={instance.credentialId ? `/console/org/operate/issuance/${instance.credentialId}` : null} />
              <RelatedRecord icon={LocalShippingIcon} label="Passport job" value={jobId ? `${jobId}${jobStatus ? ` (${jobStatus})` : ''}` : null} />
            </Box>
          </Paper>

          <Box sx={{ display: 'grid', gridTemplateColumns: { xs: '1fr', lg: 'minmax(0, 2fr) minmax(260px, 1fr)' }, gap: 3 }}>
            <Box>
              <Typography variant="h6" gutterBottom>Runtime timeline</Typography>
              <InstanceTimeline instance={instance} />
            </Box>
            <Box>
              <Typography variant="h6" gutterBottom>Execution details</Typography>
              <Stack spacing={1.5}>
                <RelatedRecord icon={AccountTreeIcon} label="Instance ID" value={instance.id} />
                <RelatedRecord icon={AssignmentIcon} label="External reference" value={instance.externalReference} />
                <Box><Typography variant="caption" color="text.secondary">Started</Typography><Typography variant="body2">{formatDate(instance.startedAt)}</Typography></Box>
                <Box><Typography variant="caption" color="text.secondary">Completed</Typography><Typography variant="body2">{formatDate(instance.completedAt)}</Typography></Box>
                {instance.error_code && <Alert severity="error">Error code: {instance.error_code}</Alert>}
              </Stack>
            </Box>
          </Box>
        </Stack>
      )}
    </ResourcePage>
  );
}

function ScopedFlowInstancesPage({ instanceId, organizationId }) {
  const [searchQuery, setSearchQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState('all');

  const { data = [], loading, error, reload } = useAsyncData(async () => {
    if (!organizationId) throw new Error('Select an organization before loading flow instances.');
    const [flowsResponse, instancesResponse] = await Promise.all([
      listFlows({ organization_id: organizationId }),
      instanceId
        ? getFlowInstance(instanceId, { organizationId }).then((instance) => [requireInstanceScope(instance, organizationId, instanceId)])
        : listFlowInstances({ organization_id: organizationId, limit: 500 }),
    ]);
    if (!Array.isArray(flowsResponse) || !Array.isArray(instancesResponse)) throw new Error('Flow catalog response is malformed.');
    const flows = flowsResponse;
    if (flows.some((flow) => flow.organization_id !== organizationId)) throw new Error('Flow definitions are not available in the selected organization.');
    const flowById = new Map(flows.map((flow) => [String(flow.id), flow]));
    const instances = instancesResponse.map((instance) => requireInstanceScope(instance, organizationId));
    return instances.map((instance) => normalizeInstance(instance, flowById.get(String(instance.flow_id || instance.flowId || ''))));
  }, [instanceId, organizationId]);

  const instances = useMemo(() => !error && Array.isArray(data) ? data : [], [data, error]);
  const selectedInstance = instanceId ? instances[0] || null : null;
  const filteredInstances = useMemo(() => {
    const query = searchQuery.trim().toLowerCase();
    return instances.filter((instance) => {
      const searchable = [instance.id, instance.flowName, instance.flowType, instance.applicationId, instance.credentialId]
        .filter(Boolean)
        .join(' ')
        .toLowerCase();
      return (!query || searchable.includes(query))
        && (statusFilter === 'all' || instance.status === statusFilter);
    });
  }, [instances, searchQuery, statusFilter]);

  if (instanceId) return <InstanceDetail instance={selectedInstance} organizationId={organizationId} loading={loading} error={error} reload={reload} />;

  return (
    <ResourcePage
      title="Flow Instances"
      description="The operational record of every MIP flow execution and its related product records."
      tabs={OPERATE_TABS}
      breadcrumbs={[
        { label: 'Console', path: '/console' },
        { label: 'Operate', path: '/console/org/operate' },
        { label: 'Flow Instances', path: '/console/org/operate/flow-instances' },
      ]}
      actions={<Button variant="outlined" startIcon={<RefreshIcon />} onClick={reload} disabled={loading}>Refresh</Button>}
    >
      {error && <Alert severity="error" sx={{ mb: 3 }}>{error?.message || String(error)}</Alert>}
      <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 2, mb: 3 }}>
        <TextField
          placeholder="Search instances or related records"
          value={searchQuery}
          onChange={(event) => setSearchQuery(event.target.value)}
          size="small"
          sx={{ width: { xs: '100%', sm: 360 } }}
          slotProps={{
            input: { startAdornment: <InputAdornment position="start"><SearchIcon color="action" /></InputAdornment> }
          }}
        />
        <FormControl size="small" sx={{ minWidth: 170 }}>
          <InputLabel>Status</InputLabel>
          <Select value={statusFilter} label="Status" onChange={(event) => setStatusFilter(event.target.value)}>
            <MenuItem value="all">All statuses</MenuItem>
            <MenuItem value="pending">Running</MenuItem>
            <MenuItem value="awaiting_approval">Awaiting approval</MenuItem>
            <MenuItem value="completed">Completed</MenuItem>
            <MenuItem value="failed">Failed</MenuItem>
          </Select>
        </FormControl>
      </Box>
      {loading ? <LinearProgress /> : error ? null : instances.length === 0 ? (
        <EmptyState {...EmptyStates.flowInstances} />
      ) : (
        <TableContainer component={Paper} variant="outlined">
          <Table>
            <TableHead><TableRow><TableCell>Instance</TableCell><TableCell>Flow</TableCell><TableCell>Current step</TableCell><TableCell>Related record</TableCell><TableCell>Started</TableCell><TableCell>Status</TableCell><TableCell align="right">Details</TableCell></TableRow></TableHead>
            <TableBody>
              {filteredInstances.length === 0 ? (
                <TableRow><TableCell colSpan={7} align="center"><Typography color="text.secondary" sx={{ py: 4 }}>No matching flow instances</Typography></TableCell></TableRow>
              ) : filteredInstances.map((instance) => (
                <TableRow key={instance.id} hover>
                  <TableCell><Typography variant="body2" sx={{ fontFamily: 'monospace' }}>{instance.id}</Typography></TableCell>
                  <TableCell><MuiLink component={Link} to={instance.flowId ? `/console/org/flows/definitions/${instance.flowId}` : '#'}>{instance.flowName}</MuiLink><Typography variant="caption" display="block" color="text.secondary">{instance.flowType.replaceAll('_', ' ')}</Typography></TableCell>
                  <TableCell><Typography variant="body2">{instance.currentStep?.replaceAll('_', ' ') || 'Waiting'}</Typography>{instance.currentStepNumber && instance.totalSteps && <Typography variant="caption" color="text.secondary">Step {instance.currentStepNumber} of {instance.totalSteps}</Typography>}</TableCell>
                  <TableCell>{instance.applicationId ? <Chip size="small" label="Application" /> : instance.credentialId ? <Chip size="small" label="Credential" /> : instance.physicalJob ? <Chip size="small" label={`Physical: ${instance.physicalJob.status || 'pending'}`} /> : <Typography variant="caption" color="text.secondary">None</Typography>}</TableCell>
                  <TableCell>{formatDate(instance.startedAt)}</TableCell>
                  <TableCell><StatusChip status={displayStatus(instance.status)} /></TableCell>
                  <TableCell align="right"><Tooltip title="View runtime details"><IconButton component={Link} to={`/console/org/operate/flow-instances/${instance.id}`} size="small" aria-label={`View flow instance ${instance.id}`}><VisibilityIcon fontSize="small" /></IconButton></Tooltip></TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>
      )}
    </ResourcePage>
  );
}

export default function FlowInstancesPage() {
  const { instanceId: routeInstanceId } = useParams();
  const instanceMatch = useMatch('/console/org/operate/flow-instances/:instanceId');
  const instanceId = routeInstanceId || instanceMatch?.params?.instanceId;
  const { activeOrgId: organizationId } = useConsole();
  return <ScopedFlowInstancesPage key={`${organizationId || 'none'}:${instanceId || 'list'}`} instanceId={instanceId} organizationId={organizationId} />;
}

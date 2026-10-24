import { useEffect, useState } from 'react';
import { Link as RouterLink } from 'react-router';
import {
  Alert,
  Box,
  Button,
  Chip,
  CircularProgress,
  Paper,
  Stack,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableRow,
  Typography,
} from '@mui/material';
import AddIcon from '@mui/icons-material/Add';
import PolicyIcon from '@mui/icons-material/Policy';

import { useConsole } from '../../../contexts/ConsoleContext';
import { usePermissions } from '../../../hooks/usePermissions';
import { listPolicySets } from '../../../services/policySetsApi';
import { ResourcePage } from '../../common';
import { requirePolicySetList } from './policySetGuards';

const ScopedPolicySets = ({ organizationId, canView, canCreate, grantsLoading }) => {
  const [items, setItems] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [revision, setRevision] = useState(0);

  useEffect(() => {
    let current = true;
    setItems([]); setError(''); setLoading(true);
    if (canView && !grantsLoading) listPolicySets(organizationId)
      .then((records) => { const scoped = requirePolicySetList(records, organizationId); if (current) setItems(scoped); })
      .catch((cause) => { if (current) setError(cause.message || 'Policy Sets could not be loaded.'); })
      .finally(() => { if (current) setLoading(false); });
    return () => { current = false; };
  }, [organizationId, canView, grantsLoading, revision]);

  return (
    <ResourcePage
      title="Policy Sets"
      description="Reusable Cedar decisions for access, verification, and application approval."
      breadcrumbs={[
        { label: 'Console', path: '/console' },
        { label: 'Govern', path: '/console/org/govern' },
        { label: 'Policy Sets', path: '/console/org/policies/sets' },
      ]}
      actions={<Stack direction="row" spacing={1}>
        {canView && <Button disabled={grantsLoading} onClick={() => setRevision((value) => value + 1)}>Refresh</Button>}
        {canCreate && !grantsLoading && <Button component={RouterLink} to="/console/org/policies/sets/new" variant="contained" startIcon={<AddIcon />}>Create Policy Set</Button>}
      </Stack>}
    >
      {error && <Alert severity="error" sx={{ mb: 2 }}>{error}</Alert>}
      {grantsLoading ? <CircularProgress /> : !canView ? <Alert severity="warning">You do not have permission to view Policy Sets in this organization.</Alert> : loading ? (
        <Box sx={{ display: 'flex', justifyContent: 'center', py: 8 }}><CircularProgress /></Box>
      ) : error ? null : items.length === 0 ? (
        <Paper variant="outlined" sx={{ p: 4, textAlign: 'center' }}>
          <PolicyIcon color="action" sx={{ fontSize: 40 }} />
          <Typography variant="h6" sx={{ mt: 1 }}>No Policy Sets</Typography>
          {canCreate && <Button component={RouterLink} to="/console/org/policies/sets/new" startIcon={<AddIcon />} sx={{ mt: 2 }}>Create Policy Set</Button>}
        </Paper>
      ) : (
        <Paper variant="outlined">
          <Table>
            <TableHead><TableRow><TableCell>Name</TableCell><TableCell>Type</TableCell><TableCell>Status</TableCell><TableCell>Policies</TableCell></TableRow></TableHead>
            <TableBody>
              {items.map((item) => (
                <TableRow key={item.id} hover component={RouterLink} to={`/console/org/policies/sets/${item.id}`} sx={{ textDecoration: 'none' }}>
                  <TableCell><Stack><Typography variant="body2" fontWeight={600}>{item.name}</Typography><Typography variant="caption" color="text.secondary">{item.description}</Typography></Stack></TableCell>
                  <TableCell>{item.policy_type}</TableCell>
                  <TableCell><Chip size="small" label={item.status} color={item.status === 'ACTIVE' ? 'success' : 'default'} /></TableCell>
                  <TableCell>{item.cedar_policies?.length || 0}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </Paper>
      )}
    </ResourcePage>
  );
};

export default function PolicySetsPage() {
  const { activeOrgId: organizationId } = useConsole();
  const { can, isLoading } = usePermissions();
  if (!organizationId) return <Alert severity="info">Select an organization to inspect its Policy Sets.</Alert>;
  return <ScopedPolicySets key={organizationId} organizationId={organizationId} canView={can('policy-set', 'view')}
    canCreate={can('policy-set', 'create')} grantsLoading={isLoading} />;
}

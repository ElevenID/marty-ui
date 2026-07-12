import { useEffect, useState } from 'react';
import { Link as RouterLink } from 'react-router-dom';
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
import { listPolicySets } from '../../../services/policySetsApi';
import { ResourcePage } from '../../common';

const PolicySetsPage = () => {
  const { activeOrgId: organizationId } = useConsole();
  const [items, setItems] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    if (!organizationId) return;
    listPolicySets(organizationId)
      .then(setItems)
      .catch((cause) => setError(cause.message))
      .finally(() => setLoading(false));
  }, [organizationId]);

  return (
    <ResourcePage
      title="Policy Sets"
      description="Reusable Cedar decisions for access, verification, and application approval."
      breadcrumbs={[
        { label: 'Console', path: '/console' },
        { label: 'Govern', path: '/console/org/govern' },
        { label: 'Policy Sets', path: '/console/org/policies/sets' },
      ]}
      actions={<Button component={RouterLink} to="/console/org/policies/sets/new" variant="contained" startIcon={<AddIcon />}>Create Policy Set</Button>}
    >
      {error && <Alert severity="error" sx={{ mb: 2 }}>{error}</Alert>}
      {loading ? (
        <Box sx={{ display: 'flex', justifyContent: 'center', py: 8 }}><CircularProgress /></Box>
      ) : items.length === 0 ? (
        <Paper variant="outlined" sx={{ p: 4, textAlign: 'center' }}>
          <PolicyIcon color="action" sx={{ fontSize: 40 }} />
          <Typography variant="h6" sx={{ mt: 1 }}>No Policy Sets</Typography>
          <Button component={RouterLink} to="/console/org/policies/sets/new" startIcon={<AddIcon />} sx={{ mt: 2 }}>Create Policy Set</Button>
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

export default PolicySetsPage;

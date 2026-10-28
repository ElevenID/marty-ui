import { useCallback, useEffect, useRef, useState } from 'react';
import { useAsyncData } from '../../../hooks/useAsyncData';
import {
  Alert,
  Box,
  Button,
  Chip,
  CircularProgress,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  Paper,
  Stack,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableRow,
  TextField,
  Typography,
} from '@mui/material';
import AddIcon from '@mui/icons-material/Add';
import LocalShippingIcon from '@mui/icons-material/LocalShipping';

import { ResourcePage } from '../../common';
import { usePermissions } from '../../../hooks/usePermissions';
import { useConsole } from '../../../contexts/ConsoleContext';
import { createDeliveryDestination, listDeliveryDestinations } from '../../../services/deliveryDestinationsApi';

const INITIAL_FORM = { name: '', description: '' };

function DeliveryDestinations({ organizationId, canCreate }) {
  const mounted = useRef(false);
  useEffect(() => { mounted.current = true; return () => { mounted.current = false; }; }, []);
  const { data, loading, error: loadError, reload, clearError } = useAsyncData(async () => {
    const result = await listDeliveryDestinations({ organizationId, activeOnly: false });
    if (!Array.isArray(result) || !result.every((destination) => typeof destination?.id === 'string'
      && (destination.is_system === true ? destination.organization_id == null : destination.organization_id === organizationId))) {
      throw new Error('Destination inventory is invalid or outside the selected organization.');
    }
    return result;
  }, [organizationId]);
  const destinations = data || [];
  const [actionError, setActionError] = useState('');
  const error = actionError || (loadError ? loadError.message || 'Delivery destinations could not be loaded.' : '');
  const setError = (value) => {
    clearError();
    setActionError(value);
  };
  const [dialogOpen, setDialogOpen] = useState(false);
  const [form, setForm] = useState(INITIAL_FORM);
  const [saving, setSaving] = useState(false);
  const load = useCallback(async () => {
    setActionError('');
    await reload();
  }, [reload]);

  const createPhysicalDestination = async () => {
    if (!canCreate) return;
    setSaving(true);
    setError('');
    try {
      await createDeliveryDestination({
        organization_id: organizationId,
        name: form.name.trim(),
        description: form.description.trim() || null,
        provider: 'physical_document_bureau',
        mode: 'physical_document',
        setup_actor: 'org_admin',
        delivery_target: 'physical_document',
        requires_consent: true,
        capabilities: { physical_document: true, personalization_bureau: true },
        setup_requirements: ['Personalization bureau service configured and approved'],
        is_enabled: true,
      });
      if (!mounted.current) return;
      setDialogOpen(false);
      setForm(INITIAL_FORM);
      await load();
    } catch (cause) {
      if (mounted.current) setError(cause.message || 'The production destination could not be created.');
    } finally {
      if (mounted.current) setSaving(false);
    }
  };

  return (
    <ResourcePage
      title="Delivery Destinations"
      description="Configured wallet, connector, and physical production destinations available to flows."
      breadcrumbs={[
        { label: 'Console', path: '/console' },
        { label: 'Connect', path: '/console/org/connect' },
        { label: 'Delivery Destinations', path: '/console/org/connect/delivery-destinations' },
      ]}
      actions={canCreate && (
        <Button variant="contained" startIcon={<AddIcon />} onClick={() => setDialogOpen(true)}>
          Add Production Destination
        </Button>
      )}
    >
      {error && <Alert severity="error" sx={{ mb: 2 }}>{error}<Button onClick={load}>Reload destinations</Button></Alert>}
      <Alert severity="info" sx={{ mb: 2 }}>Destination configuration does not establish approval, successful delivery or wallet interoperability.</Alert>
      {loading ? (
        <Box sx={{ display: 'flex', justifyContent: 'center', py: 8 }}><CircularProgress /></Box>
      ) : error ? null : destinations.length === 0 ? (
        <Paper variant="outlined" sx={{ p: 4, textAlign: 'center' }}>
          <LocalShippingIcon color="action" sx={{ fontSize: 40 }} />
          <Typography variant="h6" sx={{ mt: 1 }}>No delivery destinations</Typography>
          <Typography variant="body2" color="text.secondary">Add an approved destination before binding a physical issuance flow.</Typography>
        </Paper>
      ) : (
        <Paper variant="outlined">
          <Table>
            <TableHead><TableRow><TableCell>Name</TableCell><TableCell>Provider</TableCell><TableCell>Mode</TableCell><TableCell>Target</TableCell><TableCell>Status</TableCell></TableRow></TableHead>
            <TableBody>
              {destinations.map((destination) => (
                <TableRow key={destination.id} hover>
                  <TableCell><Stack><Typography variant="body2" fontWeight={600}>{destination.name}</Typography><Typography variant="caption" color="text.secondary">{destination.description}</Typography></Stack></TableCell>
                  <TableCell>{destination.provider}</TableCell>
                  <TableCell>{destination.mode}</TableCell>
                  <TableCell>{destination.delivery_target}</TableCell>
                  <TableCell><Chip size="small" label={destination.is_enabled ? 'Enabled' : 'Disabled'} color={destination.is_enabled ? 'success' : 'default'} /></TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </Paper>
      )}

      <Dialog open={dialogOpen} onClose={() => !saving && setDialogOpen(false)} fullWidth maxWidth="sm">
        <DialogTitle>Add physical production destination</DialogTitle>
        <DialogContent>
          <Stack spacing={2} sx={{ pt: 1 }}>
            <Alert severity="info">This destination identifies an approved personalization bureau. Connection secrets remain in deployment configuration.</Alert>
            <TextField required autoFocus label="Destination name" value={form.name} onChange={(event) => setForm((value) => ({ ...value, name: event.target.value }))} />
            <TextField label="Description" multiline minRows={3} value={form.description} onChange={(event) => setForm((value) => ({ ...value, description: event.target.value }))} />
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setDialogOpen(false)} disabled={saving}>Cancel</Button>
          <Button variant="contained" onClick={createPhysicalDestination} disabled={saving || !form.name.trim()}>
            {saving ? 'Adding...' : 'Add Destination'}
          </Button>
        </DialogActions>
      </Dialog>
    </ResourcePage>
  );
}

function DeliveryDestinationsPage() {
  const { activeOrgId } = useConsole();
  const { can, isLoading } = usePermissions();
  if (!activeOrgId) return <Alert severity="error">Select an organization before loading delivery destinations.</Alert>;
  if (isLoading) return <CircularProgress />;
  if (!can('wallet', 'view')) return <Alert severity="error">You do not have permission to view delivery destinations.</Alert>;
  const canCreate = can('integration-connector', 'create');
  return <DeliveryDestinations key={`${activeOrgId}:${canCreate}`} organizationId={activeOrgId} canCreate={canCreate} />;
}

export default DeliveryDestinationsPage;

import { useEffect, useState } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import {
  Alert,
  Box,
  Button,
  Chip,
  CircularProgress,
  Container,
  Paper,
  Stack,
  Typography,
} from '@mui/material';
import ArchiveIcon from '@mui/icons-material/Archive';
import ArrowBackIcon from '@mui/icons-material/ArrowBack';
import PlayArrowIcon from '@mui/icons-material/PlayArrow';

import { useAuth } from '../../../hooks/useAuth';
import { useConsole } from '../../../contexts/ConsoleContext';
import { activatePolicySet, archivePolicySet, getPolicySet } from '../../../services/policySetsApi';

const PolicySetDetailPage = () => {
  const { policySetId } = useParams();
  const navigate = useNavigate();
  const { organizationId: authOrganizationId } = useAuth();
  const { activeOrgId } = useConsole();
  const organizationId = activeOrgId;
  const [policySet, setPolicySet] = useState(null);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (!organizationId) return;
    getPolicySet(organizationId, policySetId).then(setPolicySet).catch((cause) => setError(cause.message));
  }, [organizationId, policySetId]);

  const changeStatus = async (operation) => {
    setBusy(true);
    setError('');
    try {
      setPolicySet(await operation(organizationId, policySetId));
    } catch (cause) {
      setError(cause.message);
    } finally {
      setBusy(false);
    }
  };

  if (!policySet && !error) return <Box sx={{ display: 'flex', justifyContent: 'center', py: 10 }}><CircularProgress /></Box>;

  return (
    <Container maxWidth="md" sx={{ py: 4 }}>
      <Button startIcon={<ArrowBackIcon />} onClick={() => navigate('/console/org/policies/sets')} sx={{ mb: 2 }}>Policy Sets</Button>
      {error && <Alert severity="error" sx={{ mb: 2 }}>{error}</Alert>}
      {policySet && (
        <>
          <Stack direction={{ xs: 'column', sm: 'row' }} justifyContent="space-between" gap={2} sx={{ mb: 3 }}>
            <Box>
              <Typography variant="h4">{policySet.name}</Typography>
              <Typography color="text.secondary">{policySet.description}</Typography>
              <Stack direction="row" gap={1} sx={{ mt: 1 }}>
                <Chip label={policySet.status} color={policySet.status === 'ACTIVE' ? 'success' : 'default'} />
                <Chip label={policySet.policy_type} variant="outlined" />
                <Chip label={policySet.cedar_schema_version} variant="outlined" />
              </Stack>
            </Box>
            {policySet.status === 'DRAFT' ? (
              <Button variant="contained" startIcon={<PlayArrowIcon />} disabled={busy} onClick={() => changeStatus(activatePolicySet)}>Activate</Button>
            ) : policySet.status === 'ACTIVE' ? (
              <Button variant="outlined" startIcon={<ArchiveIcon />} disabled={busy} onClick={() => changeStatus(archivePolicySet)}>Archive</Button>
            ) : null}
          </Stack>

          <Stack spacing={2}>
            {policySet.cedar_policies.map((policy) => (
              <Paper key={policy.policy_id} variant="outlined" sx={{ p: 2.5 }}>
                <Stack direction="row" justifyContent="space-between" alignItems="center">
                  <Typography variant="subtitle1" fontWeight={600}>{policy.description || policy.policy_id}</Typography>
                  <Chip label={policy.effect} size="small" color={policy.effect === 'forbid' ? 'error' : 'success'} variant="outlined" />
                </Stack>
                <Typography variant="caption" color="text.secondary">{policy.policy_id}</Typography>
                <Box component="pre" sx={{ mt: 2, mb: 0, p: 2, overflow: 'auto', bgcolor: 'grey.50', fontSize: 12, whiteSpace: 'pre-wrap' }}>{policy.cedar_text}</Box>
              </Paper>
            ))}
          </Stack>
        </>
      )}
    </Container>
  );
};

export default PolicySetDetailPage;

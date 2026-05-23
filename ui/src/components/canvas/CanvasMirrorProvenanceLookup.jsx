import { useEffect, useMemo, useState } from 'react';
import {
  Alert,
  Box,
  Button,
  Chip,
  CircularProgress,
  Divider,
  Paper,
  Stack,
  TextField,
  ToggleButton,
  ToggleButtonGroup,
  Typography,
} from '@mui/material';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import ErrorOutlineIcon from '@mui/icons-material/ErrorOutline';
import SearchIcon from '@mui/icons-material/Search';
import VerifiedUserIcon from '@mui/icons-material/VerifiedUser';

import { getCanvasMirrorProvenance } from '../../services/canvasIntegrationsApi';

const LOOKUP_MODES = [
  { value: 'externalCredentialId', label: 'Canvas ID', query: 'external_credential_id' },
  { value: 'deliveryRecordId', label: 'Delivery ID', query: 'delivery_record_id' },
  { value: 'credentialId', label: 'Credential ID', query: 'credential_id' },
];

export function canvasLookupModeFromParams(searchParams) {
  return LOOKUP_MODES.find((mode) => searchParams.get(mode.query))?.value || 'externalCredentialId';
}

export function canvasLookupValueFromParams(searchParams, modeValue) {
  const mode = LOOKUP_MODES.find((item) => item.value === modeValue) || LOOKUP_MODES[0];
  return searchParams.get(mode.query) || '';
}

function formatDate(value) {
  if (!value) return 'Not recorded';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return String(value);
  return date.toLocaleString(undefined, {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });
}

function display(value) {
  if (value === true) return 'Yes';
  if (value === false) return 'No';
  return value || 'Not recorded';
}

function statusColor(status) {
  const normalized = String(status || '').toLowerCase();
  if (['active', 'delivered'].includes(normalized)) return 'success';
  if (['revoked', 'failed'].includes(normalized)) return 'error';
  if (['suspended', 'pending', 'expired'].includes(normalized)) return 'warning';
  return 'default';
}

function Detail({ label, value, mono = false }) {
  return (
    <Stack spacing={0.5} sx={{ minWidth: 0 }}>
      <Typography variant="caption" color="text.secondary" sx={{ textTransform: 'uppercase', fontWeight: 700 }}>
        {label}
      </Typography>
      <Typography
        variant="body2"
        sx={{
          fontFamily: mono ? 'ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace' : undefined,
          overflowWrap: 'anywhere',
        }}
      >
        {display(value)}
      </Typography>
    </Stack>
  );
}

function ResultPanel({ title, children }) {
  return (
    <Paper
      elevation={0}
      sx={{
        border: '1px solid',
        borderColor: 'divider',
        borderRadius: 1,
        p: { xs: 2, md: 2.5 },
      }}
    >
      <Typography variant="subtitle1" sx={{ mb: 2, fontWeight: 700 }}>
        {title}
      </Typography>
      <Stack spacing={2}>{children}</Stack>
    </Paper>
  );
}

function initialValueForMode(initialParams, mode) {
  if (mode === 'deliveryRecordId') return initialParams.deliveryRecordId || '';
  if (mode === 'credentialId') return initialParams.credentialId || '';
  return initialParams.externalCredentialId || '';
}

function CanvasMirrorProvenanceLookup({
  initialParams = {},
  organizationId,
  title = 'Canvas mirror verification',
  description = 'Resolve a Canvas Credentials mirror to its canonical ElevenID issuance record.',
  showOrganizationField = true,
  onResolved,
}) {
  const initialMode = useMemo(() => {
    if (initialParams.deliveryRecordId) return 'deliveryRecordId';
    if (initialParams.credentialId) return 'credentialId';
    return 'externalCredentialId';
  }, [initialParams.credentialId, initialParams.deliveryRecordId]);
  const [lookupMode, setLookupMode] = useState(initialMode);
  const [lookupValue, setLookupValue] = useState(() => initialValueForMode(initialParams, initialMode));
  const [canvasAccountId, setCanvasAccountId] = useState(initialParams.canvasAccountId || '');
  const [selectedOrganizationId, setSelectedOrganizationId] = useState(initialParams.organizationId || organizationId || '');
  const [provenance, setProvenance] = useState(null);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  async function resolveProvenance() {
    const value = lookupValue.trim();
    if (!value) {
      setError('Choose a lookup value.');
      setProvenance(null);
      return;
    }
    const params = {
      [lookupMode]: value,
      canvasAccountId: canvasAccountId.trim() || undefined,
      organizationId: (selectedOrganizationId || organizationId || '').trim() || undefined,
    };

    setLoading(true);
    setError('');
    try {
      const data = await getCanvasMirrorProvenance(params);
      setProvenance(data);
      onResolved?.(data);
    } catch (err) {
      setProvenance(null);
      setError(err?.message || 'Canvas mirror could not be resolved.');
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    if (initialValueForMode(initialParams, initialMode).trim()) {
      resolveProvenance();
    }
    // Run only for URL/prop-provided initial lookup.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const credential = provenance?.canonical_credential || {};
  const issuance = provenance?.canonical_issuance || {};
  const mirror = provenance?.mirror || {};
  const issuer = provenance?.issuer || {};
  const trust = provenance?.trust_basis || {};
  const statusListEntry = Array.isArray(credential.status_list_entries) ? credential.status_list_entries[0] : null;
  const trusted = Boolean(trust.canonical_issuance_backed && trust.mirror_backed_by_delivery_record);

  return (
    <Paper elevation={0} sx={{ border: '1px solid', borderColor: 'divider', borderRadius: 1, p: { xs: 2, md: 2.5 } }}>
      <Stack spacing={2.5}>
        <Stack direction={{ xs: 'column', sm: 'row' }} spacing={1.5} alignItems={{ sm: 'center' }}>
          <VerifiedUserIcon color="primary" />
          <Box>
            <Typography variant="h6" sx={{ fontWeight: 800 }}>
              {title}
            </Typography>
            <Typography variant="body2" color="text.secondary">
              {description}
            </Typography>
          </Box>
        </Stack>

        <Box
          component="form"
          data-testid="canvas-provenance-form"
          onSubmit={(event) => {
            event.preventDefault();
            resolveProvenance();
          }}
        >
          <Stack spacing={2}>
            <ToggleButtonGroup
              value={lookupMode}
              exclusive
              size="small"
              onChange={(_event, value) => {
                if (!value) return;
                setLookupMode(value);
                setLookupValue('');
                setProvenance(null);
                setError('');
              }}
              aria-label="Canvas mirror lookup mode"
            >
              {LOOKUP_MODES.map((mode) => (
                <ToggleButton key={mode.value} value={mode.value}>
                  {mode.label}
                </ToggleButton>
              ))}
            </ToggleButtonGroup>

            <Box
              sx={{
                display: 'grid',
                gap: 1.5,
                gridTemplateColumns: {
                  xs: '1fr',
                  md: showOrganizationField ? 'minmax(0, 1.5fr) minmax(0, 1fr) minmax(0, 1fr) auto' : 'minmax(0, 1.5fr) minmax(0, 1fr) auto',
                },
                alignItems: 'center',
              }}
            >
              <TextField
                label={LOOKUP_MODES.find((mode) => mode.value === lookupMode)?.label || 'Lookup ID'}
                value={lookupValue}
                onChange={(event) => setLookupValue(event.target.value)}
                inputProps={{ 'data-testid': 'canvas-provenance-lookup' }}
                fullWidth
              />
              <TextField
                label="Canvas Account"
                value={canvasAccountId}
                onChange={(event) => setCanvasAccountId(event.target.value)}
                fullWidth
              />
              {showOrganizationField && (
                <TextField
                  label="Organization"
                  value={selectedOrganizationId}
                  onChange={(event) => setSelectedOrganizationId(event.target.value)}
                  fullWidth
                />
              )}
              <Button
                type="submit"
                variant="contained"
                startIcon={loading ? <CircularProgress size={18} color="inherit" /> : <SearchIcon />}
                disabled={loading}
                sx={{ minHeight: 48, whiteSpace: 'nowrap' }}
              >
                Resolve
              </Button>
            </Box>
          </Stack>
        </Box>

        {error ? <Alert severity="error" icon={<ErrorOutlineIcon />}>{error}</Alert> : null}

        {provenance ? (
          <Stack spacing={2.5} data-testid="canvas-provenance-result">
            <Paper
              elevation={0}
              sx={{
                border: '1px solid',
                borderColor: trusted ? 'success.main' : 'warning.main',
                borderRadius: 1,
                p: 2,
              }}
            >
              <Stack direction={{ xs: 'column', md: 'row' }} spacing={1.5} alignItems={{ md: 'center' }} justifyContent="space-between">
                <Stack direction="row" spacing={1.5} alignItems="center">
                  <CheckCircleIcon color={trusted ? 'success' : 'warning'} />
                  <Box>
                    <Typography variant="subtitle1" sx={{ fontWeight: 800 }}>
                      {trusted ? 'Canonical issuance found' : 'Mirror needs review'}
                    </Typography>
                    <Typography variant="body2" color="text.secondary">
                      {issuer.issuer_did || 'Issuer DID not recorded'}
                    </Typography>
                  </Box>
                </Stack>
                <Stack direction="row" spacing={1} useFlexGap flexWrap="wrap">
                  <Chip size="small" label={credential.credential_status || 'UNKNOWN'} color={statusColor(credential.credential_status)} />
                  <Chip size="small" label={mirror.delivery_status || 'delivery unknown'} color={statusColor(mirror.delivery_status)} variant="outlined" />
                  <Chip size="small" label={trust.distribution_channel || 'canvas_credentials'} variant="outlined" />
                </Stack>
              </Stack>
            </Paper>

            <Box
              sx={{
                display: 'grid',
                gap: 2,
                gridTemplateColumns: { xs: '1fr', lg: 'repeat(2, minmax(0, 1fr))' },
              }}
            >
              <ResultPanel title="Canonical credential">
                <Detail label="Credential ID" value={credential.credential_id} mono />
                <Detail label="Template" value={credential.credential_template_id} mono />
                <Detail label="Format" value={credential.credential_format} />
                <Detail label="Issued" value={formatDate(credential.issued_at)} />
                <Detail label="Subject Hash" value={credential.subject_id_hash} mono />
              </ResultPanel>

              <ResultPanel title="Issuer">
                <Detail label="Issuer DID" value={issuer.issuer_did} mono />
                <Detail label="Issuer Profile" value={issuer.issuer_profile_id} mono />
                <Detail label="Issuer Mode" value={issuer.issuer_mode} />
                <Detail label="Credential Issuer URL" value={issuer.credential_issuer_url} mono />
              </ResultPanel>

              <ResultPanel title="Canvas mirror">
                <Detail label="External Credential" value={mirror.external_credential_id} mono />
                <Detail label="External Issuer" value={mirror.external_issuer_id} mono />
                <Detail label="Canvas Account" value={provenance.canvas_account_id} mono />
                <Detail label="Published" value={formatDate(mirror.metadata?.published_at)} />
              </ResultPanel>

              <ResultPanel title="Trust basis">
                <Detail label="Canonical Backing" value={trust.canonical_issuance_backed} />
                <Detail label="Mirror Record" value={trust.mirror_backed_by_delivery_record} />
                <Detail label="Organization Match" value={trust.organization_consistent} />
                <Detail label="Issuance Transaction" value={issuance.transaction_id} mono />
                <Divider />
                <Detail label="Application" value={issuance.application_id} mono />
              </ResultPanel>

              <ResultPanel title="Revocation status">
                <Detail label="Revocation Profile" value={credential.revocation_profile_id} mono />
                <Detail label="Status Purpose" value={statusListEntry?.status_purpose} />
                <Detail label="Status List Index" value={statusListEntry?.index} />
                <Detail label="Status List URI" value={statusListEntry?.status_list_uri} mono />
              </ResultPanel>
            </Box>
          </Stack>
        ) : null}
      </Stack>
    </Paper>
  );
}

export default CanvasMirrorProvenanceLookup;

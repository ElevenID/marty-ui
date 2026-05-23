import { useEffect, useMemo, useState } from 'react';
import {
  Alert,
  Box,
  Button,
  Chip,
  CircularProgress,
  Container,
  Divider,
  Paper,
  Stack,
  TextField,
  Typography,
} from '@mui/material';
import BusinessCenterIcon from '@mui/icons-material/BusinessCenter';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import ErrorOutlineIcon from '@mui/icons-material/ErrorOutline';
import OpenInNewIcon from '@mui/icons-material/OpenInNew';
import SearchIcon from '@mui/icons-material/Search';
import WorkspacePremiumIcon from '@mui/icons-material/WorkspacePremium';
import { useSearchParams } from 'react-router-dom';

import { getCanvasMirrorProvenance } from '../../services/canvasIntegrationsApi';

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

function VerificationCheck({ label, value }) {
  return (
    <Stack direction="row" spacing={1.25} alignItems="center">
      <CheckCircleIcon color={value ? 'success' : 'disabled'} fontSize="small" />
      <Typography variant="body2">{label}</Typography>
    </Stack>
  );
}

function lookupParams(searchParams) {
  return {
    externalCredentialId: searchParams.get('external_credential_id') || '',
    credentialId: searchParams.get('credential_id') || '',
    deliveryRecordId: searchParams.get('delivery_record_id') || '',
    canvasAccountId: searchParams.get('canvas_account_id') || '',
    organizationId: searchParams.get('organization_id') || '',
  };
}

function EmployerCanvasBadgeVerificationPage() {
  const [searchParams, setSearchParams] = useSearchParams();
  const initial = useMemo(() => lookupParams(searchParams), [searchParams]);
  const [lookupValue, setLookupValue] = useState(
    initial.externalCredentialId || initial.credentialId || initial.deliveryRecordId,
  );
  const [canvasAccountId, setCanvasAccountId] = useState(initial.canvasAccountId);
  const [organizationId, setOrganizationId] = useState(initial.organizationId);
  const [provenance, setProvenance] = useState(null);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const lookupMode = initial.credentialId
    ? 'credentialId'
    : initial.deliveryRecordId
      ? 'deliveryRecordId'
      : 'externalCredentialId';

  async function verifyBadge({ updateUrl = true } = {}) {
    const value = lookupValue.trim();
    if (!value) {
      setError('Enter a Canvas credential ID or canonical credential ID.');
      setProvenance(null);
      return;
    }

    const params = {
      [lookupMode]: value,
      canvasAccountId: canvasAccountId.trim() || undefined,
      organizationId: organizationId.trim() || undefined,
    };

    setLoading(true);
    setError('');
    try {
      const data = await getCanvasMirrorProvenance(params);
      setProvenance(data);
      if (updateUrl) {
        const next = new URLSearchParams();
        const queryKey = lookupMode === 'credentialId'
          ? 'credential_id'
          : lookupMode === 'deliveryRecordId'
            ? 'delivery_record_id'
            : 'external_credential_id';
        next.set(queryKey, value);
        if (canvasAccountId.trim()) next.set('canvas_account_id', canvasAccountId.trim());
        if (organizationId.trim()) next.set('organization_id', organizationId.trim());
        setSearchParams(next, { replace: true });
      }
    } catch (err) {
      setProvenance(null);
      setError(err?.message || 'The badge could not be verified.');
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    if (lookupValue.trim()) {
      verifyBadge({ updateUrl: false });
    }
    // Run only for URL-provided verification links.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const credential = provenance?.canonical_credential || {};
  const mirror = provenance?.mirror || {};
  const issuer = provenance?.issuer || {};
  const trust = provenance?.trust_basis || {};
  const verified = Boolean(
    trust.canonical_issuance_backed
      && trust.mirror_backed_by_delivery_record
      && trust.organization_consistent
      && String(credential.credential_status || trust.credential_status || '').toLowerCase() === 'active',
  );
  const badgeName = credential.credential_name || 'Canvas Credential';
  const canvasCredentialUrl = mirror.metadata?.publish_response?.credential_url
    || mirror.metadata?.credential_url
    || mirror.metadata?.open_badge_id
    || mirror.metadata?.publish_response?.openBadgeId
    || '';

  return (
    <Box sx={{ bgcolor: 'background.default', minHeight: 'calc(100vh - 72px)', py: { xs: 4, md: 7 } }}>
      <Container maxWidth="lg">
        <Stack spacing={3}>
          <Paper
            elevation={0}
            sx={{
              border: '1px solid',
              borderColor: 'divider',
              borderRadius: 2,
              p: { xs: 3, md: 4 },
            }}
          >
            <Stack spacing={3}>
              <Stack direction={{ xs: 'column', md: 'row' }} spacing={2} alignItems={{ md: 'center' }} justifyContent="space-between">
                <Stack direction="row" spacing={1.5} alignItems="center">
                  <BusinessCenterIcon color="primary" sx={{ fontSize: 40 }} />
                  <Box>
                    <Typography variant="h4" component="h1" sx={{ fontSize: { xs: '1.75rem', md: '2.25rem' }, fontWeight: 800 }}>
                      Badge Verification
                    </Typography>
                    <Typography color="text.secondary">
                      Verify that a Canvas-earned badge is backed by an external ElevenID issuance record.
                    </Typography>
                  </Box>
                </Stack>
                {provenance ? (
                  <Chip
                    icon={<CheckCircleIcon />}
                    label={verified ? 'Verified for employer review' : 'Needs review'}
                    color={verified ? 'success' : 'warning'}
                    sx={{ alignSelf: { xs: 'flex-start', md: 'center' } }}
                  />
                ) : null}
              </Stack>

              <Box
                component="form"
                data-testid="employer-canvas-verification-form"
                onSubmit={(event) => {
                  event.preventDefault();
                  verifyBadge();
                }}
              >
                <Box
                  sx={{
                    display: 'grid',
                    gap: 2,
                    gridTemplateColumns: { xs: '1fr', md: 'minmax(0, 1.6fr) minmax(0, 1fr) minmax(0, 1fr) auto' },
                    alignItems: 'center',
                  }}
                >
                  <TextField
                    label="Canvas Credential ID"
                    value={lookupValue}
                    onChange={(event) => setLookupValue(event.target.value)}
                    inputProps={{ 'data-testid': 'employer-canvas-lookup' }}
                    fullWidth
                  />
                  <TextField
                    label="Canvas Account"
                    value={canvasAccountId}
                    onChange={(event) => setCanvasAccountId(event.target.value)}
                    fullWidth
                  />
                  <TextField
                    label="Organization"
                    value={organizationId}
                    onChange={(event) => setOrganizationId(event.target.value)}
                    fullWidth
                  />
                  <Button
                    type="submit"
                    variant="contained"
                    startIcon={loading ? <CircularProgress size={18} color="inherit" /> : <SearchIcon />}
                    disabled={loading}
                    sx={{ minHeight: 48, whiteSpace: 'nowrap' }}
                  >
                    Verify Badge
                  </Button>
                </Box>
              </Box>
            </Stack>
          </Paper>

          {error ? <Alert severity="error" icon={<ErrorOutlineIcon />}>{error}</Alert> : null}

          {provenance ? (
            <Stack spacing={3} data-testid="employer-canvas-verification-result">
              <Paper
                elevation={0}
                sx={{
                  border: '1px solid',
                  borderColor: verified ? 'success.main' : 'warning.main',
                  borderRadius: 2,
                  p: { xs: 3, md: 4 },
                }}
              >
                <Stack spacing={3}>
                  <Stack direction={{ xs: 'column', md: 'row' }} spacing={2.5} justifyContent="space-between">
                    <Stack direction="row" spacing={2} alignItems="flex-start">
                      <WorkspacePremiumIcon color="primary" sx={{ fontSize: 44 }} />
                      <Box>
                        <Typography variant="h5" component="h2" sx={{ fontWeight: 800 }}>
                          {badgeName}
                        </Typography>
                        <Typography color="text.secondary" sx={{ mt: 0.5 }}>
                          Earned in Canvas, issued by Marty, and verified outside Canvas.
                        </Typography>
                      </Box>
                    </Stack>
                    <Stack direction="row" spacing={1} useFlexGap flexWrap="wrap">
                      <Chip label={credential.credential_status || 'UNKNOWN'} color={statusColor(credential.credential_status)} />
                      <Chip label={mirror.delivery_status || 'mirror unknown'} color={statusColor(mirror.delivery_status)} variant="outlined" />
                      <Chip label="Open Badge" variant="outlined" />
                    </Stack>
                  </Stack>

                  <Divider />

                  <Box
                    sx={{
                      display: 'grid',
                      gap: 3,
                      gridTemplateColumns: { xs: '1fr', md: 'repeat(3, minmax(0, 1fr))' },
                    }}
                  >
                    <Stack spacing={1.25}>
                      <Typography variant="subtitle1" sx={{ fontWeight: 800 }}>
                        Employer Checks
                      </Typography>
                      <VerificationCheck label="Canonical issuance exists" value={trust.canonical_issuance_backed} />
                      <VerificationCheck label="Canvas mirror is linked to issuance" value={trust.mirror_backed_by_delivery_record} />
                      <VerificationCheck label="Organization and issuer match" value={trust.organization_consistent} />
                    </Stack>
                    <Stack spacing={2}>
                      <Typography variant="subtitle1" sx={{ fontWeight: 800 }}>
                        Issuer
                      </Typography>
                      <Detail label="Issuer DID" value={issuer.issuer_did} mono />
                      <Detail label="Issuer Profile" value={issuer.issuer_profile_id} mono />
                      <Detail label="Issuer Mode" value={issuer.issuer_mode} />
                    </Stack>
                    <Stack spacing={2}>
                      <Typography variant="subtitle1" sx={{ fontWeight: 800 }}>
                        Status
                      </Typography>
                      <Detail label="Issued" value={formatDate(credential.issued_at)} />
                      <Detail label="Subject Hash" value={credential.subject_id_hash} mono />
                      <Detail label="Distribution" value={trust.distribution_channel || mirror.delivery_target} />
                    </Stack>
                  </Box>

                  <Divider />

                  <Box
                    sx={{
                      display: 'grid',
                      gap: 2,
                      gridTemplateColumns: { xs: '1fr', md: 'repeat(2, minmax(0, 1fr))' },
                    }}
                  >
                    <Detail label="Canvas Credential ID" value={mirror.external_credential_id} mono />
                    <Detail label="Canonical Credential ID" value={credential.credential_id} mono />
                    <Detail label="Canvas Account" value={provenance.canvas_account_id} mono />
                    <Detail label="Published to Canvas Credentials" value={formatDate(mirror.metadata?.published_at)} />
                  </Box>

                  {canvasCredentialUrl ? (
                    <Box>
                      <Button
                        href={canvasCredentialUrl}
                        target="_blank"
                        rel="noreferrer"
                        variant="outlined"
                        endIcon={<OpenInNewIcon />}
                      >
                        View Canvas Credential Mirror
                      </Button>
                    </Box>
                  ) : null}
                </Stack>
              </Paper>
            </Stack>
          ) : null}
        </Stack>
      </Container>
    </Box>
  );
}

export default EmployerCanvasBadgeVerificationPage;

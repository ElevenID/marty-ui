import { useEffect, useLayoutEffect, useMemo, useRef, useState } from 'react';
import { useNavigate } from 'react-router';
import {
  Alert,
  Box,
  Button,
  CircularProgress,
  Container,
  FormControl,
  InputLabel,
  MenuItem,
  Paper,
  Select,
  Stack,
  TextField,
  Typography,
} from '@mui/material';
import ArrowBackIcon from '@mui/icons-material/ArrowBack';

import issuerIdentitiesApi from '../../../services/issuerIdentitiesApi';
import { useAuth } from '../../../hooks/useAuth';
import { useConsole } from '../../../contexts/ConsoleContext';
import { useNotifications } from '../../../hooks/useNotifications';

const PURPOSE_LABELS = {
  vc_jwt_issuer: 'Credential issuance',
  mdoc_dsc: 'mdoc document signing',
  x509_doc_signer: 'X.509 document signing',
  csca: 'CSCA / IACA root authority',
  jwks_signing: 'JWKS signing',
};

const sameTuple = (left, right) => left && right && ['key_purpose', 'credential_format', 'algorithm']
  .every((field) => left[field] === right[field]);

const organizationSlug = (name, organizationId) => (
  String(name || organizationId || '')
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9_-]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 64)
);

export default function IssuerIdentityWizard() {
  const navigate = useNavigate();
  const { organizationName } = useAuth();
  const { activeOrgId, memberships } = useConsole();
  const { showNotification } = useNotifications();
  const activeOrganization = useMemo(
    () => (memberships || []).find((organization) => organization.id === activeOrgId),
    [activeOrgId, memberships],
  );
  const displayName = activeOrganization?.display_name || activeOrganization?.name || organizationName;
  const [issuerDid, setIssuerDid] = useState('');
  const [selection, setSelection] = useState(null);
  const [snapshot, setSnapshot] = useState(null);
  const [refresh, setRefresh] = useState(0);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState('');
  const epochRef = useRef(0);

  useLayoutEffect(() => {
    epochRef.current += 1;
    setIssuerDid('');
    setSelection(null);
    setError('');
    setSubmitting(false);
    return () => { epochRef.current += 1; };
  }, [activeOrgId]);

  useEffect(() => {
    let current = true;
    setSnapshot(null);
    if (activeOrgId) {
      issuerIdentitiesApi.getIssuerIdentityCapabilities({ organization_id: activeOrgId })
        .then((data) => {
          if (!current) return;
          setSnapshot({ organizationId: activeOrgId, data });
          setSelection((previous) => (previous
            ? data.creation_options.find((option) => sameTuple(option, previous)) || null
            : data.creation_options[0] || null));
          setIssuerDid((previous) => previous || (data.managed_issuer_did_prefix
            ? `${data.managed_issuer_did_prefix}${organizationSlug(displayName, activeOrgId)}` : ''));
        })
        .catch((loadError) => {
          if (current) setSnapshot({ organizationId: activeOrgId, error: loadError });
        });
    }
    return () => { current = false; };
  }, [activeOrgId, displayName, refresh]);

  const capabilities = snapshot?.organizationId === activeOrgId ? snapshot.data : null;
  const options = capabilities?.creation_options || [];
  const selected = options.find((option) => sameTuple(option, selection));
  const keyPurpose = selected?.key_purpose || '';
  const credentialFormat = selected?.credential_format || '';
  const algorithm = selected?.algorithm || '';
  const purposes = [...new Set(options.map((option) => option.key_purpose))];
  const formats = [...new Set(options.filter((option) => option.key_purpose === keyPurpose)
    .map((option) => option.credential_format))];
  const algorithms = options.filter((option) => option.key_purpose === keyPurpose
    && option.credential_format === credentialFormat).map((option) => option.algorithm);

  const changePurpose = (nextPurpose) => {
    setSelection(options.find((option) => option.key_purpose === nextPurpose
      && option.credential_format === credentialFormat && option.algorithm === algorithm)
      || options.find((option) => option.key_purpose === nextPurpose) || null);
  };

  const submit = async (event) => {
    event.preventDefault();
    if (!activeOrgId) {
      setError('Select an organization before creating an issuer identity.');
      return;
    }
    if (!selected || !capabilities?.managed_issuer_did_prefix) {
      setError('Load available issuer capabilities and select a supported identity.');
      return;
    }
    if (!issuerDid.trim().startsWith('did:')) {
      setError('Enter a valid DID. New managed identities currently use a local path-scoped did:web.');
      return;
    }
    setSubmitting(true);
    setError('');
    const epoch = epochRef.current;
    try {
      const current = await issuerIdentitiesApi.getIssuerIdentityCapabilities({ organization_id: activeOrgId });
      if (epoch !== epochRef.current) return;
      if (!current.creation_options.some((option) => sameTuple(option, selected))) {
        setSnapshot({ organizationId: activeOrgId, data: current });
        setSelection(null);
        setError('Issuer capabilities changed. Choose an available identity before submitting.');
        return;
      }
      if (!current.managed_issuer_did_prefix || !issuerDid.trim().startsWith(current.managed_issuer_did_prefix)) {
        setError('Use the deployment DID prefix shown by the issuer service. Refresh capabilities if publication settings changed.');
        return;
      }
      const result = await issuerIdentitiesApi.createIssuerIdentity({
        organization_id: activeOrgId,
        issuer_did: issuerDid.trim(),
        key_purpose: keyPurpose,
        credential_format: credentialFormat,
        algorithm,
      });
      if (epoch !== epochRef.current) return;
      showNotification?.(
        result?.created ? 'Issuer identity created.' : 'Issuer identity already exists.',
        'success',
      );
      navigate('/console/org/deploy/issuer-identity');
    } catch (requestError) {
      if (epoch !== epochRef.current) return;
      setError(
        requestError?.response?.error?.message
        || requestError?.response?.data?.detail
        || requestError?.response?.detail
        || requestError?.message
        || 'Issuer identity creation failed.',
      );
    } finally {
      if (epoch === epochRef.current) setSubmitting(false);
    }
  };

  return (
    <Container maxWidth="md" sx={{ py: 4 }}>
      <Button
        startIcon={<ArrowBackIcon />}
        onClick={() => navigate('/console/org/deploy/issuer-identity')}
        sx={{ mb: 2 }}
      >
        Back to issuer identities
      </Button>
      <Paper component="form" onSubmit={submit} variant="outlined" sx={{ p: { xs: 2, md: 4 } }}>
        <Stack spacing={3}>
          <Box>
            <Typography variant="h4" gutterBottom>Create issuer identity</Typography>
            <Typography color="text.secondary">
              Choose a public DID and a signing option available to your organization.
            </Typography>
          </Box>

          <Alert severity="info">
            Private keys remain in managed custody. You can share the public identity after creation.
          </Alert>

          {!activeOrgId && <Alert severity="warning">Select an organization to continue.</Alert>}
          {error && <Alert severity="error">{error}</Alert>}
          {activeOrgId && !snapshot && <Alert severity="info">Loading available issuer identities...</Alert>}
          {snapshot?.organizationId === activeOrgId && snapshot.error && (
            <Alert severity="error">Issuer capabilities could not be loaded. {snapshot.error.message}</Alert>
          )}
          {capabilities && options.length === 0 && (
            <Alert severity="warning">No compatible issuer creation options are available for this organization. Ask an operator to check issuer configuration and publication settings.</Alert>
          )}
          <Button onClick={() => setRefresh((value) => value + 1)} disabled={!activeOrgId || submitting}>
            Refresh issuer capabilities
          </Button>

          <TextField
            required
            fullWidth
            label="Issuer DID"
            value={capabilities ? issuerDid : ''}
            disabled={!capabilities || submitting}
            onChange={(event) => setIssuerDid(event.target.value)}
            helperText={capabilities?.managed_issuer_did_prefix
              ? `Deployment DID prefix: ${capabilities.managed_issuer_did_prefix}`
              : 'The issuer service supplies the deployment DID prefix.'}
            slotProps={{ htmlInput: { spellCheck: false } }}
          />

          <FormControl fullWidth required>
            <InputLabel id="issuer-purpose-label">Signing purpose</InputLabel>
            <Select
              id="issuer-purpose"
              labelId="issuer-purpose-label"
              label="Signing purpose"
              value={keyPurpose}
              disabled={!capabilities || submitting}
              onChange={(event) => changePurpose(event.target.value)}
            >
              {purposes.map((purpose) => (
                <MenuItem key={purpose} value={purpose}>{PURPOSE_LABELS[purpose] || purpose.replaceAll('_', ' ')}</MenuItem>
              ))}
            </Select>
          </FormControl>

          <FormControl fullWidth required>
            <InputLabel id="issuer-format-label">Credential format</InputLabel>
            <Select
              id="issuer-format"
              labelId="issuer-format-label"
              label="Credential format"
              value={credentialFormat}
              disabled={!selected || submitting}
              onChange={(event) => setSelection(options.find((option) => option.key_purpose === keyPurpose
                && option.credential_format === event.target.value && option.algorithm === algorithm)
                || options.find((option) => option.key_purpose === keyPurpose
                  && option.credential_format === event.target.value) || null)}
            >
              {formats.map((format) => <MenuItem key={format} value={format}>{format}</MenuItem>)}
            </Select>
          </FormControl>

          <FormControl fullWidth required>
            <InputLabel id="issuer-algorithm-label">Algorithm</InputLabel>
            <Select
              id="issuer-algorithm"
              labelId="issuer-algorithm-label"
              label="Algorithm"
              value={algorithm}
              disabled={!selected || submitting}
              onChange={(event) => setSelection(options.find((option) => option.key_purpose === keyPurpose
                && option.credential_format === credentialFormat && option.algorithm === event.target.value) || null)}
            >
              {algorithms.map((value) => <MenuItem key={value} value={value}>{value}</MenuItem>)}
            </Select>
          </FormControl>

          <Stack direction={{ xs: 'column', sm: 'row' }} spacing={2} justifyContent="flex-end">
            <Button onClick={() => navigate('/console/org/deploy/issuer-identity')} disabled={submitting}>
              Cancel
            </Button>
            <Button type="submit" variant="contained" disabled={submitting || !activeOrgId || !selected || !capabilities?.managed_issuer_did_prefix}>
              {submitting ? <CircularProgress size={22} /> : 'Create managed identity'}
            </Button>
          </Stack>
        </Stack>
      </Paper>
    </Container>
  );
}

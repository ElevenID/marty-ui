import { useEffect, useMemo, useState } from 'react';
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

import signingKeysApi from '../../../services/signingKeysApi';
import { useAuth } from '../../../hooks/useAuth';
import { useConsole } from '../../../contexts/ConsoleContext';
import { useNotifications } from '../../../hooks/useNotifications';

const PURPOSES = [
  { value: 'vc_jwt_issuer', label: 'Credential issuance' },
  { value: 'mdoc_dsc', label: 'mdoc document signing' },
  { value: 'x509_doc_signer', label: 'X.509 document signing' },
  { value: 'csca', label: 'CSCA / IACA root authority' },
  { value: 'jwks_signing', label: 'JWKS signing' },
];

const FORMATS_BY_PURPOSE = {
  vc_jwt_issuer: ['SD_JWT_VC', 'VC_JWT', 'JSON_LD'],
  mdoc_dsc: ['MDOC', 'ZK_MDOC'],
  x509_doc_signer: ['MDOC', 'ZK_MDOC', 'ICAO_EMRTD'],
  csca: ['MDOC', 'ZK_MDOC'],
  jwks_signing: ['VC_JWT', 'SD_JWT_VC'],
};

const ALGORITHMS_BY_PURPOSE = {
  vc_jwt_issuer: ['ES256', 'ES384', 'RS256', 'EdDSA'],
  mdoc_dsc: ['ES256', 'ES384', 'EdDSA'],
  x509_doc_signer: ['ES256', 'ES384', 'RS256', 'EdDSA'],
  csca: ['ES256', 'ES384', 'ES512', 'RS256', 'EdDSA'],
  jwks_signing: ['ES256', 'ES384', 'RS256', 'EdDSA'],
};

const organizationSlug = (name, organizationId) => (
  String(name || organizationId || '')
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9_-]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 64)
);

const defaultIssuerDid = (name, organizationId) => {
  const host = typeof window !== 'undefined' ? window.location.host : '';
  const didHost = host.replace(/:/g, '%3A');
  const slug = organizationSlug(name, organizationId);
  return didHost && slug ? `did:web:${didHost}:orgs:${slug}` : '';
};

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
  const [keyPurpose, setKeyPurpose] = useState('vc_jwt_issuer');
  const [credentialFormat, setCredentialFormat] = useState('SD_JWT_VC');
  const [algorithm, setAlgorithm] = useState('ES256');
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState('');

  useEffect(() => {
    setIssuerDid(defaultIssuerDid(displayName, activeOrgId));
  }, [activeOrgId, displayName]);

  const formats = FORMATS_BY_PURPOSE[keyPurpose] || [];
  const algorithms = ALGORITHMS_BY_PURPOSE[keyPurpose] || [];

  const changePurpose = (nextPurpose) => {
    const nextFormats = FORMATS_BY_PURPOSE[nextPurpose] || [];
    const nextAlgorithms = ALGORITHMS_BY_PURPOSE[nextPurpose] || [];
    setKeyPurpose(nextPurpose);
    setCredentialFormat(nextFormats.includes(credentialFormat) ? credentialFormat : nextFormats[0]);
    setAlgorithm(nextAlgorithms.includes(algorithm) ? algorithm : nextAlgorithms[0]);
  };

  const submit = async (event) => {
    event.preventDefault();
    if (!activeOrgId) {
      setError('Select an organization before creating an issuer identity.');
      return;
    }
    if (!issuerDid.trim().startsWith('did:')) {
      setError('Enter a valid DID. New managed identities currently use a local path-scoped did:web.');
      return;
    }
    setSubmitting(true);
    setError('');
    try {
      const result = await signingKeysApi.createIssuerIdentity({
        organization_id: activeOrgId,
        issuer_did: issuerDid.trim(),
        key_purpose: keyPurpose,
        credential_format: credentialFormat,
        algorithm,
      });
      showNotification?.(
        result?.created ? 'Issuer identity created.' : 'Issuer identity already exists.',
        'success',
      );
      navigate('/console/org/deploy/issuer-identity');
    } catch (requestError) {
      setError(
        requestError?.response?.error?.message
        || requestError?.response?.data?.detail
        || requestError?.response?.detail
        || requestError?.message
        || 'Issuer identity creation failed.',
      );
    } finally {
      setSubmitting(false);
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
              Choose the public DID and signing compatibility. Marty resolves and provisions the authorized
              issuer profile and managed custody internally.
            </Typography>
          </Box>

          <Alert severity="info">
            No profile ID, signing service, key reference, KMS provider, or key material crosses this API.
            Private keys remain in managed custody and every signature is made through the resolved issuer profile.
          </Alert>

          {!activeOrgId && <Alert severity="warning">Select an organization to continue.</Alert>}
          {error && <Alert severity="error">{error}</Alert>}

          <TextField
            required
            fullWidth
            label="Issuer DID"
            value={issuerDid}
            onChange={(event) => setIssuerDid(event.target.value)}
            helperText="Use this deployment's path-scoped did:web identifier. External DIDs require resolver-backed proof of control."
            slotProps={{ htmlInput: { spellCheck: false } }}
          />

          <FormControl fullWidth required>
            <InputLabel id="issuer-purpose-label">Signing purpose</InputLabel>
            <Select
              id="issuer-purpose"
              labelId="issuer-purpose-label"
              label="Signing purpose"
              value={keyPurpose}
              onChange={(event) => changePurpose(event.target.value)}
            >
              {PURPOSES.map((purpose) => (
                <MenuItem key={purpose.value} value={purpose.value}>{purpose.label}</MenuItem>
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
              onChange={(event) => setCredentialFormat(event.target.value)}
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
              onChange={(event) => setAlgorithm(event.target.value)}
            >
              {algorithms.map((value) => <MenuItem key={value} value={value}>{value}</MenuItem>)}
            </Select>
          </FormControl>

          <Stack direction={{ xs: 'column', sm: 'row' }} spacing={2} justifyContent="flex-end">
            <Button onClick={() => navigate('/console/org/deploy/issuer-identity')} disabled={submitting}>
              Cancel
            </Button>
            <Button type="submit" variant="contained" disabled={submitting || !activeOrgId}>
              {submitting ? <CircularProgress size={22} /> : 'Create managed identity'}
            </Button>
          </Stack>
        </Stack>
      </Paper>
    </Container>
  );
}

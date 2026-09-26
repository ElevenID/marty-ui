import { useCallback, useEffect, useState } from 'react';
import { useNavigate } from 'react-router';
import {
  Alert,
  Box,
  Button,
  Chip,
  CircularProgress,
  Container,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  IconButton,
  Paper,
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
import AddIcon from '@mui/icons-material/Add';
import ContentCopyIcon from '@mui/icons-material/ContentCopy';
import DeleteOutlineIcon from '@mui/icons-material/DeleteOutlineOutlined';
import RefreshIcon from '@mui/icons-material/Refresh';
import SwapHorizIcon from '@mui/icons-material/SwapHoriz';
import UploadFileOutlinedIcon from '@mui/icons-material/UploadFileOutlined';

import signingKeysApi from '../../../services/signingKeysApi';
import { useConsole } from '../../../contexts/ConsoleContext';
import { useNotifications } from '../../../hooks/useNotifications';

const PUBLIC_CREDENTIAL_FORMATS = [
  'SD_JWT_VC',
  'VC_JWT',
  'JSON_LD',
  'MDOC',
  'ZK_MDOC',
  'ICAO_EMRTD',
];

const identityKey = (identity) => [
  identity.issuer_did,
  identity.key_purpose,
  identity.credential_format,
  identity.algorithm,
].join('|');

export default function DidIdentitiesPage() {
  const navigate = useNavigate();
  const { activeOrgId } = useConsole();
  const { showNotification } = useNotifications();
  const [identities, setIdentities] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [retiring, setRetiring] = useState(null);
  const [rebinding, setRebinding] = useState(null);
  const [certifying, setCertifying] = useState(null);
  const [certificate, setCertificate] = useState({ certificate_id: '', cert_pem: '', cert_chain_pem: '' });
  const [submitting, setSubmitting] = useState(false);

  const load = useCallback(async () => {
    if (!activeOrgId) {
      setIdentities([]);
      setError('Select an organization before loading issuer identities.');
      setLoading(false);
      return;
    }
    setLoading(true);
    setError('');
    try {
      const results = await Promise.all(PUBLIC_CREDENTIAL_FORMATS.map(async (credentialFormat) => {
        const response = await signingKeysApi.listPublicIssuerIdentities({
          organization_id: activeOrgId,
          credential_format: credentialFormat,
        });
        const values = Array.isArray(response?.identities) ? response.identities : [];
        return values.map((identity) => ({ ...identity, credential_format: credentialFormat }));
      }));
      const unique = new Map();
      results.flat().forEach((identity) => unique.set(identityKey(identity), identity));
      setIdentities([...unique.values()].sort((left, right) => identityKey(left).localeCompare(identityKey(right))));
    } catch (requestError) {
      setError(
        requestError?.response?.error?.message
        || requestError?.response?.detail
        || requestError?.message
        || 'Issuer identities could not be loaded.',
      );
    } finally {
      setLoading(false);
    }
  }, [activeOrgId]);

  useEffect(() => {
    load();
  }, [load]);

  const copyDid = async (issuerDid) => {
    try {
      await navigator.clipboard.writeText(issuerDid);
      showNotification?.('Issuer DID copied.', 'success');
    } catch {
      showNotification?.('Issuer DID could not be copied.', 'error');
    }
  };

  const retireIdentity = async () => {
    if (!retiring || !activeOrgId) return;
    setSubmitting(true);
    setError('');
    try {
      await signingKeysApi.deleteIssuerIdentity({
        organization_id: activeOrgId,
        issuer_did: retiring.issuer_did,
        key_purpose: retiring.key_purpose,
        credential_format: retiring.credential_format,
        algorithm: retiring.algorithm,
      });
      showNotification?.('Issuer identity retired.', 'success');
      setRetiring(null);
      await load();
    } catch (requestError) {
      setError(
        requestError?.response?.error?.message
        || requestError?.response?.detail
        || requestError?.message
        || 'Issuer identity could not be retired.',
      );
    } finally {
      setSubmitting(false);
    }
  };

  const rebindIdentity = async () => {
    if (!rebinding || !activeOrgId) return;
    setSubmitting(true);
    setError('');
    try {
      const result = await signingKeysApi.rebindIssuerIdentity({
        organization_id: activeOrgId,
        issuer_did: rebinding.issuer_did,
        key_purpose: rebinding.key_purpose,
        credential_format: rebinding.credential_format,
        algorithm: rebinding.algorithm,
      });
      showNotification?.(
        result?.changed
          ? 'Issuer identity moved to the default signing service.'
          : 'Issuer identity already uses the default signing service.',
        'success',
      );
      setRebinding(null);
      await load();
    } catch (requestError) {
      setError(
        requestError?.response?.error?.message
        || requestError?.response?.detail
        || requestError?.message
        || 'Issuer identity could not be moved to the default signing service.',
      );
    } finally {
      setSubmitting(false);
    }
  };

  const attachCertificate = async () => {
    if (!certifying || !activeOrgId || !certificate.cert_pem.trim()
      || (certifying.key_purpose === 'csca' && !certificate.certificate_id.trim())) return;
    setSubmitting(true);
    setError('');
    try {
      const publicCertificate = {
        organization_id: activeOrgId,
        issuer_did: certifying.issuer_did,
        credential_format: certifying.credential_format,
        algorithm: certifying.algorithm,
        cert_pem: certificate.cert_pem.trim(),
        cert_chain_pem: certificate.cert_chain_pem.trim(),
      };
      if (certifying.key_purpose === 'csca') {
        await signingKeysApi.enrollCscaCertificate({
          ...publicCertificate,
          certificate_id: certificate.certificate_id.trim(),
        });
        showNotification?.('Public CSCA trust anchor enrolled.', 'success');
      } else {
        await signingKeysApi.storeIssuerIdentityCertificate({
          ...publicCertificate,
          key_purpose: certifying.key_purpose,
        });
        showNotification?.('Document signer certificate attached to issuer identity.', 'success');
      }
      setCertifying(null);
      setCertificate({ certificate_id: '', cert_pem: '', cert_chain_pem: '' });
    } catch (requestError) {
      setError(
        requestError?.response?.error?.message
        || requestError?.response?.detail
        || requestError?.message
        || (certifying.key_purpose === 'csca'
          ? 'CSCA trust anchor could not be enrolled.'
          : 'Document signer certificate could not be attached.'),
      );
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <Container maxWidth="xl" sx={{ py: 4 }}>
      <Stack direction={{ xs: 'column', md: 'row' }} justifyContent="space-between" spacing={2} sx={{ mb: 3 }}>
        <Box>
          <Typography variant="h4" gutterBottom>Issuer identities</Typography>
          <Typography color="text.secondary">
            Public DID identities authorized for this organization. Custody profiles, services, and key references remain internal.
          </Typography>
        </Box>
        <Stack direction="row" spacing={1} alignItems="center">
          <Tooltip title="Reload identities">
            <span>
              <IconButton onClick={load} disabled={loading || !activeOrgId} aria-label="Reload identities">
                <RefreshIcon />
              </IconButton>
            </span>
          </Tooltip>
          <Button
            variant="contained"
            startIcon={<AddIcon />}
            disabled={!activeOrgId}
            onClick={() => navigate('/console/org/deploy/issuer-identity/new')}
          >
            Create identity
          </Button>
        </Stack>
      </Stack>

      <Alert severity="info" sx={{ mb: 3 }}>
        Runtime callers select an issuer with organization, DID, purpose, credential format, and algorithm.
        Marty resolves exactly one active issuer profile and signs through managed custody; ambiguity or tenant mismatch fails closed.
      </Alert>
      {error && <Alert severity="error" sx={{ mb: 3 }}>{error}</Alert>}

      <TableContainer component={Paper} variant="outlined">
        <Table>
          <TableHead>
            <TableRow>
              <TableCell>Issuer DID</TableCell>
              <TableCell>Purpose</TableCell>
              <TableCell>Format</TableCell>
              <TableCell>Algorithm</TableCell>
              <TableCell>Status</TableCell>
              <TableCell align="right">Actions</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {loading && (
              <TableRow><TableCell colSpan={6} align="center"><CircularProgress size={28} /></TableCell></TableRow>
            )}
            {!loading && identities.length === 0 && (
              <TableRow>
                <TableCell colSpan={6} align="center">
                  <Typography color="text.secondary" sx={{ py: 4 }}>
                    No active issuer identities are compatible with the supported credential formats.
                  </Typography>
                </TableCell>
              </TableRow>
            )}
            {!loading && identities.map((identity) => (
              <TableRow key={identityKey(identity)} hover>
                <TableCell sx={{ maxWidth: 440 }}>
                  <Stack direction="row" alignItems="center" spacing={1}>
                    <Typography fontFamily="monospace" sx={{ overflowWrap: 'anywhere' }}>{identity.issuer_did}</Typography>
                    <Tooltip title="Copy DID">
                      <IconButton size="small" onClick={() => copyDid(identity.issuer_did)} aria-label="Copy issuer DID">
                        <ContentCopyIcon fontSize="inherit" />
                      </IconButton>
                    </Tooltip>
                  </Stack>
                </TableCell>
                <TableCell>{identity.key_purpose}</TableCell>
                <TableCell>{identity.credential_format}</TableCell>
                <TableCell>{identity.algorithm}</TableCell>
                <TableCell><Chip size="small" color="success" label={identity.status} /></TableCell>
                <TableCell align="right">
                  {identity.credential_format === 'ICAO_EMRTD' && identity.key_purpose === 'x509_doc_signer' && (
                    <Tooltip title="Attach document signer certificate">
                      <IconButton
                        onClick={() => {
                          setCertifying(identity);
                          setCertificate({ certificate_id: '', cert_pem: '', cert_chain_pem: '' });
                        }}
                        aria-label="Attach document signer certificate"
                      >
                        <UploadFileOutlinedIcon />
                      </IconButton>
                    </Tooltip>
                  )}
                  {identity.key_purpose === 'csca' && (
                    <Tooltip title="Enroll public CSCA trust anchor">
                      <IconButton
                        onClick={() => {
                          setCertifying(identity);
                          setCertificate({ certificate_id: '', cert_pem: '', cert_chain_pem: '' });
                        }}
                        aria-label="Enroll public CSCA trust anchor"
                      >
                        <UploadFileOutlinedIcon />
                      </IconButton>
                    </Tooltip>
                  )}
                  <Tooltip title="Move to default signing service">
                    <IconButton onClick={() => setRebinding(identity)} aria-label="Move identity to default signing service">
                      <SwapHorizIcon />
                    </IconButton>
                  </Tooltip>
                  <Tooltip title="Retire identity">
                    <IconButton color="error" onClick={() => setRetiring(identity)} aria-label="Retire identity">
                      <DeleteOutlineIcon />
                    </IconButton>
                  </Tooltip>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </TableContainer>

      <Dialog open={Boolean(certifying)} onClose={() => !submitting && setCertifying(null)} maxWidth="md" fullWidth>
        <DialogTitle>{certifying?.key_purpose === 'csca' ? 'Enroll public CSCA trust anchor' : 'Attach document signer certificate'}</DialogTitle>
        <DialogContent>
          <Stack spacing={2} sx={{ mt: 1 }}>
            <Alert severity="info">
              {certifying?.key_purpose === 'csca'
                ? 'Upload only the public CA certificate and optional chain. Marty verifies its signature and matches its public key to this managed KMS identity; no private key is uploaded.'
                : 'Upload the signed DSC and optional chain for this passport issuer. Marty verifies the certificate public key against the issuer’s managed KMS identity; no private key is uploaded.'}
            </Alert>
            {certifying && (
              <Typography fontFamily="monospace" sx={{ overflowWrap: 'anywhere' }}>{certifying.issuer_did}</Typography>
            )}
            {certifying?.key_purpose === 'csca' && (
              <TextField
                label="CSCA certificate ID"
                required
                fullWidth
                value={certificate.certificate_id}
                onChange={(event) => setCertificate((current) => ({ ...current, certificate_id: event.target.value }))}
              />
            )}
            <TextField
              label={certifying?.key_purpose === 'csca' ? 'CSCA certificate PEM' : 'Document signer certificate PEM'}
              multiline
              minRows={6}
              fullWidth
              required
              value={certificate.cert_pem}
              onChange={(event) => setCertificate((current) => ({ ...current, cert_pem: event.target.value }))}
            />
            <TextField
              label="Certificate chain PEM (optional)"
              multiline
              minRows={3}
              fullWidth
              value={certificate.cert_chain_pem}
              onChange={(event) => setCertificate((current) => ({ ...current, cert_chain_pem: event.target.value }))}
            />
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setCertifying(null)} disabled={submitting}>Cancel</Button>
          <Button variant="contained" onClick={attachCertificate} disabled={submitting || !certificate.cert_pem.trim() || (certifying?.key_purpose === 'csca' && !certificate.certificate_id.trim())}>
            {submitting ? <CircularProgress size={20} /> : (certifying?.key_purpose === 'csca' ? 'Enroll trust anchor' : 'Attach certificate')}
          </Button>
        </DialogActions>
      </Dialog>

      <Dialog open={Boolean(retiring)} onClose={() => !submitting && setRetiring(null)} maxWidth="sm" fullWidth>
        <DialogTitle>Retire issuer identity?</DialogTitle>
        <DialogContent>
          <Typography>
            New signing operations for this DID, purpose, format, and algorithm will stop immediately. Existing credentials remain verifiable.
          </Typography>
          {retiring && (
            <Typography fontFamily="monospace" sx={{ mt: 2, overflowWrap: 'anywhere' }}>{retiring.issuer_did}</Typography>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setRetiring(null)} disabled={submitting}>Cancel</Button>
          <Button color="error" variant="contained" onClick={retireIdentity} disabled={submitting}>
            {submitting ? <CircularProgress size={20} /> : 'Retire identity'}
          </Button>
        </DialogActions>
      </Dialog>

      <Dialog open={Boolean(rebinding)} onClose={() => !submitting && setRebinding(null)} maxWidth="sm" fullWidth>
        <DialogTitle>Move issuer identity to the default signer?</DialogTitle>
        <DialogContent>
          <Typography>
            Marty will validate the compatible default signing service and publish its public key to this DID before changing active custody. Existing verification methods remain published so credentials already issued by this DID stay verifiable.
          </Typography>
          {rebinding && (
            <Typography fontFamily="monospace" sx={{ mt: 2, overflowWrap: 'anywhere' }}>{rebinding.issuer_did}</Typography>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setRebinding(null)} disabled={submitting}>Cancel</Button>
          <Button variant="contained" onClick={rebindIdentity} disabled={submitting}>
            {submitting ? <CircularProgress size={20} /> : 'Move identity'}
          </Button>
        </DialogActions>
      </Dialog>
    </Container>
  );
}

import { useCallback, useEffect, useLayoutEffect, useRef, useState } from 'react';
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
import { createIdempotencyKey } from '../../../services/idempotency';
import { useConsole } from '../../../contexts/ConsoleContext';
import { useNotifications } from '../../../hooks/useNotifications';
import { usePermissions } from '../../../hooks/usePermissions';

const PUBLIC_CREDENTIAL_FORMATS = [
  'SD_JWT_VC',
  'VC_JWT',
  'JSON_LD',
  'MDOC',
  'ZK_MDOC',
  'ICAO_EMRTD',
];
const CSR_ALGORITHMS = new Set(['ES256', 'ES384', 'ES512']);
const dscPendingKey = (organizationId, issuerDid) =>
  `passport-dsc-pending:${encodeURIComponent(organizationId)}:${encodeURIComponent(issuerDid)}`;

const pendingDscRequest = (organizationId, issuerDid) => {
  try {
    const saved = JSON.parse(window.sessionStorage.getItem(dscPendingKey(organizationId, issuerDid)) || 'null');
    const request = saved?.request;
    if (saved?.organization_id !== organizationId || request?.dsc_issuer_did !== issuerDid
      || !request?.idempotency_key || !request?.csca_issuer_did || !request?.csca_certificate_id) return null;
    return request;
  } catch {
    return null;
  }
};

const freshIssueForm = (identity) => ({
  certificate_id: '', csca_issuer_did: '', csca_certificate_id: '',
  country: '', organization: '', common_name: '',
  validity_days: identity.key_purpose === 'csca' ? '365' : '30',
  idempotency_key: createIdempotencyKey('passport-dsc').replace(/:/g, '-'),
});

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
  const { can, isLoading: permissionsLoading } = usePermissions();
  const canIssueCsca = !permissionsLoading && can('passport-certificate', 'issue-csca');
  const canIssueDsc = !permissionsLoading && can('passport-certificate', 'issue');
  const [identities, setIdentities] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [retiring, setRetiring] = useState(null);
  const [rebinding, setRebinding] = useState(null);
  const [certifying, setCertifying] = useState(null);
  const [certificate, setCertificate] = useState({ certificate_id: '', cert_pem: '', cert_chain_pem: '' });
  const [csrSubject, setCsrSubject] = useState({ country: '', organization: '', common_name: '' });
  const [csrPem, setCsrPem] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [issueSubmitting, setIssueSubmitting] = useState(false);
  const [issuing, setIssuing] = useState(null);
  const [issueForm, setIssueForm] = useState({
    certificate_id: '', csca_issuer_did: '', csca_certificate_id: '',
    country: '', organization: '', common_name: '', validity_days: '', idempotency_key: '',
  });
  const [issuedCertificate, setIssuedCertificate] = useState(null);
  const [issueError, setIssueError] = useState('');
  const [issuePendingRetry, setIssuePendingRetry] = useState(false);
  const issueEpochRef = useRef(0);
  const loadRequestRef = useRef(0);
  useLayoutEffect(() => {
    issueEpochRef.current += 1;
    setIssuing(null);
    setIssuedCertificate(null);
    setIssueError('');
    setIssueSubmitting(false);
    setIssuePendingRetry(false);
  }, [activeOrgId]);
  const csrSupported = certifying && CSR_ALGORITHMS.has(certifying.algorithm);
  const issueValidityDays = Number(issueForm.validity_days);
  const issueFormValid = Boolean(issuing)
    && Number.isInteger(issueValidityDays) && issueValidityDays >= 1
    && issueValidityDays <= (issuing?.key_purpose === 'csca' ? 3650 : 90)
    && /^[A-Za-z]{2}$/.test(issueForm.country.trim())
    && Boolean(issueForm.organization.trim() && issueForm.common_name.trim())
    && (issuing?.key_purpose === 'csca'
      ? Boolean(issueForm.certificate_id.trim())
      : Boolean(issueForm.csca_issuer_did.trim() && issueForm.csca_certificate_id.trim())
        && /^[A-Za-z0-9._-]{1,128}$/.test(issueForm.idempotency_key));

  const openIssuance = (identity) => {
    if (!activeOrgId || identity.organization_id !== activeOrgId) return;
    if (identity.credential_format !== 'ICAO_EMRTD' || identity.algorithm !== 'ES256'
      || identity.status !== 'active' || !['csca', 'x509_doc_signer'].includes(identity.key_purpose)) return;
    issueEpochRef.current += 1;
    setIssuing(identity);
    setIssuedCertificate(null);
    setIssueError('');
    const pending = identity.key_purpose === 'x509_doc_signer'
      ? pendingDscRequest(activeOrgId, identity.issuer_did) : null;
    setIssuePendingRetry(Boolean(pending));
    setIssueForm(pending ? {
      ...freshIssueForm(identity),
      csca_issuer_did: pending.csca_issuer_did,
      csca_certificate_id: pending.csca_certificate_id,
      country: pending.country,
      organization: pending.organization,
      common_name: pending.common_name,
      validity_days: String(pending.validity_days),
      idempotency_key: pending.idempotency_key,
    } : freshIssueForm(identity));
  };

  const discardPendingDsc = () => {
    if (!issuing || !activeOrgId || !issuePendingRetry) return;
    if (!window.confirm('The previous DSC request may have succeeded. Check certificate records before starting a different request. Continue?')) return;
    try {
      window.sessionStorage.removeItem(dscPendingKey(activeOrgId, issuing.issuer_did));
    } catch {
      setIssueError('The pending DSC request could not be cleared. Retry it with the saved reference.');
      return;
    }
    setIssuePendingRetry(false);
    setIssueError('');
    setIssueForm(freshIssueForm(issuing));
  };

  const issueCertificate = async () => {
    if (!issuing || !activeOrgId || issuing.organization_id !== activeOrgId) return;
    const issueEpoch = issueEpochRef.current;
    const csca = issuing.key_purpose === 'csca';
    if (!(csca ? canIssueCsca : canIssueDsc)) return;
    if (!issueFormValid) return;
    setIssueSubmitting(true);
    setIssueError('');
    try {
      const subject = {
        organization_id: activeOrgId,
        country: issueForm.country.trim().toUpperCase(),
        organization: issueForm.organization.trim(),
        common_name: issueForm.common_name.trim(),
        validity_days: issueValidityDays,
      };
      const dscRequest = csca ? null : {
          ...subject, dsc_issuer_did: issuing.issuer_did,
          csca_issuer_did: issueForm.csca_issuer_did.trim(),
          csca_certificate_id: issueForm.csca_certificate_id.trim(),
          idempotency_key: issueForm.idempotency_key,
        };
      if (dscRequest) {
        window.sessionStorage.setItem(dscPendingKey(activeOrgId, issuing.issuer_did), JSON.stringify({
          organization_id: activeOrgId, request: dscRequest,
        }));
        setIssuePendingRetry(true);
      }
      const result = csca
        ? await signingKeysApi.issueCscaSelfSignedCertificate({
          ...subject, issuer_did: issuing.issuer_did, certificate_id: issueForm.certificate_id.trim(),
        })
        : await signingKeysApi.issueDscCertificate(dscRequest);
      if (issueEpoch === issueEpochRef.current) {
        if (dscRequest) {
          try {
            window.sessionStorage.removeItem(dscPendingKey(activeOrgId, issuing.issuer_did));
          } catch {
            // A successful idempotent retry remains safe if session storage cannot be cleared.
          }
          setIssuePendingRetry(false);
        }
        setIssuedCertificate(result);
        showNotification?.(csca ? 'CSCA certificate issued.' : 'Document signer certificate issued.', 'success');
      }
    } catch {
      if (issueEpoch === issueEpochRef.current) {
        setIssueError('Passport certificate could not be issued. Check the selected profiles and certificate details, then retry.');
      }
    } finally {
      if (issueEpoch === issueEpochRef.current) setIssueSubmitting(false);
    }
  };

  const load = useCallback(async () => {
    const requestId = ++loadRequestRef.current;
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
        return values.map((identity) => ({ ...identity, credential_format: credentialFormat, organization_id: activeOrgId }));
      }));
      if (requestId !== loadRequestRef.current) return;
      const unique = new Map();
      results.flat().forEach((identity) => unique.set(identityKey(identity), identity));
      setIdentities([...unique.values()].sort((left, right) => identityKey(left).localeCompare(identityKey(right))));
    } catch (requestError) {
      if (requestId !== loadRequestRef.current) return;
      setError(
        requestError?.response?.error?.message
        || requestError?.response?.detail
        || requestError?.message
        || 'Issuer identities could not be loaded.',
      );
    } finally {
      if (requestId === loadRequestRef.current) setLoading(false);
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

  const generateCsr = async () => {
    if (!csrSupported || !activeOrgId || !csrSubject.country.trim()
      || !csrSubject.organization.trim() || !csrSubject.common_name.trim()) return;
    setSubmitting(true);
    setError('');
    try {
      const result = await signingKeysApi.generateIssuerIdentityCsr({
        organization_id: activeOrgId,
        issuer_did: certifying.issuer_did,
        key_purpose: certifying.key_purpose,
        credential_format: certifying.credential_format,
        algorithm: certifying.algorithm,
        country: csrSubject.country.trim(),
        organization: csrSubject.organization.trim(),
        common_name: csrSubject.common_name.trim(),
      });
      setCsrPem(result?.csr_pem || '');
      showNotification?.('KMS-backed certificate request generated.', 'success');
    } catch (requestError) {
      setError(
        requestError?.response?.error?.message
        || requestError?.response?.detail
        || requestError?.message
        || 'Certificate request could not be generated.',
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
                  {identity.organization_id === activeOrgId && identity.credential_format === 'ICAO_EMRTD' && identity.key_purpose === 'csca' && identity.algorithm === 'ES256' && identity.status === 'active' && canIssueCsca && (
                    <Button size="small" onClick={() => openIssuance(identity)}>Issue CSCA</Button>
                  )}
                  {identity.organization_id === activeOrgId && identity.credential_format === 'ICAO_EMRTD' && identity.key_purpose === 'x509_doc_signer' && identity.algorithm === 'ES256' && identity.status === 'active' && canIssueDsc && (
                    <Button size="small" onClick={() => openIssuance(identity)}>Issue DSC</Button>
                  )}
                  {identity.credential_format === 'ICAO_EMRTD' && identity.key_purpose === 'x509_doc_signer' && (
                    <Tooltip title="Attach document signer certificate">
                      <IconButton
                        onClick={() => {
                          setCertifying(identity);
                          setCertificate({ certificate_id: '', cert_pem: '', cert_chain_pem: '' });
                          setCsrSubject({ country: '', organization: '', common_name: '' });
                          setCsrPem('');
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
                          setCsrSubject({ country: '', organization: '', common_name: '' });
                          setCsrPem('');
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

      <Dialog open={Boolean(issuing) && issuing?.organization_id === activeOrgId} onClose={() => !issueSubmitting && setIssuing(null)} maxWidth="md" fullWidth>
        <DialogTitle>{issuing?.key_purpose === 'csca' ? 'Issue beta CSCA certificate' : 'Issue beta document signer certificate'}</DialogTitle>
        <DialogContent>
          <Stack spacing={2} sx={{ mt: 1 }}>
            {issueError && <Alert severity="error">{issueError}</Alert>}
            {issuePendingRetry && <Alert severity="warning">A DSC request is pending or its response was lost. Retry with the saved reference and unchanged details, or check certificate records before starting a different request.</Alert>}
            <Alert severity="info">
              The selected issuer profile holds the signing key in managed custody. This ceremony returns public certificate material only.
            </Alert>
            <Typography fontFamily="monospace" sx={{ overflowWrap: 'anywhere' }}>{issuing?.issuer_did}</Typography>
            {issuing?.key_purpose === 'csca' ? (
              <TextField label="CSCA certificate ID" required value={issueForm.certificate_id}
                onChange={(event) => setIssueForm((current) => ({ ...current, certificate_id: event.target.value }))} />
            ) : (
              <>
                <TextField label="CSCA issuer DID" required value={issueForm.csca_issuer_did}
                  disabled={issuePendingRetry}
                  onChange={(event) => setIssueForm((current) => ({ ...current, csca_issuer_did: event.target.value }))} />
                <TextField label="CSCA certificate ID" required value={issueForm.csca_certificate_id}
                  disabled={issuePendingRetry}
                  onChange={(event) => setIssueForm((current) => ({ ...current, csca_certificate_id: event.target.value }))} />
                <TextField label="DSC request reference" required value={issueForm.idempotency_key}
                  disabled={issuePendingRetry}
                  helperText="Save this reference before submitting. Use the same reference and details to retry after a lost response."
                  onChange={(event) => setIssueForm((current) => ({ ...current, idempotency_key: event.target.value }))}
                  slotProps={{ htmlInput: { maxLength: 128 } }} />
              </>
            )}
            <Stack direction={{ xs: 'column', sm: 'row' }} spacing={1}>
              <TextField label="Country code (C)" required value={issueForm.country}
                disabled={issuePendingRetry}
                onChange={(event) => setIssueForm((current) => ({ ...current, country: event.target.value }))}
                slotProps={{ htmlInput: { maxLength: 2 } }} />
              <TextField label="Organization (O)" required fullWidth value={issueForm.organization}
                disabled={issuePendingRetry}
                onChange={(event) => setIssueForm((current) => ({ ...current, organization: event.target.value }))} />
              <TextField label="Common name (CN)" required fullWidth value={issueForm.common_name}
                disabled={issuePendingRetry}
                onChange={(event) => setIssueForm((current) => ({ ...current, common_name: event.target.value }))} />
            </Stack>
            <TextField label="Validity (days)" type="number" required value={issueForm.validity_days}
              disabled={issuePendingRetry}
              onChange={(event) => setIssueForm((current) => ({ ...current, validity_days: event.target.value }))}
              slotProps={{ htmlInput: { min: 1, max: issuing?.key_purpose === 'csca' ? 3650 : 90, step: 1 } }} />
            {issuedCertificate && (
              <>
                <Alert severity="success">Certificate issued. Save this public result for enrollment records.</Alert>
                <Typography>Serial: {issuedCertificate.serial}</Typography>
                <Typography>Valid: {issuedCertificate.not_before} to {issuedCertificate.not_after}</Typography>
                <TextField label="Issued certificate PEM" multiline minRows={6} fullWidth
                  value={issuedCertificate.certificate_pem || ''} slotProps={{ input: { readOnly: true, sx: { fontFamily: 'monospace' } } }} />
                <TextField label="Issued certificate chain PEM" multiline minRows={3} fullWidth
                  value={issuedCertificate.chain_pem || ''} slotProps={{ input: { readOnly: true, sx: { fontFamily: 'monospace' } } }} />
              </>
            )}
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setIssuing(null)} disabled={issueSubmitting}>Close</Button>
          {issuePendingRetry && !issuedCertificate && <Button onClick={discardPendingDsc} disabled={issueSubmitting}>Start a different DSC request</Button>}
          {!issuedCertificate && <Button variant="contained" onClick={issueCertificate} disabled={issueSubmitting || !issueFormValid}>
            {issueSubmitting ? <CircularProgress size={20} /> : (issuing?.key_purpose === 'csca' ? 'Issue CSCA certificate' : 'Issue DSC certificate')}
          </Button>}
        </DialogActions>
      </Dialog>

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
            <Typography variant="subtitle2">Generate a KMS-backed certificate request</Typography>
            {certifying && !csrSupported && (
              <Alert severity="info">
                KMS-backed certificate requests support ES256, ES384, and ES512 identities. You can still attach a signed public certificate for this identity.
              </Alert>
            )}
            <Stack direction={{ xs: 'column', sm: 'row' }} spacing={1}>
              <TextField
                label="Country code (C)"
                value={csrSubject.country}
                onChange={(event) => setCsrSubject((current) => ({ ...current, country: event.target.value }))}
                slotProps={{ htmlInput: { maxLength: 2 } }}
              />
              <TextField
                label="Organization (O)"
                value={csrSubject.organization}
                onChange={(event) => setCsrSubject((current) => ({ ...current, organization: event.target.value }))}
                fullWidth
              />
              <TextField
                label="Common name (CN)"
                value={csrSubject.common_name}
                onChange={(event) => setCsrSubject((current) => ({ ...current, common_name: event.target.value }))}
                fullWidth
              />
            </Stack>
            <Button variant="outlined" onClick={generateCsr} disabled={!csrSupported || submitting || !csrSubject.country.trim() || !csrSubject.organization.trim() || !csrSubject.common_name.trim()}>
              Generate KMS-backed CSR
            </Button>
            {csrPem && (
              <TextField
                label="Certificate Signing Request (PEM)"
                value={csrPem}
                multiline
                minRows={5}
                fullWidth
                slotProps={{ input: { readOnly: true, sx: { fontFamily: 'monospace' } } }}
              />
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

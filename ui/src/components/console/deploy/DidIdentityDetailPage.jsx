import { useEffect, useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router';
import { Alert, Box, Button, CircularProgress, Container, Link, Paper, Stack, Table, TableBody, TableCell, TableHead, TableRow, Typography } from '@mui/material';
import issuerIdentitiesApi from '../../../services/issuerIdentitiesApi';
import { useConsole } from '../../../contexts/ConsoleContext';
import { usePermissions } from '../../../hooks/usePermissions';
import { useNotifications } from '../../../hooks/useNotifications';

const signerLabels = { matched: 'Registry key matches the current managed signer', mismatch: 'Registry key differs from the managed signer', unavailable: 'Managed signer check unavailable' };
const publicLabels = { matched: 'Public DID key matches the managed signer', stale: 'Public DID key is stale or different',
  unverified: 'Public DID resolved; signer comparison unavailable', unavailable: 'Public DID could not be resolved',
  invalid: 'Public DID returned invalid material', unsupported: 'Public resolution is not supported for this identity authority' };
const recorded = (value) => value || 'Not recorded';

function Methods({ methods, label }) {
  return <Box>
    <Typography variant="h6">{label}</Typography>
    <Table size="small" aria-label={label}>
      <TableHead><TableRow><TableCell>Verification method</TableCell><TableCell>Type</TableCell><TableCell>Controller</TableCell><TableCell>Authorized for assertions</TableCell></TableRow></TableHead>
      <TableBody>{methods.map((method) => <TableRow key={method.id}>
        <TableCell sx={{ overflowWrap: 'anywhere' }}>{method.id}</TableCell><TableCell>{method.type}</TableCell>
        <TableCell sx={{ overflowWrap: 'anywhere' }}>{method.controller}</TableCell><TableCell>{method.assertion_authorized ? 'Yes' : 'No'}</TableCell>
      </TableRow>)}</TableBody>
    </Table>
    {methods.length === 0 && <Typography color="text.secondary">No verification methods available.</Typography>}
  </Box>;
}

function PublicDocument({ title, document, onCopy }) {
  if (!document) return null;
  return <Paper variant="outlined" sx={{ p: 2 }}>
    <Stack direction="row" justifyContent="space-between"><Typography variant="h6">{title}</Typography>
      <Button onClick={() => onCopy(JSON.stringify(document, null, 2), title)}>Copy {title.toLowerCase()}</Button></Stack>
    <Box component="pre" tabIndex={0} aria-label={title} sx={{ overflow: 'auto', maxHeight: 400, whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}>{JSON.stringify(document, null, 2)}</Box>
  </Paper>;
}

export default function DidIdentityDetailPage() {
  const navigate = useNavigate();
  const [search] = useSearchParams();
  const { activeOrgId } = useConsole();
  const { can, isLoading: permissionsLoading } = usePermissions();
  const { showNotification } = useNotifications();
  const [snapshot, setSnapshot] = useState(null);
  const [refresh, setRefresh] = useState(0);
  const query = Object.fromEntries(['organization_id', 'issuer_did', 'key_purpose', 'credential_format', 'algorithm'].map((field) => [field, search.get(field)]));
  const requestKey = JSON.stringify(query);
  const scoped = Boolean(activeOrgId && query.organization_id === activeOrgId);
  const permitted = !permissionsLoading && can('signing-key', 'view');
  const complete = Object.values(query).every(Boolean);
  useEffect(() => {
    let current = true;
    setSnapshot(null);
    if (scoped && permitted && complete) {
      issuerIdentitiesApi.inspectIssuerIdentity(JSON.parse(requestKey)).then((data) => {
        if (current) setSnapshot({ key: requestKey, data });
      }).catch(() => { if (current) setSnapshot({ key: requestKey, error: true }); });
    }
    return () => { current = false; };
  }, [requestKey, scoped, permitted, complete, refresh]);
  const data = scoped && permitted && snapshot?.key === requestKey ? snapshot.data : null;
  const copyPublic = async (value, label) => {
    try { await navigator.clipboard.writeText(value); showNotification?.(`${label} copied.`, 'success'); }
    catch { showNotification?.(`${label} could not be copied.`, 'error'); }
  };
  const pem = data?.certificate.x5c.map((certificate) => `-----BEGIN CERTIFICATE-----\n${certificate}\n-----END CERTIFICATE-----`).join('\n');
  return <Container maxWidth="lg" sx={{ py: 3 }}>
    <Stack spacing={3}>
      <Stack direction={{ xs: 'column', sm: 'row' }} justifyContent="space-between" spacing={2}>
        <Box><Typography variant="h4">DID identity</Typography><Typography color="text.secondary">Public documents and current signer observations.</Typography></Box>
        <Button onClick={() => navigate('/console/org/deploy/issuer-identity')}>Back to identities</Button>
      </Stack>
      {!complete && <Alert severity="warning">Open an identity from the organization inventory to inspect its complete public identity.</Alert>}
      {complete && !scoped && <Alert severity="warning">This identity belongs to a different organization selection. Open an identity from the active organization.</Alert>}
      {scoped && !permissionsLoading && !permitted && <Alert severity="error">You do not have permission to view signing identities in this organization.</Alert>}
      {permissionsLoading && <CircularProgress aria-label="Checking identity permissions" />}
      {scoped && permitted && complete && !snapshot && <CircularProgress aria-label="Inspecting DID identity" />}
      {scoped && permitted && snapshot?.error && <Alert severity="error">Identity inspection is unavailable. Check organization access and identity state, then retry.</Alert>}
      <Button variant="outlined" disabled={!scoped || !permitted || !complete} onClick={() => setRefresh((value) => value + 1)}>Refresh inspection</Button>
      {data && <>
        <Paper variant="outlined" sx={{ p: 2 }}><Stack spacing={1}>
          <Typography variant="h6" sx={{ overflowWrap: 'anywhere' }}>{data.identity.issuer_did}</Typography>
          <Button sx={{ alignSelf: 'start' }} onClick={() => copyPublic(data.identity.issuer_did, 'Issuer DID')}>Copy DID</Button>
          <Typography>{data.identity.key_purpose} · {data.identity.credential_format} · {data.identity.algorithm} · {data.identity.status}</Typography>
          <Typography>Created: {recorded(data.identity_created_at)}</Typography><Typography>Identity updated: {recorded(data.identity_updated_at)}</Typography>
          <Typography>Inspection completed: {data.inspected_at}</Typography>
          {data.canonical_document_url ? <Link href={data.canonical_document_url} target="_blank" rel="noopener noreferrer">View canonical public DID document</Link>
            : <Typography>No canonical publication URL is available for this identity authority.</Typography>}
        </Stack></Paper>
        <Alert severity={data.assertion_ready ? 'success' : 'warning'}>
          {data.assertion_ready ? 'Stored and public assertion keys match the current managed signer.' : 'DID assertion readiness is incomplete.'}
          {' '}These observations do not qualify credential issuance or certificate trust.
        </Alert>
        <Paper variant="outlined" sx={{ p: 2 }}><Stack spacing={1}>
          <Typography>{data.registry.status === 'available' ? 'Stored DID document available' : 'Not published in the organization registry'}</Typography>
          {data.registry.source === 'legacy_projection' && <Typography>This document is projected from the legacy organization publication.</Typography>}
          <Typography>Document updated: {recorded(data.registry.updated_at)}</Typography>
          <Typography>{signerLabels[data.managed_signer.status]}</Typography><Typography>Signer checked: {recorded(data.managed_signer.checked_at)}</Typography>
          <Typography>{publicLabels[data.public_resolution.status]}</Typography><Typography>Public resolution checked: {recorded(data.public_resolution.checked_at)}</Typography>
          <Typography>Public document retrieved: {recorded(data.public_resolution.retrieved_at)}</Typography>
          {data.public_resolution.content_sha256 && <Typography sx={{ overflowWrap: 'anywhere' }}>Resolved source SHA-256: {data.public_resolution.content_sha256}</Typography>}
          {!data.assertion_ready && <Typography>Republish the current public verification method and check that the canonical URL is reachable. Refresh inspection after correcting the document or signer connection.</Typography>}
        </Stack></Paper>
        <Methods label="Stored verification methods" methods={data.registry.verification_methods} />
        {data.public_resolution.document && <Methods label="Public verification methods" methods={data.public_resolution.verification_methods} />}
        <PublicDocument title="Stored DID document" document={data.registry.document} onCopy={copyPublic} />
        <PublicDocument title="Public DID document" document={data.public_resolution.document} onCopy={copyPublic} />
        <Paper variant="outlined" sx={{ p: 2 }}><Stack spacing={1}>
          <Typography variant="h6">Certificate</Typography><Typography>Certificate expiry state: {data.certificate.status.replaceAll('_', ' ')}</Typography>
          <Typography>Expires: {recorded(data.certificate.expires_at)}</Typography>
          <Typography>Certificate public key matches signer: {data.certificate.public_key_matches == null ? 'Not checked' : data.certificate.public_key_matches ? 'Yes' : 'No'}</Typography>
          {pem && <><Button sx={{ alignSelf: 'start' }} onClick={() => copyPublic(pem, 'Public certificate chain')}>Copy public certificate chain</Button>
            <Box component="pre" aria-label="Public certificate chain" sx={{ overflow: 'auto', maxHeight: 300 }}>{pem}</Box></>}
        </Stack></Paper>
      </>}
    </Stack>
  </Container>;
}

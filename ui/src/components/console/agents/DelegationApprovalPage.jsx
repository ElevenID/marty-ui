import { useEffect, useMemo, useRef, useState } from 'react';
import { useParams, useSearchParams } from 'react-router';
import { Alert, Box, Button, Checkbox, CircularProgress, FormControlLabel, Paper, Stack, Typography } from '@mui/material';
import { useAuth } from '../../../hooks/useAuth';
import { useConsole } from '../../../contexts/ConsoleContext';
import { usePermissions } from '../../../hooks/usePermissions';
import { isAgentTrustFeatureEnabled } from '../../../application/agentTrustFeatures';
import { AgentTrustError, agentTrustErrorMessage, confirmDelegation, isAgentTrustId, reviewDelegation, validGrantReference, withdrawDelegation } from '../../../services/agentTrustApi';

function readRecovery(key, grant) {
  const raw = window.sessionStorage.getItem(key);
  if (raw === null) return null;
  if (raw.length > 2048) throw new Error('Invalid recovery record');
  const value = JSON.parse(raw);
  if (!isAgentTrustId(value.review_id) || !isAgentTrustId(value.confirmation_id)
    || value.grant?.id !== grant.id || value.grant?.revision !== grant.revision
    || value.grant?.terms_digest !== grant.terms_digest) throw new Error('Invalid recovery record');
  return value;
}

function Approval({ organizationId, actorId, grant, canApprove, canView }) {
  const recoveryKey = `elevenid.delegation-approval.v1:${organizationId}:${actorId}:${grant.id}:${grant.revision}:${grant.terms_digest}`;
  const [review, setReview] = useState(null);
  const [confirmed, setConfirmed] = useState(null);
  const [withdrawn, setWithdrawn] = useState(null);
  const [journal, setJournal] = useState(null);
  const [storageError, setStorageError] = useState(false);
  const [checked, setChecked] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);
  const [now, setNow] = useState(Date.now());
  const pending = useRef(false);
  const mounted = useRef(false);
  useEffect(() => {
    mounted.current = true;
    try { setJournal(readRecovery(recoveryKey, grant)); }
    catch { setStorageError(true); }
    const timer = setInterval(() => setNow(Date.now()), 1000);
    return () => { mounted.current = false; clearInterval(timer); };
  }, [recoveryKey, grant]);

  async function run(operation) {
    if (pending.current || !mounted.current) return;
    pending.current = true; setBusy(true); setError(null);
    try { await operation(); }
    catch (failure) { if (mounted.current) setError(failure); }
    finally { if (mounted.current) { pending.current = false; setBusy(false); } }
  }
  const expired = review && Date.parse(review.expires_at) <= now;
  const reviewTerms = () => run(async () => {
    if (!canApprove || journal || storageError) return;
    setReview(null); setChecked(false);
    const result = await reviewDelegation(organizationId, grant);
    if (result.terms.grantor.id !== `urn:marty:user:${actorId}`) throw new AgentTrustError('invalid_response');
    if (mounted.current) { setReview(result); setChecked(false); }
  });
  const submitConfirmation = recovery => run(async () => {
    if (!canView || storageError) return;
    let intent = journal;
    if (!recovery) {
      if (!canApprove || !review || !checked || expired || intent) return;
      intent = { review_id: review.review_id, grant: review.grant, confirmation_id: crypto.randomUUID() };
      // Persist the exact explicit intent before dispatch. A lost reply, reload
      // or later revocation cannot cause a replacement confirmation identity.
      try { window.sessionStorage.setItem(recoveryKey, JSON.stringify(intent)); }
      catch { setStorageError(true); return; }
      setJournal(intent);
    }
    if (!intent) return;
    const result = await confirmDelegation(organizationId, intent, intent.confirmation_id);
    if (mounted.current) setConfirmed(result);
  });
  const withdraw = () => run(async () => {
    const confirmationId = confirmed?.confirmation_id || journal?.confirmation_id;
    if (!canView || !confirmationId || storageError || withdrawn) return;
    // Withdrawal can use the original intent after a new login even when the
    // producer correctly refuses old-session confirmation recovery. It never
    // creates a confirmation, changes its ID, or renews representation authority.
    const result = await withdrawDelegation(organizationId, grant.id, confirmationId);
    if (mounted.current) setWithdrawn(result);
  });

  return <Stack spacing={2}>
    <Typography variant="h4" component="h1">Review delegated authority</Typography>
    <Typography>Confirm only after reviewing the agent, organization, exact operation and validity below. The grant requires a separate activation and current authority check before use.</Typography>
    <Typography variant="body2">Grant: {grant.id} · Revision: {grant.revision}</Typography>
    {busy && <CircularProgress size={24} aria-label="Checking approval" />}
    {error && <Alert severity="error">{agentTrustErrorMessage(error)}</Alert>}
    {storageError && <Alert severity="error">The original confirmation record cannot be preserved or read in this browser. Approval is unavailable. Inspect the grant before starting another approval.</Alert>}
    {journal && !confirmed && !withdrawn && <Alert severity="info">A confirmation was already requested for these exact terms. Check that original request to recover its result.</Alert>}
    {!journal && !storageError && canApprove && <Button variant="outlined" disabled={busy} onClick={reviewTerms}>Load exact terms</Button>}
    {review && <Paper variant="outlined" sx={{ p: 2, overflowWrap: 'anywhere' }}>
      <Stack spacing={1.5}>
        <Typography variant="h6" component="h2">Authority being approved</Typography>
        <Typography>Approver: {review.terms.grantor?.id}</Typography>
        <Typography>Represented organization: {review.terms.subject?.id}</Typography>
        <Typography>Agent: {review.terms.delegate?.type} — {review.terms.delegate?.id}</Typography>
        <Typography>Issuer: {review.issuer?.id}</Typography>
        <Typography>Bound key: {review.terms.binding?.key_thumbprint}</Typography>
        <Typography>Actions: {review.terms.actions.join(', ')}</Typography>
        <Typography>Audiences: {review.terms.audiences.join(', ')}</Typography>
        <Typography>Resources: {review.terms.resources.join(', ')}</Typography>
        <Typography>Grant validity: {review.terms.valid_from} to {review.terms.valid_until}</Typography>
        <Typography>Approval lasts at most {review.confirmation_max_age_seconds} seconds from confirmation, and ends sooner if the grant expires or consent or authority is withdrawn.</Typography>
        <Typography>Review expires: {review.expires_at}</Typography>
        <Typography>Further delegation: prohibited</Typography>
        <Typography variant="subtitle2" component="h3">Exact operation and constraints</Typography>
        <Box component="pre" sx={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere', m: 0 }}>{JSON.stringify(review.terms.constraints, null, 2)}</Box>
        <Typography variant="body2">Terms digest: {review.grant.terms_digest}</Typography>
        <details><summary>Complete immutable terms</summary><Box component="pre" sx={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}>{JSON.stringify(review.terms, null, 2)}</Box></details>
      </Stack>
    </Paper>}
    {review && !journal && <>
      {expired && <Alert severity="warning">This review expired. Load the current exact terms again.</Alert>}
      <FormControlLabel control={<Checkbox checked={checked} disabled={busy || expired || !canApprove || !canView || storageError} onChange={event => setChecked(event.target.checked)} />}
        label="I explicitly approve these exact terms on behalf of this organization." />
      <Button variant="contained" disabled={!checked || busy || expired || !canApprove || !canView || storageError} onClick={() => submitConfirmation(false)}>Confirm exact terms</Button>
    </>}
    {journal && !confirmed && !withdrawn && <Button variant="contained" disabled={busy || !canView || storageError} onClick={() => submitConfirmation(true)}>Check original confirmation</Button>}
    {confirmed && <Alert severity="success">
      Confirmation {confirmed.confirmation_id} was recorded at {confirmed.confirmed_at}. Its original validity ends at {confirmed.valid_until}.
      {confirmed.recovered && ' This is the original recorded result; recovery does not renew authority.'}
    </Alert>}
    {(confirmed || journal) && !withdrawn && canView && <>
      {!confirmed && <Typography variant="body2">If the original request was recorded, you can withdraw that consent from your current session. This does not create or renew consent.</Typography>}
      <Button color="error" variant="outlined" disabled={busy || storageError} onClick={withdraw}>{confirmed ? 'Withdraw this consent' : 'Withdraw recorded consent'}</Button>
    </>}
    {withdrawn && <Alert severity="info">Consent was withdrawn at {withdrawn.withdrawn_at}. Historical records remain available.</Alert>}
  </Stack>;
}

export default function DelegationApprovalPage() {
  const { grantId } = useParams(); const [query] = useSearchParams();
  const { activeOrgId } = useConsole(); const { user } = useAuth();
  const { can, isLoading, error, refresh } = usePermissions();
  const actorId = user?.user_id || user?.sub || user?.id;
  const revisionText = query.get('revision');
  const termsDigest = query.get('terms_digest');
  const grant = useMemo(() => ({ id: grantId, revision: Number(revisionText), terms_digest: termsDigest }), [grantId, revisionText, termsDigest]);
  if (!isAgentTrustFeatureEnabled('delegationApproval')) return <Alert severity="info">Delegation approval is not enabled in this application.</Alert>;
  if (isLoading) return <CircularProgress aria-label="Checking permissions" />;
  if (error) return <Alert severity="error" action={<Button color="inherit" onClick={refresh}>Retry</Button>}>Approval permissions could not be checked.</Alert>;
  if (!can('delegation-grant', 'view')) return <Alert severity="error">You do not have permission to review delegated authority in this organization.</Alert>;
  if (!isAgentTrustId(activeOrgId) || !isAgentTrustId(actorId) || !validGrantReference(grant)
    || String(grant.revision) !== revisionText || query.getAll('revision').length !== 1 || query.getAll('terms_digest').length !== 1) {
    return <Alert severity="error">Open an approval link containing the exact grant revision and terms digest, and select its organization.</Alert>;
  }
  // A tenant/account/reference change unmounts every old action and review.
  return <Box sx={{ maxWidth: 960, mx: 'auto', p: 3 }}><Approval key={`${activeOrgId}:${actorId}:${grantId}:${revisionText}:${grant.terms_digest}`}
    organizationId={activeOrgId} actorId={actorId} grant={grant} canApprove={can('delegation-grant', 'approve')} canView={can('delegation-grant', 'view')} /></Box>;
}

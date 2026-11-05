import { useEffect, useRef, useState } from 'react';
import { Accordion, AccordionDetails, AccordionSummary, Alert, Box, Button, Checkbox, Chip, CircularProgress,
  FormControl, FormControlLabel, InputLabel, MenuItem, Paper, Select, Stack, Typography } from '@mui/material';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import { QRCodeSVG } from 'qrcode.react';
import { publicVerificationApi as api, createVerificationCapability } from '../../services/publicVerificationApi';
import { SEOHead } from '../seo';

const storageKey = 'marty.public-verification.v1';
const pending = session => session && ['awaiting_wallet', 'verifying'].includes(session.status);
function remember(value) {
  try { if (value) sessionStorage.setItem(storageKey, JSON.stringify(value)); else sessionStorage.removeItem(storageKey); } catch { /* The current tab can still finish without recovery storage. */ }
}
function recover() {
  try {
    const value = JSON.parse(sessionStorage.getItem(storageKey));
    if (!value || !/^[A-Za-z0-9_-]{43}$/.test(value.key) || !value.selection || value.selection.consent !== true
      || !Number.isFinite(value.savedAt) || value.savedAt > Date.now()
      || (value.id ? (!Number.isFinite(value.accessExpiresAt) || value.accessExpiresAt <= Date.now()) : Date.now() - value.savedAt > 30 * 60_000)) { remember(null); return null; }
    return value;
  } catch { remember(null); return null; }
}
function failure(error) {
  const status = error?.status ?? error?.response?.status;
  if (status === 409) return 'The request or session changed. Review the current request and start a new verification.';
  if (status === 429) return 'The demonstration is busy. Wait a moment, then retry this session.';
  if (status === 404) return 'This demonstration or session is unavailable. Start again when the service is ready.';
  return 'The service could not confirm the result. Retry this session to check its progress.';
}
function resultMessage(session) {
  if (session.verified === true) return ['success', 'Verified', 'The verifier accepted this presentation against the selected requirements.'];
  if (session.verified === false) return ['warning', 'Not verified', 'The verifier did not accept this presentation against the selected requirements.'];
  if (session.status === 'expired') return ['info', 'Session expired', 'Start a new verification for a fresh request.'];
  if (session.status === 'cancelled') return ['info', 'Verification cancelled', 'No verification decision was made.'];
  if (session.example_status === 'input_rejected') return ['warning', 'Example input rejected', 'The holder could not prepare a valid presentation from this signed sample. The verifier has not made a decision.'];
  if (session.example_status === 'retry_exhausted') return ['info', 'Example could not finish', 'The attempt limit was reached without a confirmed decision. Start a new session.'];
  if (session.example_id) return ['info', 'Preparing your example', 'Marty presents a signed fictional credential to the verifier. This does not verify your identity.'];
  return ['info', 'Waiting for your wallet', 'Review the request in your wallet, then choose whether to share.'];
}

export default function PublicVerificationPage() {
  const [catalog, setCatalog] = useState(null);
  const [scenarioId, setScenarioId] = useState('');
  const [choiceId, setChoiceId] = useState('');
  const [exampleId, setExampleId] = useState('');
  const [mode, setMode] = useState('example');
  const [consent, setConsent] = useState(false);
  const [preview, setPreview] = useState(null);
  const [previewError, setPreviewError] = useState(false);
  const [session, setSession] = useState(null);
  const [recovery, setRecovery] = useState(recover);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(true);
  const [clock, setClock] = useState(Date.now());
  const generation = useRef(0);
  const operation = useRef(false);
  const recoveryRef = useRef(recovery);
  const scenario = catalog?.scenarios.find(item => item.id === scenarioId);
  const choice = scenario?.choices.find(item => item.id === choiceId);
  const examples = catalog?.examples.filter(item => item.scenario_id === scenarioId) ?? [];
  const example = examples.find(item => item.id === exampleId);

  function save(value) { recoveryRef.current = value; setRecovery(value); remember(value); }
  useEffect(() => {
    let active = true;
    const controller = new AbortController();
    api.catalog({ signal: controller.signal }).then(value => {
      if (!active) return;
      setCatalog(value);
      const saved = recoveryRef.current;
      const previous = saved?.selection;
      const first = (previous?.catalog_revision === value.revision && value.scenarios.find(item => item.id === previous.scenario_id))
        || value.scenarios.find(item => value.examples.some(sample => sample.scenario_id === item.id)) || value.scenarios[0];
      setScenarioId(first.id); setChoiceId(first.choices.find(item => item.id === previous?.choice_id)?.id ?? first.choices[0].id);
      setExampleId(value.examples.find(item => item.id === previous?.example_id && item.scenario_id === first.id)?.id ?? value.examples.find(item => item.scenario_id === first.id)?.id ?? '');
      if (saved && !previous?.example_id) setMode('wallet');
      const version = generation.current;
      if (saved?.id) api.session(saved.id, saved.key, { signal: controller.signal }).then(current => {
        if (active && version === generation.current) setSession(current);
      }).catch(() => { if (active && version === generation.current) setError('A previous session could not be read. Retry it or start a new verification.'); });
    }).catch(() => { if (active) setError('The verification demonstration is currently unavailable. Please try again later.'); })
      .finally(() => { if (active) setLoading(false); });
    return () => { active = false; controller.abort(); generation.current += 1; };
  }, []);

  const previewReady = preview && preview.catalog_revision === catalog?.revision && preview.scenario_id === scenarioId && preview.choice_id === choiceId;
  useEffect(() => {
    if (!catalog || !scenarioId || !choiceId) return undefined;
    let active = true;
    const controller = new AbortController();
    setPreviewError(false);
    api.preview({ catalog_revision: catalog.revision, scenario_id: scenarioId, choice_id: choiceId }, { signal: controller.signal })
      .then(value => { if (active) setPreview(value); })
      .catch(() => { if (active) { setPreview(null); setPreviewError(true); } });
    return () => { active = false; controller.abort(); };
  }, [catalog, scenarioId, choiceId]);

  useEffect(() => {
    if (!recovery?.id || !Number.isFinite(recovery.accessExpiresAt)) return undefined;
    const key = recovery.key;
    const timer = setTimeout(() => {
      if (recoveryRef.current?.key !== key) return;
      generation.current += 1; recoveryRef.current = null; remember(null);
      setRecovery(null); setSession(null); setConsent(false);
      setError('Result access has ended. Start a new verification.');
    }, Math.max(0, Math.min(2_147_483_647, recovery.accessExpiresAt - Date.now())));
    return () => clearTimeout(timer);
  }, [recovery]);

  useEffect(() => {
    if (!pending(session) || !recovery?.id) return undefined;
    const version = generation.current;
    let inFlight = false;
    const controller = new AbortController();
    const timer = setInterval(async () => {
      setClock(Date.now());
      if (inFlight || operation.current) return;
      inFlight = true;
      try {
        const current = await api.session(recovery.id, recovery.key, { signal: controller.signal });
        if (version === generation.current) { setSession(current); setError(''); }
      } catch { /* A polling outage never creates a new session or a verdict. */ }
      finally { inFlight = false; }
    }, 2500);
    return () => { clearInterval(timer); controller.abort(); };
  }, [session, recovery]);

  function reset() {
    generation.current += 1;
    const old = recoveryRef.current;
    if (old?.id && pending(session)) api.cancel(old.id, old.key).catch(() => {});
    save(null); setSession(null); setConsent(false); setError('');
  }
  function edit(action) { reset(); action(); }
  async function run(resume = false) {
    if (operation.current) return;
    operation.current = true; setBusy(true); setError('');
    const version = generation.current;
    let saved = resume ? recoveryRef.current : null;
    try {
      if (!saved) {
        if (!consent || !choice || !previewReady || (mode === 'example' && !example)) return;
        saved = { key: createVerificationCapability(), savedAt: Date.now(), selection: {
          catalog_revision: catalog.revision, scenario_id: scenarioId, choice_id: choiceId, consent: true, request_digest: preview.request_digest,
          ...(mode === 'example' ? { example_id: exampleId } : {}),
        } };
        save(saved); // Save before a request whose response might be lost.
      }
      let current = saved.id ? await api.session(saved.id, saved.key) : await api.launch(saved.selection, saved.key);
      if (version !== generation.current) return;
      saved = { ...saved, id: current.session_id, accessExpiresAt: Date.parse(current.access_expires_at) }; save(saved); setSession(current);
      if (pending(current) && current.example_id && !['input_rejected', 'retry_exhausted'].includes(current.example_status)) {
        current = await api.example(current.session_id, saved.key);
        if (version === generation.current) { setSession(current); setClock(Date.now()); }
      }
    } catch (cause) { if (version === generation.current) setError(failure(cause)); }
    finally { operation.current = false; setBusy(false); }
  }
  async function cancel() {
    if (!recovery?.id || operation.current) return;
    operation.current = true; setBusy(true);
    const version = generation.current;
    try { const current = await api.cancel(recovery.id, recovery.key); if (version === generation.current) setSession(current); }
    catch (cause) { if (version === generation.current) setError(failure(cause)); }
    finally { operation.current = false; setBusy(false); }
  }

  const expires = session && Date.parse(session.expires_at);
  const locallyExpired = pending(session) && expires <= clock;
  const displayed = locallyExpired ? { ...session, status: 'expired', example_status: undefined } : session;
  const result = displayed && resultMessage(displayed);
  const currentScenario = catalog && session && catalog.revision === session.catalog_revision ? catalog.scenarios.find(item => item.id === session?.scenario_id) : null;
  const currentChoice = currentScenario?.choices.find(item => item.id === session?.choice_id);
  return <Box sx={{ py: { xs: 4, md: 7 }, maxWidth: 1040, mx: 'auto' }}>
    <SEOHead title="Try credential verification | Marty" description="Verify a signed fictional credential, customize the request, or use a compatible wallet." canonicalPath="/verify" />
    <Chip label="Marty verification demo" color="primary" variant="outlined" />
    <Typography component="h1" variant="h3" fontWeight={800} sx={{ mt: 2, mb: 2, fontSize: { xs: '2rem', sm: '3rem' }, lineHeight: 1.12 }}>See a credential get verified.</Typography>
    <Typography color="text.secondary" sx={{ maxWidth: 680, mb: 4 }}>Start with a signed fictional example. Change what the verifier requires and see what happens. No account or wallet installation is needed for the example.</Typography>
    {loading && <Box role="status"><CircularProgress size={24} /> Loading demonstration...</Box>}
    {error && <Alert severity="warning" sx={{ mb: 3 }}>{error}</Alert>}
    {!loading && !catalog && <Button onClick={() => window.location.reload()}>Try again</Button>}
    {catalog && <Box sx={{ display: 'grid', gridTemplateColumns: { xs: '1fr', md: '1.1fr 1fr' }, gap: 3, alignItems: 'start' }}>
      <Paper variant="outlined" sx={{ p: { xs: 2, sm: 3 }, minWidth: 0 }}>
        <Typography component="h2" variant="h5" fontWeight={700}>{session ? 'Verification result' : 'Your signed example'}</Typography>
        {result ? <>
          <Alert severity={result[0]} sx={{ mt: 2 }} role="status"><Typography fontWeight={700}>{result[1]}</Typography>{result[2]}</Alert>
          <Typography sx={{ mt: 2 }}>{currentScenario?.label ?? 'Selected scenario'} &middot; {currentChoice?.label ?? 'Original request'}</Typography>
          {session.example_id && <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>This result concerns a fictional credential. It establishes no fact about you.</Typography>}
          {pending(displayed) && !session.example_id && <Box sx={{ mt: 3, textAlign: 'center' }}>
            <Box sx={{ bgcolor: 'white', p: 2, display: 'inline-flex', maxWidth: '100%' }}><QRCodeSVG value={session.wallet_uri} size={208} title="Wallet verification request" style={{ maxWidth: '100%', height: 'auto' }} /></Box>
            <Button component="a" href={session.wallet_uri} variant="contained" fullWidth sx={{ mt: 2 }}>Open compatible wallet</Button>
            <Typography variant="body2" sx={{ mt: 1 }}>Use a wallet holding a credential that matches this request. Review disclosure in your wallet. You can decline.</Typography>
          </Box>}
          {pending(displayed) && <Typography variant="body2" sx={{ mt: 2 }}>Request expires at {new Date(session.expires_at).toLocaleTimeString()}.</Typography>}
        </> : <Box sx={{ mt: 3 }}>
          <Typography variant="h6">{mode === 'example' ? (example?.label ?? 'No example configured') : 'Use your own wallet'}</Typography>
          <Typography color="text.secondary" sx={{ mt: 1 }}>{mode === 'example' ? (example?.description ?? 'Choose another scenario or use a compatible wallet.') : 'Your wallet needs a matching credential from an issuer accepted by this demonstration.'}</Typography>
        </Box>}
        {recovery && <Stack direction="row" gap={1} flexWrap="wrap" sx={{ mt: 3 }}>
          {(!displayed || pending(displayed)) && !['input_rejected', 'retry_exhausted'].includes(session?.example_status) && <Button disabled={busy} variant="contained" onClick={() => run(true)}>{busy ? 'Checking...' : 'Resume verification'}</Button>}
          {pending(displayed) && <Button disabled={busy} onClick={cancel}>Cancel</Button>}
          <Button disabled={busy} onClick={reset}>Start a new verification</Button>
        </Stack>}
      </Paper>
      <Stack spacing={2}>
        <Paper variant="outlined" sx={{ p: { xs: 2, sm: 3 } }}>
          <Typography component="h2" variant="h6" fontWeight={700}>What the verifier requires</Typography>
          <Typography sx={{ mt: 1 }}>{session ? (currentScenario?.label ?? 'Original scenario') : scenario?.label} &middot; {session ? (currentChoice?.label ?? 'Original request') : choice?.label}</Typography>
          {!session && !previewReady && <Alert severity={previewError ? 'warning' : 'info'} sx={{ mt: 2 }}>{previewError ? 'The exact request could not be loaded. Refresh before giving consent.' : 'Loading the exact requested information...'}</Alert>}
          {previewReady && (!session || (session.catalog_revision === preview.catalog_revision && session.scenario_id === preview.scenario_id && session.choice_id === preview.choice_id)) && <Box component="ul" sx={{ pl: 2.5, mb: 0 }}>{preview.claims.map(claim => <Box component="li" key={claim.name} sx={{ mb: 2 }}>
            <Typography fontWeight={600}>{claim.display_name} ({claim.name})</Typography>
            <Typography variant="body2">{claim.required ? 'Required' : 'Optional'}{claim.purpose ? `: ${claim.purpose}` : ''}</Typography>
            {claim.constraints.map((rule, index) => <Typography variant="body2" key={index}>{rule.kind.replaceAll('_', ' ')}{rule.value !== null ? `: ${JSON.stringify(rule.value)}` : ''}</Typography>)}
            <Typography variant="body2" color="text.secondary">{claim.intent_to_retain === null ? 'Retention intent is not specified by this policy.' : claim.intent_to_retain ? 'The request declares an intent to retain this information.' : 'The request declares no intent to retain this information.'}</Typography>
          </Box>)}</Box>}
          <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>Signature, issuer trust, validity and session binding are checked by the verifier. Changing an eligibility requirement does not turn these checks off.</Typography>
          {!recovery && <>
          <Typography variant="body2" color="text.secondary" sx={{ mt: 2 }}>Session details are scheduled for deletion after the verification deadline plus {catalog.retention_policy.result_access_seconds / 60} minutes of result access. A minimal launch receipt is retained for {catalog.retention_policy.receipt_days} days for abuse prevention.</Typography>
          <FormControlLabel sx={{ mt: 3, alignItems: 'flex-start' }} control={<Checkbox disabled={!previewReady} checked={consent} onChange={event => setConsent(event.target.checked)} />} label={catalog.notice} />
          <Button size="large" variant="contained" fullWidth disabled={busy || !consent || !choice || !previewReady || (mode === 'example' && !example)} onClick={() => run()} sx={{ mt: 2 }}>{busy ? 'Verifying...' : mode === 'example' ? 'Verify example' : 'Create wallet request'}</Button>
          </>}
        </Paper>
        <Accordion disableGutters>
          <AccordionSummary expandIcon={<ExpandMoreIcon />}><Typography>Customize the request</Typography></AccordionSummary>
          <AccordionDetails><Stack spacing={2}>
            <FormControl fullWidth><InputLabel id="verify-scenario-label">Scenario</InputLabel><Select labelId="verify-scenario-label" label="Scenario" value={scenarioId} disabled={busy} onChange={event => edit(() => { const next = catalog.scenarios.find(item => item.id === event.target.value); setScenarioId(next.id); setChoiceId(next.choices[0].id); setExampleId(catalog.examples.find(item => item.scenario_id === next.id)?.id ?? ''); })}>{catalog.scenarios.map(item => <MenuItem key={item.id} value={item.id}>{item.label}</MenuItem>)}</Select></FormControl>
            <FormControl fullWidth><InputLabel id="verify-choice-label">Requirement</InputLabel><Select labelId="verify-choice-label" label="Requirement" value={choiceId} disabled={busy} onChange={event => edit(() => setChoiceId(event.target.value))}>{scenario?.choices.map(item => <MenuItem key={item.id} value={item.id}>{item.label}</MenuItem>)}</Select></FormControl>
            {mode === 'example' && examples.length > 0 && <FormControl fullWidth><InputLabel id="verify-example-label">Signed specimen</InputLabel><Select labelId="verify-example-label" label="Signed specimen" value={exampleId} disabled={busy} onChange={event => edit(() => setExampleId(event.target.value))}>{examples.map(item => <MenuItem key={item.id} value={item.id}>{item.label}</MenuItem>)}</Select></FormControl>}
            <Typography variant="body2">An edit clears the result and needs fresh consent. Available choices are governed Marty policies.</Typography>
          </Stack></AccordionDetails>
        </Accordion>
        <Button disabled={busy} onClick={() => edit(() => setMode(mode === 'example' ? 'wallet' : 'example'))}>{mode === 'example' ? 'Use your wallet instead' : 'Back to the signed example'}</Button>
      </Stack>
    </Box>}
  </Box>;
}

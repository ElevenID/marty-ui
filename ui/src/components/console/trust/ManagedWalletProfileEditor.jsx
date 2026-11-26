import { useEffect, useRef, useState } from 'react';
import { Link as RouterLink, useLocation } from 'react-router';
import { Alert, Box, Button, Checkbox, FormControl, FormControlLabel, InputLabel, Link, MenuItem, Paper, Select, TextField, Typography } from '@mui/material';
import { useAuth } from '../../../hooks/useAuth';
import { usePermissions } from '../../../hooks/usePermissions';
import { useAsyncActionScope } from '../../../hooks/useAsyncActionScope';
import { buildManagedWalletVerifierSource, getTrustProfile, updateTrustProfile, validateWalletSigningKeys } from '../../../services/presentationPolicyApi';
import WalletIssuerTrustEditor from './WalletIssuerTrustEditor';
import WalletProfileActivation from './WalletProfileActivation';

const empty = () => ({ producer_id: '', public_base_url: '', verifier_did: '', request_key_id: '', public_jwk: '', valid_from: '', valid_until: '', enabled: false });
const fromSource = (source) => source ? {
  ...empty(), ...source.managed_flow_verifier,
  public_jwk: JSON.stringify(source.managed_flow_verifier?.public_jwk || {}, null, 2), enabled: source.enabled === true,
} : empty();
const canonical = (value) => Array.isArray(value) ? value.map(canonical)
  : value && typeof value === 'object' ? Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonical(value[key])])) : value;
const sameValue = (left, right) => JSON.stringify(canonical(left)) === JSON.stringify(canonical(right));

function WalletVerifierEditor({ profile, organizationId, canActivate, disabled, onBusyChange, onProfileSaved }) {
  const [current, setCurrent] = useState(profile);
  const first = profile.trust_sources?.find((source) => source.source_type === 'MANAGED_FLOW_VERIFIER');
  const [selected, setSelected] = useState(first?.id || 'new');
  const [form, setForm] = useState(() => fromSource(first));
  const [reviewed, setReviewed] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);
  const [success, setSuccess] = useState(false);
  const [reloadRequired, setReloadRequired] = useState(false);
  const pending = useRef(false);
  const operationBusy = (value) => { pending.current = value; setBusy(value); onBusyChange(value); };
  const entry = useRef({ href: window.location.href, key: window.history.state?.key });
  const startAction = useAsyncActionScope();
  const begin = () => {
    const action = startAction();
    return { action, isCurrent: () => action.isCurrent() && window.location.href === entry.current.href
      && window.history.state?.key === entry.current.key };
  };
  const accept = (result, sourceId = selected) => {
    if (result?.id !== profile.id || result.organization_id !== organizationId
      || result.profile_type !== 'CUSTOM' || JSON.stringify(result.trust_purposes) !== '["PRESENTATION_VERIFIER"]'
      || !Array.isArray(result.trust_sources) || !result.updated_at) {
      throw new Error('The profile response does not match this organization and wallet purpose. Reload to inspect it.');
    }
    setCurrent(result);
    const source = result.trust_sources.find((item) => item.id === sourceId && item.source_type === 'MANAGED_FLOW_VERIFIER');
    setSelected(source?.id || 'new');
    setForm(fromSource(source));
    setReviewed(false);
    onProfileSaved(result);
  };
  const reload = async () => {
    if (pending.current || disabled) return;
    const { action, isCurrent } = begin();
    if (!isCurrent()) return;
    operationBusy(true); setError(null); setSuccess(false);
    try {
      const result = await action.run(getTrustProfile, profile.id, { isCurrent, singleAttemptReads: true });
      if (!isCurrent()) return;
      accept(result); setReloadRequired(false);
    } catch (failure) { if (isCurrent()) setError(failure.message); }
    finally { if (isCurrent()) operationBusy(false); }
  };
  const save = async () => {
    if (pending.current || disabled || reloadRequired || !reviewed) return;
    const { action, isCurrent } = begin();
    if (!isCurrent()) return;
    operationBusy(true); setError(null); setSuccess(false);
    let dispatched = false;
    try {
      let publicKey;
      try { publicKey = JSON.parse(form.public_jwk); } catch { throw new Error('Import the public signing key as a valid JWK object.'); }
      const registrationSource = buildManagedWalletVerifierSource({ enabled: form.enabled, managed_flow_verifier: {
        producer_id: form.producer_id.trim(), public_base_url: form.public_base_url.trim(),
        verifier_did: form.verifier_did.trim(), request_key_id: form.request_key_id.trim(), public_jwk: publicKey,
        valid_from: form.valid_from.trim(), valid_until: form.valid_until.trim(),
      } }, selected === 'new' ? undefined : selected);
      await action.run(validateWalletSigningKeys, [publicKey], { verifier: true, requestKeyId: registrationSource.managed_flow_verifier.request_key_id });
      if (!isCurrent()) return;
      const fresh = await action.run(getTrustProfile, profile.id, { isCurrent, singleAttemptReads: true });
      if (!isCurrent()) return;
      if (fresh.id !== current.id || fresh.organization_id !== organizationId || !current.updated_at
        || fresh.updated_at !== current.updated_at || !sameValue(fresh.trust_sources, current.trust_sources)) {
        setReloadRequired(true);
        throw new Error('The profile changed. Reload and review its latest verifier configuration.');
      }
      if (selected !== 'new' && !fresh.trust_sources.some((item) => item.id === selected && item.source_type === 'MANAGED_FLOW_VERIFIER')) {
        throw new Error('The selected verifier is no longer available. Reload before saving.');
      }
      const source = { ...fresh.trust_sources.find((item) => item.id === selected), ...registrationSource };
      const sources = selected === 'new' ? [...fresh.trust_sources, source]
        : fresh.trust_sources.map((item) => item.id === selected ? source : item);
      dispatched = true;
      const result = await action.run(updateTrustProfile, profile.id, {
        trust_sources: sources, compliance_status: 'COMPLIANT',
      }, { isCurrent });
      if (!isCurrent()) return;
      const saved = result.trust_sources?.find((item) => item.source_type === 'MANAGED_FLOW_VERIFIER'
        && (selected === 'new' || item.id === selected)
        && item.enabled === source.enabled
        && sameValue(item.managed_flow_verifier, source.managed_flow_verifier));
      if (!saved?.id || result.compliance_status !== 'COMPLIANT') {
        throw new Error('The saved verifier could not be confirmed. Reload to inspect the profile.');
      }
      accept(result, saved.id); setSuccess(true);
    } catch (failure) {
      if (isCurrent()) { setError(failure.message); if (dispatched) setReloadRequired(true); }
    } finally { if (isCurrent()) operationBusy(false); }
  };
  const change = (field, value) => { setForm((prior) => ({ ...prior, [field]: value })); setReviewed(false); setSuccess(false); };
  return <Paper sx={{ p: 3, mb: 3 }}>
    <Typography variant="h5" component="h2" gutterBottom>Wallet verifier configuration</Typography>
    <Typography sx={{ mb: 2 }}>Use the Flow service identity and public signing key approved for this organization. Enabling a verifier does not activate a draft profile.</Typography>
    {current.status === 'active' && <Alert severity="info" sx={{ mb: 2 }}>This profile is active. Saved changes take effect immediately.</Alert>}
    {error && <Alert severity="error" sx={{ mb: 2 }}>{error}</Alert>}
    {success && <Alert severity="success" sx={{ mb: 2 }}>Verifier configuration saved. Profile activation is a separate action.</Alert>}
    {reloadRequired && <Alert severity="info" sx={{ mb: 2 }}>A write may already have completed. Reload the saved configuration before making another change.</Alert>}
    <Box component="fieldset" disabled={disabled || busy || reloadRequired} sx={{ border: 0, p: 0, m: 0 }}>
      <FormControl fullWidth disabled={disabled || busy || reloadRequired} sx={{ mb: 2 }}>
        <InputLabel id="wallet-verifier-selection">Verifier registration</InputLabel>
        <Select labelId="wallet-verifier-selection" label="Verifier registration" value={selected} onChange={(event) => {
          setSelected(event.target.value); setForm(fromSource(current.trust_sources.find((source) => source.id === event.target.value)));
          setReviewed(false); setSuccess(false);
        }}>
          <MenuItem value="new">Add a verifier</MenuItem>
          {current.trust_sources.filter((source) => source.source_type === 'MANAGED_FLOW_VERIFIER').map((source) => (
            <MenuItem key={source.id} value={source.id}>{source.managed_flow_verifier?.verifier_did || source.id}</MenuItem>
          ))}
        </Select>
      </FormControl>
      {[
        ['producer_id', 'Flow producer', 'Use the producer name configured by the installation owner.'],
        ['public_base_url', 'Flow public address', 'Exact HTTPS base address, without a trailing slash.'],
        ['verifier_did', 'Verifier DID', 'The published signing identity of the Flow service.'],
        ['request_key_id', 'Request key identifier', 'The exact key identifier within that DID.'],
        ['valid_from', 'Valid from (UTC)', 'Whole-second UTC, for example 2026-11-26T12:00:00Z.'],
        ['valid_until', 'Valid until (UTC)', 'Use the actual public key validity; this form does not extend it.'],
      ].map(([field, label, helper]) => <TextField key={field} fullWidth required label={label} helperText={helper}
        value={form[field]} onChange={(event) => change(field, event.target.value)} sx={{ mb: 2 }} />)}
      <TextField fullWidth required multiline minRows={4} label="Public request signing key (JWK)"
        helperText="Import the public P-256 signing key. Never enter a private key."
        value={form.public_jwk} onChange={(event) => change('public_jwk', event.target.value)} sx={{ mb: 2 }} />
      <FormControlLabel control={<Checkbox checked={form.enabled} onChange={(event) => change('enabled', event.target.checked)} />}
        label="Enable this verifier when the profile is active" />
      <FormControlLabel control={<Checkbox checked={reviewed} onChange={(event) => setReviewed(event.target.checked)} />}
        label="I have reviewed this verifier’s identity, public key and validity" />
    </Box>
    <Box sx={{ mt: 2, display: 'flex', flexWrap: 'wrap', gap: 2 }}>
      <Button variant="contained" onClick={save} disabled={disabled || busy || reloadRequired || !reviewed}>Save verifier configuration</Button>
      <Button onClick={reload} disabled={disabled || busy}>Reload wallet configuration</Button>
      <Link component={RouterLink} to={`/console/org/trust/profiles/${encodeURIComponent(profile.id)}`}>Profile details</Link>
    </Box>
    <WalletProfileActivation profile={current} organizationId={organizationId} canActivate={canActivate}
      ready={current.compliance_status === 'COMPLIANT' && current.trust_sources.some((source) => source.enabled
        && ['MANAGED_FLOW_VERIFIER', 'REGISTERED_VERIFIER'].includes(source.source_type))}
      disabled={disabled || busy || reloadRequired || !sameValue(form, fromSource(current.trust_sources.find((source) => source.id === selected)))}
      onActivated={(value) => { accept(value); setSuccess(false); }} onBusyChange={operationBusy}
      onReloadRequired={() => setReloadRequired(true)} />
  </Paper>;
}

export default function ManagedWalletProfileEditor({ profile, organizationId, disabled, onBusyChange, onProfileSaved }) {
  const { user, isAuthenticated } = useAuth();
  const { can, isLoading } = usePermissions();
  const location = useLocation();
  const grants = ['view', 'create', 'edit'].map((action) => can('trusted-issuer', action));
  const canActivate = can('trust-profile', 'activate');
  const key = JSON.stringify([profile.id, organizationId, user?.user_id || user?.sub || user?.id,
    isAuthenticated, location.key, location.pathname, location.search, location.hash, canActivate, ...grants]);
  useEffect(() => () => onBusyChange(false), [key, onBusyChange]);
  if (isLoading || !isAuthenticated) return <Alert severity="info">Sign in with the intended organization owner to configure wallet trust.</Alert>;
  return profile.trust_purposes[0] === 'PRESENTATION_VERIFIER'
    ? <WalletVerifierEditor key={key} profile={profile} organizationId={organizationId} canActivate={canActivate}
      disabled={disabled} onBusyChange={onBusyChange} onProfileSaved={onProfileSaved} />
    : <WalletIssuerTrustEditor key={key} profile={profile} organizationId={organizationId}
      canActivate={canActivate} canViewIssuers={grants[0]} canCreateIssuers={grants[1]} canEditIssuers={grants[2]}
      disabled={disabled} onBusyChange={onBusyChange} onProfileSaved={onProfileSaved} />;
}

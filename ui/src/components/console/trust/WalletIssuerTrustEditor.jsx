import { useCallback, useEffect, useRef, useState } from 'react';
import { Link as RouterLink } from 'react-router';
import { Alert, Box, Button, Checkbox, FormControl, FormControlLabel, InputLabel, Link, MenuItem, Paper, Select, TextField, Typography } from '@mui/material';
import { useAsyncActionScope } from '../../../hooks/useAsyncActionScope';
import { getTrustProfile, listIssuerEntities, listTrustProfileIssuers, saveWalletIssuerTrust, walletIssuerProfileSupported } from '../../../services/presentationPolicyApi';
import WalletProfileActivation from './WalletProfileActivation';

const CREDENTIAL_GRANTS = 'marty_credential_authorizations_v1';
const ISSUANCE_GRANTS = 'marty_wallet_issuance_authorizations_v1';
const emptyService = () => ({ credential_issuer: '', credential_configuration_id: '', format: 'dc+sd-jwt', vct: '', authorization_server: '', token_endpoint: '' });
const empty = () => ({ display_name: '', issuer_id: '', keys: '', types: '', services: [] });
const fromIssuer = (issuer, relationship) => issuer ? {
  display_name: issuer.display_name, issuer_id: issuer.issuer_id,
  keys: JSON.stringify(issuer.metadata?.verification_keys || [], null, 2),
  types: (relationship?.metadata?.[CREDENTIAL_GRANTS] || []).map((grant) => grant.vct).join('\n'),
  services: (relationship?.metadata?.[ISSUANCE_GRANTS] || []).map((grant) => Object.fromEntries(
    Object.keys(emptyService()).map((field) => [field, grant[field] ?? '']),
  )),
} : empty();

export default function WalletIssuerTrustEditor({ profile, organizationId, canActivate, canViewIssuers, canCreateIssuers, canEditIssuers, disabled, onBusyChange, onProfileSaved }) {
  const [current, setCurrent] = useState(profile);
  const [entities, setEntities] = useState([]);
  const [relationships, setRelationships] = useState([]);
  const [selected, setSelected] = useState('new');
  const [form, setForm] = useState(empty);
  const [reviewed, setReviewed] = useState(false);
  const [dirty, setDirty] = useState(false);
  const [busy, setBusy] = useState(false);
  const [loaded, setLoaded] = useState(false);
  const [error, setError] = useState(null);
  const [success, setSuccess] = useState(false);
  const [reloadRequired, setReloadRequired] = useState(false);
  const pending = useRef(false);
  const operationBusy = useCallback((value) => { pending.current = value; setBusy(value); onBusyChange(value); }, [onBusyChange]);
  const preferredDid = useRef('');
  const entry = useRef({ href: window.location.href, key: window.history.state?.key });
  const startAction = useAsyncActionScope();
  const begin = useCallback(() => {
    const action = startAction();
    return { action, isCurrent: () => action.isCurrent() && window.location.href === entry.current.href
      && window.history.state?.key === entry.current.key };
  }, [startAction]);
  const load = useCallback(async () => {
    if (pending.current || !canViewIssuers) return;
    const { action, isCurrent } = begin();
    if (!isCurrent()) return;
    operationBusy(true); setError(null); setSuccess(false);
    const options = { isCurrent, singleAttemptReads: true };
    try {
      const [fresh, issuers, links] = await action.run(() => Promise.all([
        getTrustProfile(profile.id, options), listIssuerEntities(organizationId, options),
        listTrustProfileIssuers(profile.id, organizationId, options),
      ]));
      if (!isCurrent()) return;
      if (fresh.id !== profile.id || fresh.organization_id !== organizationId
        || JSON.stringify(fresh.trust_purposes) !== '["CREDENTIAL_ISSUER"]' || !fresh.updated_at) {
        throw new Error('The profile response does not match the selected organization and wallet purpose.');
      }
      const owned = issuers.filter((issuer) => issuer.organization_id === organizationId && !issuer.is_system_issuer);
      const chosen = owned.find((issuer) => issuer.issuer_id === preferredDid.current);
      setCurrent(fresh); setEntities(owned); setRelationships(links);
      setSelected(chosen?.id || 'new');
      setForm(fromIssuer(chosen, links.find((link) => link.issuer_id === chosen?.id)));
      setReviewed(false); setDirty(false); setLoaded(true); setReloadRequired(false);
      onProfileSaved(fresh);
    } catch (failure) { if (isCurrent()) { setError(failure.message); setLoaded(false); } }
    finally { if (isCurrent()) operationBusy(false); }
  }, [begin, canViewIssuers, organizationId, profile.id, operationBusy, onProfileSaved]);
  useEffect(() => { void load(); }, [load]);

  const issuer = entities.find((item) => item.id === selected);
  const relationship = relationships.find((item) => item.issuer_id === selected);
  const permitted = canViewIssuers && (issuer ? canEditIssuers : canCreateIssuers)
    && (relationship ? canEditIssuers : canCreateIssuers);
  const compatible = walletIssuerProfileSupported(current);
  const change = (field, value) => { setForm((prior) => ({ ...prior, [field]: value })); setReviewed(false); setDirty(true); setSuccess(false); };
  const serviceChange = (index, field, value) => change('services', form.services.map((service, item) => item === index ? { ...service, [field]: value } : service));
  const save = async () => {
    if (pending.current || disabled || !loaded || !permitted || !compatible || !reviewed || reloadRequired) return;
    const { action, isCurrent } = begin();
    if (!isCurrent()) return;
    operationBusy(true); setError(null); setSuccess(false);
    try {
      let keys;
      try { keys = JSON.parse(form.keys); } catch { throw new Error('Import the public signing keys as a JSON array.'); }
      preferredDid.current = form.issuer_id.trim();
      const result = await action.run(saveWalletIssuerTrust, profile.id, organizationId, {
        profile_updated_at: current.updated_at,
        issuer: issuer || { issuer_id: form.issuer_id.trim(), display_name: form.display_name.trim() },
        relationship, verification_keys: keys,
        credential_types: form.types.split(/\r?\n/).map((value) => value.trim()).filter(Boolean),
        issuance_authorizations: form.services.map((service) => ({
          ...Object.fromEntries(['credential_issuer', 'credential_configuration_id', 'format', 'vct'].map((field) => [field, service[field].trim()])),
          authorization_server: service.authorization_server.trim() || null,
          token_endpoint: service.token_endpoint.trim() || null,
        })),
      }, { isCurrent });
      if (!isCurrent()) return;
      setCurrent(result.profile);
      setEntities((prior) => [...prior.filter((item) => item.id !== result.issuer.id), result.issuer]);
      setRelationships((prior) => [...prior.filter((item) => item.issuer_id !== result.issuer.id), result.relationship]);
      setSelected(result.issuer.id); setForm(fromIssuer(result.issuer, result.relationship));
      setReviewed(false); setDirty(false); setSuccess(true);
      onProfileSaved(result.profile);
    } catch (failure) {
      if (isCurrent()) { setError(failure.message); if (failure.walletReloadRequired) setReloadRequired(true); }
    } finally { if (isCurrent()) operationBusy(false); }
  };

  if (!canViewIssuers) return <Alert severity="info" sx={{ mb: 3 }}>Permission to view trusted issuers is required to configure wallet issuer trust.</Alert>;
  return <Paper sx={{ p: 3, mb: 3 }}>
    <Typography variant="h5" component="h2" gutterBottom>Wallet issuer configuration</Typography>
    <Typography sx={{ mb: 2 }}>Authorize exact public signing keys and credential types. Optional issuance services specify where a paired wallet may collect those credentials.</Typography>
    {current.status === 'active' && <Alert severity="info" sx={{ mb: 2 }}>This profile is active. Saved changes take effect immediately. Issuer key changes also affect other profiles linked to that issuer.</Alert>}
    {!compatible && <Alert severity="info" sx={{ mb: 2 }}>This profile uses additional trust controls that this wallet policy cannot satisfy. Create a dedicated paired-wallet issuer profile to keep those controls intact.</Alert>}
    {error && <Alert severity="error" sx={{ mb: 2 }}>{error}</Alert>}
    {success && <Alert severity="success" sx={{ mb: 2 }}>Issuer keys and grants saved. Profile activation is a separate action.</Alert>}
    {reloadRequired && <Alert severity="info" sx={{ mb: 2 }}>Some changes may already be saved. Reload, then select the saved issuer before continuing.</Alert>}
    {loaded && !permitted && <Alert severity="info" sx={{ mb: 2 }}>You need permission to create or edit the selected trusted issuer and its relationship.</Alert>}
    <Box component="fieldset" disabled={disabled || busy || !loaded || reloadRequired || !compatible} sx={{ border: 0, p: 0, m: 0 }}>
      <FormControl fullWidth disabled={disabled || busy || !loaded || reloadRequired || !compatible} sx={{ mb: 2 }}>
        <InputLabel id="wallet-issuer-selection">Issuer</InputLabel>
        <Select labelId="wallet-issuer-selection" label="Issuer" value={selected} onChange={(event) => {
          const value = entities.find((item) => item.id === event.target.value);
          setSelected(event.target.value); setForm(fromIssuer(value, relationships.find((item) => item.issuer_id === value?.id)));
          setReviewed(false); setDirty(false); setSuccess(false);
        }}>
          <MenuItem value="new" disabled={!canCreateIssuers}>Create an issuer</MenuItem>
          {entities.map((item) => <MenuItem key={item.id} value={item.id}>{item.display_name} — {item.issuer_id}</MenuItem>)}
        </Select>
      </FormControl>
      <TextField fullWidth required label="Issuer display name" value={form.display_name} disabled={Boolean(issuer) || !permitted}
        onChange={(event) => change('display_name', event.target.value)} sx={{ mb: 2 }} />
      <TextField fullWidth required label="Credential issuer identifier" value={form.issuer_id} disabled={Boolean(issuer) || !permitted}
        helperText="The exact signed issuer identifier, such as the issuer’s published DID."
        onChange={(event) => change('issuer_id', event.target.value)} sx={{ mb: 2 }} />
      <TextField fullWidth required multiline minRows={4} disabled={!permitted} label="Public issuer signing keys (JWK array)"
        helperText="Public P-256 or Ed25519 keys, with signing or verification usage. Never enter private keys."
        value={form.keys} onChange={(event) => change('keys', event.target.value)} sx={{ mb: 2 }} />
      <TextField fullWidth required multiline minRows={2} disabled={!permitted} label="Accepted credential types"
        helperText="One complete credential type URI per line. These grants apply to SD-JWT credentials."
        value={form.types} onChange={(event) => change('types', event.target.value)} sx={{ mb: 2 }} />
      <Typography variant="h6" component="h3" gutterBottom>Allowed issuance services</Typography>
      <Typography sx={{ mb: 2 }}>Leave this list empty to grant no credential collection services. Use the exact identifiers published by the issuer.</Typography>
      {form.services.map((service, index) => <Box key={index} sx={{ border: 1, borderColor: 'divider', p: 2, mb: 2 }}>
        <Typography component="h4" variant="subtitle1">Issuance service {index + 1}</Typography>
        {[
          ['credential_issuer', 'Credential issuer service'], ['credential_configuration_id', 'Credential configuration'],
          ['vct', 'Credential type'], ['authorization_server', 'Authorization server (optional)'], ['token_endpoint', 'Token endpoint (optional)'],
        ].map(([field, label]) => <TextField key={field} fullWidth disabled={!permitted} label={`${label} ${index + 1}`}
          value={service[field]} onChange={(event) => serviceChange(index, field, event.target.value)} sx={{ mt: 2 }} />)}
        <FormControl fullWidth disabled={disabled || busy || !loaded || reloadRequired || !compatible || !permitted} sx={{ mt: 2 }}>
          <InputLabel id={`wallet-issuance-format-${index}`}>Credential format {index + 1}</InputLabel>
          <Select labelId={`wallet-issuance-format-${index}`} label={`Credential format ${index + 1}`} value={service.format}
            onChange={(event) => serviceChange(index, 'format', event.target.value)}>
            <MenuItem value="dc+sd-jwt">dc+sd-jwt</MenuItem><MenuItem value="vc+sd-jwt">vc+sd-jwt</MenuItem>
          </Select>
        </FormControl>
        <Button disabled={!permitted} onClick={() => change('services', form.services.filter((_, item) => item !== index))} sx={{ mt: 1 }}>Remove service {index + 1}</Button>
      </Box>)}
      <Button disabled={!permitted || form.services.length >= 128} onClick={() => change('services', [...form.services, emptyService()])}>Add issuance service</Button>
      <FormControlLabel sx={{ display: 'flex', mt: 2 }} control={<Checkbox disabled={!permitted} checked={reviewed} onChange={(event) => setReviewed(event.target.checked)} />}
        label="I have reviewed this issuer, its public keys and these grants, and authorize their use" />
    </Box>
    <Box sx={{ mt: 2, display: 'flex', flexWrap: 'wrap', gap: 2 }}>
      <Button variant="contained" onClick={save} disabled={disabled || busy || !loaded || !permitted || !compatible || !reviewed || reloadRequired}>Save issuer configuration</Button>
      <Button onClick={load} disabled={disabled || busy}>Reload wallet configuration</Button>
      <Link component={RouterLink} to={`/console/org/trust/profiles/${encodeURIComponent(profile.id)}`}>Profile details</Link>
    </Box>
    <WalletProfileActivation profile={current} organizationId={organizationId} canActivate={canActivate}
      ready={compatible && current.compliance_status === 'COMPLIANT' && relationships.some((link) => link.relationship_status === 'TRUSTED'
        && link.metadata?.[CREDENTIAL_GRANTS]?.length && entities.some((entity) => entity.id === link.issuer_id && entity.metadata?.verification_keys?.length))}
      disabled={disabled || busy || !loaded || reloadRequired || dirty}
      onActivated={(value) => { setCurrent(value); setSuccess(false); onProfileSaved(value); }}
      onBusyChange={operationBusy} onReloadRequired={() => setReloadRequired(true)} />
  </Paper>;
}

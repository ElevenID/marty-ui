import { useRef, useState } from 'react';
import { useNavigate } from 'react-router';
import { Alert, Box, Button, Checkbox, FormControlLabel, Paper, TextField, Typography } from '@mui/material';
import { useAsyncActionScope } from '../../../hooks/useAsyncActionScope';
import { createTrustProfile } from '../../../services/presentationPolicyApi';

/** Create only a draft. Keys, grants and review belong to the next owner form. */
export default function WalletTrustProfileCreate({ organizationId, purpose, onBusyChange }) {
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [accepted, setAccepted] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);
  const [uncertain, setUncertain] = useState(false);
  const pending = useRef(false);
  const startAction = useAsyncActionScope();
  const navigate = useNavigate();
  const entry = useRef({ href: window.location.href, key: window.history.state?.key });
  const issuer = purpose === 'CREDENTIAL_ISSUER';
  const create = async () => {
    if (pending.current || uncertain || !name.trim() || !accepted) return;
    const action = startAction();
    const isCurrent = () => action.isCurrent() && window.location.href === entry.current.href
      && window.history.state?.key === entry.current.key;
    if (!isCurrent()) return;
    pending.current = true;
    setBusy(true);
    onBusyChange(true);
    setError(null);
    try {
      const profile = await action.run(createTrustProfile, {
        organization_id: organizationId, name: name.trim(), description: description.trim() || null,
        profile_type: 'CUSTOM', trust_purposes: [purpose], compliance_status: 'SETUP_REQUIRED',
        supported_formats: issuer ? ['SD_JWT_VC'] : [], trusted_assertion_formats: ['JWT'],
        trust_sources: [], allowed_issuers: [],
        allowed_algorithms: issuer ? ['ES256', 'EdDSA'] : ['ES256'],
        time_policy: { clock_skew_seconds: 30, require_freshness: false },
        revocation_policy: { check_mode: 'HARD_FAIL', check_ocsp: false, check_crl: false, check_status_list: false },
      }, { isCurrent });
      if (!isCurrent()) return;
      if (typeof profile?.id !== 'string' || !profile.id.trim() || profile.organization_id !== organizationId || profile.status !== 'draft'
        || JSON.stringify(profile.trust_purposes) !== JSON.stringify([purpose])) {
        throw new Error('The creation response is incomplete. Check the profile list before creating another profile.');
      }
      navigate(`/console/org/trust/profiles/${encodeURIComponent(profile.id)}/edit`);
    } catch (failure) {
      if (isCurrent()) {
        setError(failure.message || 'The draft could not be confirmed.');
        // A dispatched creation may have persisted even if its response was lost.
        setUncertain(true);
      }
    } finally {
      if (isCurrent()) {
        pending.current = false;
        setBusy(false);
        onBusyChange(false);
      }
    }
  };
  return <Paper sx={{ p: 3, maxWidth: 900, mx: 'auto' }}>
    <Typography variant="h5" component="h2" gutterBottom>
      {issuer ? 'Wallet credential issuers' : 'Wallet verifiers'}
    </Typography>
    <Typography sx={{ mb: 2 }}>
      {issuer
        ? 'Choose the issuers, public signing keys and credential types that a paired wallet may accept. Optional issuance service grants control where it may collect credentials.'
        : 'Register the identity and public request key of the Flow service that a paired wallet may trust.'}
    </Typography>
    <Alert severity="info" sx={{ mb: 2 }}>
      This creates a draft. Review its configuration before activating it.
      {issuer && ' This wallet policy checks explicit issuer keys and live trust state. It does not perform OCSP, CRL or status-list lookups.'}
    </Alert>
    {error && <Alert severity="error" sx={{ mb: 2 }}>{error}</Alert>}
    <Box component="fieldset" disabled={busy || uncertain} sx={{ border: 0, p: 0, m: 0 }}>
      <TextField fullWidth required label="Profile name" value={name} onChange={(event) => setName(event.target.value)} sx={{ mb: 2 }} />
      <TextField fullWidth multiline label="Description" value={description} onChange={(event) => setDescription(event.target.value)} sx={{ mb: 2 }} />
      <FormControlLabel control={<Checkbox checked={accepted} onChange={(event) => setAccepted(event.target.checked)} />}
        label="Use this dedicated wallet trust policy" />
    </Box>
    <Button variant="contained" disabled={busy || uncertain || !accepted || !name.trim()} onClick={create} sx={{ mt: 2 }}>
      {busy ? 'Creating draft…' : 'Create draft and configure'}
    </Button>
    {uncertain && <Button sx={{ ml: 2, mt: 2 }} onClick={() => navigate('/console/org/trust/profiles')}>
      Review profile list
    </Button>}
  </Paper>;
}

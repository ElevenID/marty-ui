import { useRef, useState } from 'react';
import { Alert, Button, Dialog, DialogActions, DialogContent, DialogTitle, Typography } from '@mui/material';
import { useAsyncActionScope } from '../../../hooks/useAsyncActionScope';
import { activateTrustProfile, getTrustProfile } from '../../../services/presentationPolicyApi';

/** Explicit human activation of the saved profile, separate from authoring. */
export default function WalletProfileActivation({ profile, organizationId, canActivate, ready, disabled, onActivated, onBusyChange, onReloadRequired }) {
  const [open, setOpen] = useState(false);
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(false);
  const pending = useRef(false);
  const entry = useRef({ href: window.location.href, key: window.history.state?.key });
  const startAction = useAsyncActionScope();
  const activate = async () => {
    if (pending.current || disabled || !ready || !canActivate || !open) return;
    const action = startAction();
    const isCurrent = () => action.isCurrent() && window.location.href === entry.current.href
      && window.history.state?.key === entry.current.key;
    if (!isCurrent()) return;
    pending.current = true; setBusy(true); setError(null); onBusyChange(true);
    let dispatched = false;
    try {
      const fresh = await action.run(getTrustProfile, profile.id, { isCurrent, singleAttemptReads: true });
      if (!isCurrent()) return;
      if (fresh.id !== profile.id || fresh.organization_id !== organizationId || !profile.updated_at
        || fresh.updated_at !== profile.updated_at || fresh.compliance_status !== 'COMPLIANT'
        || !['draft', 'suspended'].includes(fresh.status)
        || JSON.stringify(fresh.trust_purposes) !== JSON.stringify(profile.trust_purposes)) {
        onReloadRequired();
        throw new Error('The saved profile changed. Reload and review it before activation.');
      }
      dispatched = true;
      const active = await action.run(activateTrustProfile, profile.id, {
        isCurrent, allowReadback: false, singleAttemptReads: true,
      });
      if (!isCurrent()) return;
      if (active?.id !== profile.id || active.organization_id !== organizationId || active.status !== 'active'
        || active.compliance_status !== 'COMPLIANT'
        || JSON.stringify(active.trust_purposes) !== JSON.stringify(profile.trust_purposes)) {
        throw new Error('Activation could not be confirmed. Reload the profile to inspect its state.');
      }
      onActivated(active); setOpen(false);
    } catch (failure) {
      if (isCurrent()) { setError(failure.message); if (dispatched) onReloadRequired(); }
    } finally { if (isCurrent()) { pending.current = false; setBusy(false); onBusyChange(false); } }
  };
  if (profile.status === 'active') return <Alert severity="success" sx={{ mt: 2 }}>This wallet trust profile is active.</Alert>;
  return <>
    <Button sx={{ mt: 2 }} variant="outlined" disabled={disabled || !canActivate || !ready || !['draft', 'suspended'].includes(profile.status)}
      onClick={() => { setOpen(true); setError(null); }}>Activate reviewed profile</Button>
    {!canActivate && <Typography variant="body2" sx={{ mt: 1 }}>An owner with profile activation permission must activate this profile.</Typography>}
    <Dialog open={open} onClose={() => { if (!busy) setOpen(false); }} aria-labelledby="wallet-profile-activation-title">
      <DialogTitle id="wallet-profile-activation-title">Activate wallet trust profile</DialogTitle>
      <DialogContent>
        <Typography gutterBottom>Activate “{profile.name}” for the selected organization?</Typography>
        <Typography>Paired wallets can use the saved, reviewed trust configuration once this profile is active. This does not issue a credential or complete a verification.</Typography>
        {error && <Alert severity="error" sx={{ mt: 2 }}>{error}</Alert>}
      </DialogContent>
      <DialogActions>
        <Button disabled={busy} onClick={() => setOpen(false)}>Cancel</Button>
        <Button variant="contained" disabled={busy || disabled || !canActivate || !ready} onClick={activate}>Confirm activation</Button>
      </DialogActions>
    </Dialog>
  </>;
}

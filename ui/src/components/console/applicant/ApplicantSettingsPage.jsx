/**
 * Applicant Settings Page
 * 
 * Profile and preferences for applicants.
 */

import { useState, useEffect, useRef } from 'react';
import { useLocation } from 'react-router';
import {
  Box,
  Paper,
  Typography,
  TextField,
  Button,
  Grid,
  Alert,
  FormControlLabel,
  Checkbox,
  Chip,
  CircularProgress,
  Stack,
} from '@mui/material';
import SaveIcon from '@mui/icons-material/Save';
import AccountBalanceWalletIcon from '@mui/icons-material/AccountBalanceWallet';
import { useTranslation } from 'react-i18next';

import { useAuth } from '../../../hooks/useAuth';
import { useAsyncData } from '../../../hooks/useAsyncData';
import { getMyApplicantProfile, upsertMyApplicantProfile } from '../../../services/applicantApi';
import { listWallets } from '../../../services/walletRegistryApi';
import useWalletPreferences from '../../../hooks/useWalletPreferences';
import { getPlatform } from '../../../utils/deviceDetection';
import { WALLET_SELECTION_ALLOWED_WALLET_IDS } from '@ui-public-config';
import {
  createWalletSelectionAllowlist,
  filterSelectableWallets,
} from '../../../utils/walletSelectionRestrictions';

const walletSelectionAllowlist = createWalletSelectionAllowlist(WALLET_SELECTION_ALLOWED_WALLET_IDS);

function userDisplayName(user) {
  return user?.name
    || [user?.given_name, user?.family_name].filter(Boolean).join(' ')
    || '';
}

function ApplicantSettingsPage() {
  const { t } = useTranslation('applicant');
  const location = useLocation();
  const { user } = useAuth();
  const userId = user?.user_id;
  const currentUser = useRef(user);
  currentUser.current = user;
  const profileRequest = useRef(0);
  const [profileLoading, setProfileLoading] = useState(true);
  const [profileLoadError, setProfileLoadError] = useState(false);
  const [profileRetryCount, setProfileRetryCount] = useState(0);
  const [saving, setSaving] = useState(false);
  const [success, setSuccess] = useState(false);
  const [error, setError] = useState(null);
  const [applicantId, setApplicantId] = useState(null);
  const [profile, setProfile] = useState({
    name: userDisplayName(user),
    email: user?.email || '',
    phone: '',
  });

  // Wallet preferences
  const { walletIds: preferredWallets, addWallet, removeWallet } = useWalletPreferences(userId);
  const { data: wallets, loading: walletsLoading, error: walletsError, reload: reloadWallets } = useAsyncData(
    () => listWallets(true),
    [],
  );
  const registryWallets = Array.isArray(wallets) ? wallets : [];
  const walletLoadFailed = walletsError || (!walletsLoading && !Array.isArray(wallets));
  const walletSelectionRestricted = Boolean(walletSelectionAllowlist);
  const selectableRegistryWallets = filterSelectableWallets(registryWallets, WALLET_SELECTION_ALLOWED_WALLET_IDS);
  const platform = getPlatform();
  const iosSameDeviceLimitedWallets = platform === 'ios'
    ? selectableRegistryWallets.filter(
      (wallet) => preferredWallets.includes(wallet.id) && wallet.ios_same_device_single_wallet_only,
    )
    : [];
  const iosSameDeviceLimitedWalletNames = Array.from(
    new Set(iosSameDeviceLimitedWallets.map((wallet) => wallet.name).filter(Boolean)),
  );

  // Reload only for the account or an explicit retry. Updating unrelated auth
  // context or translations must not overwrite an in-progress profile edit.
  useEffect(() => {
    const request = ++profileRequest.current;
    const profileUser = currentUser.current;
    const isCurrent = () => profileRequest.current === request;

    setProfileLoading(true);
    setProfileLoadError(false);
    setApplicantId(null);
    setSaving(false);
    setSuccess(false);
    setError(null);
    setProfile({
      name: userDisplayName(profileUser),
      email: profileUser?.email || '',
      phone: '',
    });

    const loadProfile = async () => {
      try {
        if (userId) {
          let applicant = await getMyApplicantProfile();
          if (!isCurrent()) return;

          // If no profile exists, create one
          if (!applicant) {
            const nameParts = userDisplayName(profileUser).trim().split(/\s+/).filter(Boolean);
            applicant = await upsertMyApplicantProfile({
              email: profileUser.email || '',
              given_name: profileUser.given_name || nameParts[0] || '',
              family_name: profileUser.family_name || nameParts.slice(1).join(' ') || '',
            });
          }
          if (!isCurrent()) return;

          if (applicant?.id) {
            setApplicantId(applicant.id);
            setProfile({
              name: applicant.full_name
                || [applicant.given_name, applicant.family_name].filter(Boolean).join(' ')
                || userDisplayName(profileUser),
              email: applicant.email || profileUser.email || '',
              phone: applicant.phone || '',
            });
          } else {
            setProfileLoadError(true);
          }
        }
      } catch (err) {
        if (!isCurrent()) return;
        console.error('Error loading applicant profile:', err);
        setProfileLoadError(true);
      } finally {
        if (isCurrent()) setProfileLoading(false);
      }
    };

    loadProfile();
    return () => {
      profileRequest.current += 1;
    };
  }, [userId, profileRetryCount]);

  useEffect(() => {
    if (location.hash !== '#wallet-selection') {
      return;
    }

    const target = document.getElementById('wallet-selection');
    if (!target) {
      return;
    }

    target.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }, [location.hash]);

  const handleSave = async () => {
    if (profileLoading || saving || !applicantId) return;
    const request = profileRequest.current;
    setSaving(true);
    setError(null);
    setSuccess(false);

    try {
      // Split name into given_name and family_name
      const nameParts = profile.name.trim().split(/\s+/).filter(Boolean);
      const given_name = nameParts[0] || '';
      const family_name = nameParts.slice(1).join(' ') || '';

      await upsertMyApplicantProfile({
        given_name,
        family_name,
        phone: profile.phone,
      });

      if (profileRequest.current === request) setSuccess(true);
    } catch (err) {
      if (profileRequest.current !== request) return;
      console.error('Error saving settings:', err);
      setError(err.message || 'Failed to save settings');
    } finally {
      if (profileRequest.current === request) setSaving(false);
    }
  };

  const handleProfileChange = (field) => (event) => {
    setSuccess(false);
    setError(null);
    setProfile((prev) => ({ ...prev, [field]: event.target.value }));
  };

  return (
    <Box>
      <Typography variant="h4" gutterBottom>
        {t('settings.title')}
      </Typography>
      <Typography variant="body1" color="text.secondary" paragraph>
        {t('settings.description')}
      </Typography>

      {/* Profile Settings */}
      <Paper sx={{ p: 3, mb: 3 }}>
        <Typography variant="h6" gutterBottom>
          {t('settings.profile.title')}
        </Typography>
        {profileLoading && (
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 2 }} role="status">
            <CircularProgress size={20} />
            {t('common.loading', { ns: 'common' })}
          </Box>
        )}
        {profileLoadError && (
          <Alert
            severity="error"
            sx={{ mb: 3 }}
            action={(
              <Button color="inherit" onClick={() => setProfileRetryCount((count) => count + 1)}>
                {t('actions.retry', { ns: 'common' })}
              </Button>
            )}
          >
            {t('settings.profile.loadError', 'Your profile could not be loaded. Please try again.')}
          </Alert>
        )}
        {success && (
          <Alert severity="success" sx={{ mb: 3 }}>
            {t('settings.profile.saved', 'Profile saved.')}
          </Alert>
        )}
        {error && (
          <Alert severity="error" sx={{ mb: 3 }}>
            {error}
          </Alert>
        )}
        <Grid container spacing={3}>
          <Grid size={{ xs: 12, sm: 6 }}>
            <TextField
              fullWidth
              label={t('settings.profile.fullName')}
              value={profile.name}
              onChange={handleProfileChange('name')}
              disabled={profileLoading || saving || !applicantId}
            />
          </Grid>
          <Grid size={{ xs: 12, sm: 6 }}>
            <TextField
              fullWidth
              label={t('settings.profile.email')}
              value={profile.email}
              onChange={handleProfileChange('email')}
              disabled
              helperText={t('settings.profile.emailHelp')}
            />
          </Grid>
          <Grid size={{ xs: 12, sm: 6 }}>
            <TextField
              fullWidth
              label={t('settings.profile.phone')}
              value={profile.phone}
              onChange={handleProfileChange('phone')}
              disabled={profileLoading || saving || !applicantId}
            />
          </Grid>
        </Grid>
        <Button
          variant="contained"
          startIcon={<SaveIcon />}
          onClick={handleSave}
          disabled={profileLoading || saving || !applicantId}
          sx={{ mt: 3 }}
        >
          {saving ? t('settings.actions.saving') : t('settings.profile.save', 'Save profile')}
        </Button>
      </Paper>

      {/* Notification Settings */}
      <Paper sx={{ p: 3, mb: 3 }}>
        <Typography variant="h6" gutterBottom>
          {t('settings.notifications.title')}
        </Typography>
        <Alert severity="info">
          {t('settings.notifications.unavailable', 'Notification preferences are not available in this deployment.')}
        </Alert>
      </Paper>

      {/* My Wallets */}
      <Paper
        id="wallet-selection"
        sx={{ p: 3, mb: 3, scrollMarginTop: { xs: 80, sm: 96 } }}
        data-testid="wallet-selection-section"
      >
        <Stack direction="row" spacing={1} alignItems="center" sx={{ mb: 1 }}>
          <AccountBalanceWalletIcon color="primary" />
          <Typography variant="h6">My Wallets</Typography>
        </Stack>
        <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
          Choose the wallet apps you use. When you claim a credential, we&apos;ll show a tab for each
          selected wallet so you get the right handoff and QR code.
        </Typography>
        <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
          {t('settings.wallets.savedAutomatically', 'Wallet choices are saved automatically in this browser.')}
        </Typography>

        {walletSelectionRestricted && (
          <Alert severity="info" sx={{ mb: 2 }}>
            Wallet selection is limited for this deployment. Unavailable wallets are shown disabled.
          </Alert>
        )}

        {iosSameDeviceLimitedWalletNames.length > 0 && (
          <Alert severity="warning" sx={{ mb: 2 }} data-testid="ios-same-device-wallet-warning">
            iOS same-device flows for {iosSameDeviceLimitedWalletNames.join(', ')} are effectively
            limited to single-wallet support. Those wallets only expose raw{' '}
            <code>openid-credential-offer://</code> / <code>openid4vp://</code> links, and iOS does
            not deterministically choose the intended app when multiple wallets register the same
            scheme.
          </Alert>
        )}

        {walletsLoading ? (
          <Box sx={{ display: 'flex', justifyContent: 'center', py: 3 }}>
            <CircularProgress size={24} />
          </Box>
        ) : walletLoadFailed ? (
          <Alert
            severity="error"
            action={(
              <Button color="inherit" onClick={reloadWallets}>
                {t('actions.retry', { ns: 'common' })}
              </Button>
            )}
          >
            {t('settings.wallets.loadError', 'Available wallets could not be loaded. Please try again.')}
          </Alert>
        ) : registryWallets.length === 0 ? (
          <Alert severity="info">No wallets are available in the registry yet.</Alert>
        ) : (
          <Stack spacing={1}>
            {registryWallets.map((w) => {
              const enabled = !walletSelectionAllowlist || walletSelectionAllowlist.has(w.id);
              const checked = preferredWallets.includes(w.id);
              return (
                <FormControlLabel
                  key={w.id}
                  disabled={!enabled}
                  control={(
                    <Checkbox
                      checked={checked}
                      onChange={(_, selected) => selected ? addWallet(w.id) : removeWallet(w.id)}
                      slotProps={{ input: { 'aria-label': w.name } }}
                      sx={{ mr: 1, p: 0 }}
                    />
                  )}
                  label={(
                    <Box
                      component="span"
                      sx={{ display: 'flex', alignItems: 'center', flexWrap: 'wrap', gap: 1 }}
                    >
                      <Box component="span" sx={{ flex: '1 1 160px', minWidth: 0 }}>
                        <Typography component="span" variant="subtitle2" sx={{ display: 'block' }}>{w.name}</Typography>
                        {w.description && (
                          <Typography component="span" variant="caption" color="text.secondary">
                            {w.description}
                          </Typography>
                        )}
                      </Box>
                      <Box component="span" sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5 }}>
                        {!enabled && <Chip component="span" label="Unavailable" size="small" variant="outlined" />}
                        {(w.supported_platforms || w.platforms || []).map((p) => (
                          <Chip key={p} component="span" label={p} size="small" variant="outlined" />
                        ))}
                      </Box>
                    </Box>
                  )}
                  sx={{
                    display: 'flex',
                    alignItems: 'center',
                    m: 0,
                    p: 1.5,
                    borderRadius: 1,
                    border: 1,
                    borderColor: checked ? 'primary.main' : 'divider',
                    bgcolor: checked ? 'action.selected' : 'transparent',
                    cursor: enabled ? 'pointer' : 'not-allowed',
                    opacity: enabled ? 1 : 0.52,
                    '&:hover': enabled ? { bgcolor: 'action.hover' } : undefined,
                    '& .MuiFormControlLabel-label': { flex: 1, minWidth: 0 },
                  }}
                />
              );
            })}
          </Stack>
        )}
      </Paper>
    </Box>
  );
}

export default ApplicantSettingsPage;

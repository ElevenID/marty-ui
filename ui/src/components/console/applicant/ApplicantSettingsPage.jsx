/**
 * Applicant Settings Page
 * 
 * Profile and preferences for applicants.
 */

import { useState, useEffect } from 'react';
import { useLocation } from 'react-router-dom';
import {
  Box,
  Paper,
  Typography,
  TextField,
  Button,
  Grid,
  Alert,
  Switch,
  FormControlLabel,
  Divider,
  Checkbox,
  Chip,
  CircularProgress,
  Stack,
} from '@mui/material';
import SaveIcon from '@mui/icons-material/Save';
import AccountBalanceWalletIcon from '@mui/icons-material/AccountBalanceWallet';
import { useTranslation } from 'react-i18next';

import { useAuth } from '../../../hooks/useAuth';
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
  const { user, organizationId } = useAuth();
  const activeOrganizationId = organizationId || user?.organization_id || user?.default_organization_id || '';
  const [saving, setSaving] = useState(false);
  const [success, setSuccess] = useState(false);
  const [error, setError] = useState(null);
  const [applicantId, setApplicantId] = useState(null);
  const [profile, setProfile] = useState({
    name: userDisplayName(user),
    email: user?.email || '',
    phone: '',
  });
  const [notifications, setNotifications] = useState({
    emailAlerts: true,
    applicationUpdates: true,
    expirationReminders: true,
  });

  // Wallet preferences
  const { walletIds: preferredWallets, addWallet, removeWallet } = useWalletPreferences(user?.user_id);
  const [registryWallets, setRegistryWallets] = useState([]);
  const [walletsLoading, setWalletsLoading] = useState(true);
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

  // Load applicant profile on mount
  useEffect(() => {
    const loadProfile = async () => {
      if (user?.user_id) {
        try {
          let applicant = await getMyApplicantProfile(activeOrganizationId);

          // If no profile exists, create one
          if (!applicant) {
            const nameParts = userDisplayName(user).trim().split(/\s+/).filter(Boolean);
            const created = await upsertMyApplicantProfile({
              organization_id: activeOrganizationId,
              email: user.email || '',
              given_name: user.given_name || nameParts[0] || '',
              family_name: user.family_name || nameParts.slice(1).join(' ') || '',
            });
            applicant = created;
          }

          if (applicant) {
            setApplicantId(applicant.id);
            setProfile({
              name: applicant.full_name
                || [applicant.given_name, applicant.family_name].filter(Boolean).join(' ')
                || userDisplayName(user),
              email: applicant.email || user.email || '',
              phone: applicant.phone || '',
            });
          }
        } catch (err) {
          console.error('Error loading applicant profile:', err);
          setError(err.message || t('settings.errorNotFound'));
        }
      }
    };

    loadProfile();
  }, [user, activeOrganizationId, t]);

  // Load wallet registry
  useEffect(() => {
    const loadWallets = async () => {
      setWalletsLoading(true);
      try {
        const wallets = await listWallets(true);
        setRegistryWallets(Array.isArray(wallets) ? wallets : []);
      } catch (err) {
        console.error('Error loading wallet registry:', err);
      } finally {
        setWalletsLoading(false);
      }
    };

    loadWallets();
  }, []);

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
    setSaving(true);
    setError(null);
    setSuccess(false);

    try {
      if (!applicantId) {
        throw new Error(t('settings.errorNotFound'));
      }

      // Split name into given_name and family_name
      const nameParts = profile.name.trim().split(' ');
      const given_name = nameParts[0] || '';
      const family_name = nameParts.slice(1).join(' ') || '';

      await upsertMyApplicantProfile({
        organization_id: activeOrganizationId,
        given_name,
        family_name,
        phone: profile.phone,
      });

      setSuccess(true);
      setTimeout(() => setSuccess(false), 3000);
    } catch (err) {
      console.error('Error saving settings:', err);
      setError(err.message || 'Failed to save settings');
    } finally {
      setSaving(false);
    }
  };

  const handleProfileChange = (field) => (event) => {
    setProfile((prev) => ({ ...prev, [field]: event.target.value }));
  };

  const handleNotificationChange = (field) => (event) => {
    setNotifications((prev) => ({ ...prev, [field]: event.target.checked }));
  };

  return (
    <Box>
      <Typography variant="h4" gutterBottom>
        {t('settings.title')}
      </Typography>
      <Typography variant="body1" color="text.secondary" paragraph>
        {t('settings.description')}
      </Typography>

      {success && (
        <Alert severity="success" sx={{ mb: 3 }}>
          {t('settings.successMessage')}
        </Alert>
      )}

      {error && (
        <Alert severity="error" sx={{ mb: 3 }}>
          {error}
        </Alert>
      )}

      {/* Profile Settings */}
      <Paper sx={{ p: 3, mb: 3 }}>
        <Typography variant="h6" gutterBottom>
          {t('settings.profile.title')}
        </Typography>
        <Grid container spacing={3}>
          <Grid item xs={12} sm={6}>
            <TextField
              fullWidth
              label={t('settings.profile.fullName')}
              value={profile.name}
              onChange={handleProfileChange('name')}
            />
          </Grid>
          <Grid item xs={12} sm={6}>
            <TextField
              fullWidth
              label={t('settings.profile.email')}
              value={profile.email}
              onChange={handleProfileChange('email')}
              disabled
              helperText={t('settings.profile.emailHelp')}
            />
          </Grid>
          <Grid item xs={12} sm={6}>
            <TextField
              fullWidth
              label={t('settings.profile.phone')}
              value={profile.phone}
              onChange={handleProfileChange('phone')}
            />
          </Grid>
        </Grid>
      </Paper>

      {/* Notification Settings */}
      <Paper sx={{ p: 3, mb: 3 }}>
        <Typography variant="h6" gutterBottom>
          {t('settings.notifications.title')}
        </Typography>
        <FormControlLabel
          control={
            <Switch
              checked={notifications.emailAlerts}
              onChange={handleNotificationChange('emailAlerts')}
            />
          }
          label={t('settings.notifications.emailAlerts')}
        />
        <Typography variant="body2" color="text.secondary" paragraph sx={{ ml: 6 }}>
          {t('settings.notifications.emailAlertsDescription')}
        </Typography>

        <Divider sx={{ my: 2 }} />

        <FormControlLabel
          control={
            <Switch
              checked={notifications.applicationUpdates}
              onChange={handleNotificationChange('applicationUpdates')}
            />
          }
          label={t('settings.notifications.applicationUpdates')}
        />
        <Typography variant="body2" color="text.secondary" paragraph sx={{ ml: 6 }}>
          {t('settings.notifications.applicationUpdatesDescription')}
        </Typography>

        <Divider sx={{ my: 2 }} />

        <FormControlLabel
          control={
            <Switch
              checked={notifications.expirationReminders}
              onChange={handleNotificationChange('expirationReminders')}
            />
          }
          label={t('settings.notifications.expirationReminders')}
        />
        <Typography variant="body2" color="text.secondary" paragraph sx={{ ml: 6 }}>
          {t('settings.notifications.expirationRemindersDescription')}
        </Typography>
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
        ) : registryWallets.length === 0 ? (
          <Alert severity="info">No wallets are available in the registry yet.</Alert>
        ) : (
          <Stack spacing={1}>
            {registryWallets.map((w) => {
              const enabled = !walletSelectionAllowlist || walletSelectionAllowlist.has(w.id);
              const checked = preferredWallets.includes(w.id);
              return (
                <Box
                  key={w.id}
                  sx={{
                    display: 'flex',
                    alignItems: 'center',
                    p: 1.5,
                    borderRadius: 1,
                    border: 1,
                    borderColor: checked ? 'primary.main' : 'divider',
                    bgcolor: checked ? 'action.selected' : 'transparent',
                    cursor: enabled ? 'pointer' : 'not-allowed',
                    opacity: enabled ? 1 : 0.52,
                    '&:hover': enabled ? { bgcolor: 'action.hover' } : undefined,
                  }}
                  onClick={() => {
                    if (!enabled) return;
                    checked ? removeWallet(w.id) : addWallet(w.id);
                  }}
                >
                  <Checkbox checked={checked} disabled={!enabled} sx={{ mr: 1, p: 0 }} />
                  <Box sx={{ flex: 1 }}>
                    <Typography variant="subtitle2">{w.name}</Typography>
                    {w.description && (
                      <Typography variant="caption" color="text.secondary">
                        {w.description}
                      </Typography>
                    )}
                  </Box>
                  {!enabled && <Chip label="Unavailable" size="small" variant="outlined" sx={{ ml: 0.5 }} />}
                  {(w.supported_platforms || w.platforms || []).map((p) => (
                    <Chip key={p} label={p} size="small" variant="outlined" sx={{ ml: 0.5 }} />
                  ))}
                </Box>
              );
            })}
          </Stack>
        )}
      </Paper>

      <Button
        variant="contained"
        startIcon={<SaveIcon />}
        onClick={handleSave}
        disabled={saving}
      >
        {saving ? t('settings.actions.saving') : t('settings.actions.save')}
      </Button>
    </Box>
  );
}

export default ApplicantSettingsPage;

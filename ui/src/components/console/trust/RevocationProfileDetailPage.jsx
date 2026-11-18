/** Revocation profile details use the public HTTP timing and lifecycle contract. */
import { useCallback, useEffect, useRef, useState } from 'react';
import { useLocation, useParams, useNavigate, Link as RouterLink } from 'react-router';
import {
  Alert, Box, Breadcrumbs, Button, Chip, Divider, Grid, Link, List, ListItem,
  ListItemIcon, ListItemText, Paper, Skeleton, Tooltip, Typography,
} from '@mui/material';
import ArrowBackIcon from '@mui/icons-material/ArrowBack';
import BlockIcon from '@mui/icons-material/Block';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import ErrorOutlineIcon from '@mui/icons-material/ErrorOutlined';
import HelpOutlineIcon from '@mui/icons-material/HelpOutlined';
import LayersIcon from '@mui/icons-material/Layers';
import LinkIcon from '@mui/icons-material/Link';
import ScheduleIcon from '@mui/icons-material/Schedule';
import SecurityIcon from '@mui/icons-material/Security';
import WarningAmberIcon from '@mui/icons-material/WarningAmber';
import { useTranslation } from 'react-i18next';
import { useAsyncActionScope } from '../../../hooks/useAsyncActionScope';
import { useConsole } from '../../../contexts/ConsoleContext';
import { usePermissions } from '../../../hooks/usePermissions';
import { activateRevocationProfile, getRevocationProfile } from '../../../services/presentationPolicyApi';

// Public check_mode is a timing policy, not the internal HARD_FAIL/SOFT_FAIL/SKIP enum.
const CHECK_MODE_META = {
  ALWAYS: { key: 'always', color: 'success', icon: <CheckCircleIcon fontSize="small" /> },
  CACHED: { key: 'cached', color: 'info', icon: <CheckCircleIcon fontSize="small" /> },
  OFFLINE_GRACE: { key: 'offlineGrace', color: 'warning', icon: <WarningAmberIcon fontSize="small" /> },
  DISABLED: { key: 'disabled', color: 'error', icon: <BlockIcon fontSize="small" /> },
};
const UNKNOWN_CHECK_MODE = { key: 'unknown', color: 'default', icon: <HelpOutlineIcon fontSize="small" /> };
const STATUS_KEYS = { DRAFT: 'statusDraft', ACTIVE: 'statusActive', SUSPENDED: 'statusSuspended' };
const MECHANISM_KEYS = {
  STATUS_LIST_2021: 'statusList2021', BITSTRING_STATUS_LIST: 'bitstringStatusList',
  TOKEN_STATUS_LIST: 'tokenStatusList', OCSP: 'ocsp', CRL: 'crl',
};
function checkModeMeta(value) {
  return typeof value === 'string' && Object.hasOwn(CHECK_MODE_META, value) ? CHECK_MODE_META[value] : UNKNOWN_CHECK_MODE;
}
function profileMatches(profile, id, organizationId) {
  return profile?.id === id && profile?.organization_id === organizationId;
}
function scopeError(code) {
  const error = new Error(code);
  error.code = code;
  return error;
}
function CheckModePanel({ checkMode }) {
  const { t } = useTranslation('console');
  const meta = checkModeMeta(checkMode);
  return (
    <Paper sx={{ p: 3, mb: 3 }}>
      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 2 }}>
        <SecurityIcon color="primary" />
        <Typography variant="h6" sx={{ fontWeight: 600 }}>{t('trust.revocationDetail.checkModeTitle')}</Typography>
      </Box>
      <Box sx={{ mb: 2 }}>
        <Chip icon={meta.icon} label={t('trust.revocationDetail.checkModes.' + meta.key)} color={meta.color} />
      </Box>
      <Typography variant="body2" color="text.secondary">
        {t('trust.revocationDetail.checkModes.' + meta.key + 'Description')}
      </Typography>
    </Paper>
  );
}

function MechanismsPanel({ mechanisms, statusListUrl }) {
  const { t } = useTranslation('console');
  const nativeMechanisms = Array.isArray(mechanisms) ? mechanisms : [];
  return (
    <Paper sx={{ p: 3, mb: 3 }}>
      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 2 }}>
        <LayersIcon color="primary" />
        <Typography variant="h6" sx={{ fontWeight: 600 }}>{t('trust.revocationDetail.mechanismsTitle')}</Typography>
      </Box>
      {nativeMechanisms.length === 0 ? (
        <Typography variant="body2" color="text.secondary">{t('trust.revocationDetail.noMechanisms')}</Typography>
      ) : (
        <List disablePadding>
          {nativeMechanisms.map((mechanism, index) => {
            const known = typeof mechanism === 'string' && Object.hasOwn(MECHANISM_KEYS, mechanism);
            return (
              <ListItem key={index} disableGutters sx={{ pb: 0.5 }}>
                <ListItemIcon sx={{ minWidth: 36 }}><SecurityIcon color="action" fontSize="small" /></ListItemIcon>
                <ListItemText
                  primary={known ? t('trust.revocationDetail.mechanisms.' + MECHANISM_KEYS[mechanism])
                    : typeof mechanism === 'string' ? mechanism : t('trust.revocationDetail.mechanisms.unknown')}
                  secondary={known ? undefined : t('trust.revocationDetail.mechanisms.unknown')}
                />
              </ListItem>
            );
          })}
        </List>
      )}
      {typeof statusListUrl === 'string' && statusListUrl && (
        <>
          <Divider sx={{ my: 2 }} />
          <Box sx={{ display: 'flex', alignItems: 'flex-start', gap: 1 }}>
            <LinkIcon color="action" fontSize="small" sx={{ mt: 0.3 }} />
            <Box>
              <Typography variant="subtitle2" gutterBottom>{t('trust.revocationDetail.statusListUrl')}</Typography>
              <Tooltip title={statusListUrl}>
                <Typography variant="body2" sx={{ fontFamily: 'monospace', fontSize: '0.75rem', color: 'text.secondary', wordBreak: 'break-all' }}>
                  {statusListUrl}
                </Typography>
              </Tooltip>
            </Box>
          </Box>
        </>
      )}
    </Paper>
  );
}

function MetadataPanel({ profile }) {
  const { t } = useTranslation('console');
  const date = (value) => {
    const parsed = value ? new Date(value) : null;
    return parsed && Number.isFinite(parsed.getTime()) ? parsed.toLocaleString() : t('trust.revocationDetail.notAvailable');
  };
  const rows = [
    { key: 'profileId', value: profile.id, mono: true },
    { key: 'organization', value: profile.organization_id, mono: true },
    { key: 'created', value: date(profile.created_at) },
    { key: 'updated', value: date(profile.updated_at) },
  ];
  // HTTP emits these fields only for their corresponding timing mode.
  if (profile.check_mode === 'OFFLINE_GRACE' && Number.isInteger(profile.offline_grace_seconds) && profile.offline_grace_seconds >= 0) {
    rows.push({ key: 'offlineGrace', value: String(profile.offline_grace_seconds) + 's' });
  }
  if (profile.check_mode === 'CACHED' && Number.isInteger(profile.cache_ttl_seconds) && profile.cache_ttl_seconds >= 0) {
    rows.push({ key: 'cacheTtl', value: String(profile.cache_ttl_seconds) + 's' });
  }
  return (
    <Paper sx={{ p: 3, mb: 3 }}>
      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 2 }}>
        <ScheduleIcon color="primary" />
        <Typography variant="h6" sx={{ fontWeight: 600 }}>{t('trust.revocationDetail.metadataTitle')}</Typography>
      </Box>
      <Grid container spacing={2}>
        {rows.map(({ key, value, mono }) => (
          <Grid size={{ xs: 12, sm: 6 }} key={key}>
            <Typography variant="body2" color="text.secondary" gutterBottom>{t('trust.revocationDetail.' + key)}</Typography>
            <Typography variant="body2" sx={[{ fontWeight: 500 }, mono && { fontFamily: 'monospace', fontSize: '0.75rem', wordBreak: 'break-all' }]}>
              {value}
            </Typography>
          </Grid>
        ))}
      </Grid>
    </Paper>
  );
}

function RevocationProfileDetailContent({ id, organizationId, canActivate }) {
  const { t } = useTranslation('console');
  const navigate = useNavigate();
  const beginAction = useAsyncActionScope();
  const busy = useRef(false);
  // BrowserRouter changes history before committing its React transition.
  const browserEntry = useRef(typeof window === 'undefined' ? null : {
    href: window.location.href, key: window.history.state?.key,
  });
  const isCurrentView = useCallback(() => !browserEntry.current || (
    typeof window !== 'undefined' && window.location.href === browserEntry.current.href
      && window.history.state?.key === browserEntry.current.key
  ), []);
  const [profile, setProfile] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [activating, setActivating] = useState(false);
  const [actionError, setActionError] = useState(null);

  const reload = useCallback(async () => {
    const action = beginAction();
    const isCurrent = () => action.isCurrent() && isCurrentView();
    if (!isCurrent()) return;
    busy.current = false;
    setProfile(null); setError(null); setLoading(true);
    setActivating(false); setActionError(null);
    try {
      const result = await action.run(getRevocationProfile, id);
      if (!isCurrent()) return;
      if (!profileMatches(result, id, organizationId)) throw scopeError('PROFILE_SCOPE_MISMATCH');
      setProfile(result);
    } catch (reason) {
      if (isCurrent()) setError(reason || new Error());
    } finally {
      if (isCurrent()) setLoading(false);
    }
  }, [beginAction, id, organizationId, isCurrentView]);
  useEffect(() => { reload(); }, [reload]);

  const handleActivate = async () => {
    if (busy.current || !canActivate || !isCurrentView() || !profileMatches(profile, id, organizationId)
      || (profile.status !== 'DRAFT' && profile.status !== 'SUSPENDED')) return;
    const action = beginAction();
    const isCurrent = () => action.isCurrent() && isCurrentView();
    if (!isCurrent()) return;
    busy.current = true;
    setActivating(true); setActionError(null);
    try {
      const activated = await action.run(activateRevocationProfile, id);
      if (!isCurrent()) return;
      if (!profileMatches(activated, id, organizationId) || activated.status !== 'ACTIVE') {
        throw scopeError('ACTIVATION_SCOPE_MISMATCH');
      }
      // The native activation returns the complete postimage. A dispatched write
      // may finish after navigation; it is never rolled back or followed by a stale read.
      setProfile(activated);
    } catch (reason) {
      if (isCurrent()) setActionError(reason || new Error());
    } finally {
      if (isCurrent()) { busy.current = false; setActivating(false); }
    }
  };
  const back = () => { if (isCurrentView()) navigate('/console/org/trust/revocation'); };
  const backButton = <Button variant="outlined" startIcon={<ArrowBackIcon />} onClick={back}>
    {t('trust.revocationDetail.backToList')}
  </Button>;

  if (loading) return <Box sx={{ py: 2 }}>
    <Skeleton variant="text" width={340} height={40} sx={{ mb: 1 }} />
    <Skeleton variant="rectangular" height={120} sx={{ mb: 2 }} />
    <Skeleton variant="rectangular" height={200} />
  </Box>;
  if (error || !profile) return <Box sx={{ py: 4 }}>
    <Alert severity="error">{error?.code === 'PROFILE_SCOPE_MISMATCH'
      ? t('trust.revocationDetail.profileScopeMismatch') : error?.message || t('trust.revocationDetail.loadFailed')}</Alert>
    <Box sx={{ display: 'flex', gap: 2, mt: 2 }}>
      <Button onClick={reload}>{t('trust.revocationDetail.retryProfile')}</Button>{backButton}
    </Box>
  </Box>;

  const mode = checkModeMeta(profile.check_mode);
  const statusKey = typeof profile.status === 'string' && Object.hasOwn(STATUS_KEYS, profile.status)
    ? STATUS_KEYS[profile.status] : 'statusUnknown';
  return (
    <Box>
      <Breadcrumbs sx={{ mb: 2 }}>
        <Link component={RouterLink} to="/console" underline="hover" color="inherit">{t('trust.breadcrumbs.console')}</Link>
        <Link component={RouterLink} to="/console/org/trust" underline="hover" color="inherit">{t('trust.breadcrumbs.trust')}</Link>
        <Link component={RouterLink} to="/console/org/trust/revocation" underline="hover" color="inherit">{t('trust.breadcrumbs.revocationProfiles')}</Link>
        <Typography color="text.primary">{profile.name}</Typography>
      </Breadcrumbs>
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', mb: 3 }}>
        <Box>
          <Typography variant="h4" component="h1" gutterBottom>{profile.name}</Typography>
          <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
            <Chip label={t('trust.revocationDetail.' + statusKey)} color={profile.status === 'ACTIVE' ? 'success' : 'default'} size="small" />
            <Chip icon={<SecurityIcon />} label={t('trust.revocationDetail.checkModes.' + mode.key)} color={mode.color} size="small" />
          </Box>
        </Box>
        <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap', justifyContent: 'flex-end' }}>
          {canActivate && (profile.status === 'DRAFT' || profile.status === 'SUSPENDED') && (
            <Button variant="contained" startIcon={<CheckCircleIcon />} onClick={handleActivate} disabled={activating}>
              {t('trust.revocationDetail.' + (activating ? 'activating' : 'activate'))}
            </Button>
          )}
          {backButton}
        </Box>
      </Box>
      {actionError && <Alert severity="error" sx={{ mb: 3 }}>
        {actionError.code === 'ACTIVATION_SCOPE_MISMATCH' ? t('trust.revocationDetail.activationScopeMismatch')
          : actionError.message || t('trust.revocationDetail.activationFailed')}
      </Alert>}
      {profile.check_mode === 'DISABLED' && <Alert severity="warning" icon={<ErrorOutlineIcon />} sx={{ mb: 3 }}>
        {t('trust.revocationDetail.disabledAdvisory')}
      </Alert>}
      <CheckModePanel checkMode={profile.check_mode} />
      <MechanismsPanel mechanisms={profile.revocation_mechanism} statusListUrl={profile.status_list_url} />
      <MetadataPanel profile={profile} />
      <Box sx={{ display: 'flex', gap: 2 }}>{backButton}</Box>
    </Box>
  );
}

export default function RevocationProfileDetailPage() {
  const { t } = useTranslation('console');
  const { id } = useParams();
  const location = useLocation();
  const { activeOrgId } = useConsole();
  const { can, isLoading } = usePermissions();
  const canView = can('revocation-profile', 'view');
  const canActivate = can('revocation-profile', 'activate');
  if (isLoading) return <Skeleton variant="rectangular" height={400} />;
  if (typeof activeOrgId !== 'string' || !activeOrgId.trim()) return <Alert severity="info">{t('trust.revocationDetail.selectOrganization')}</Alert>;
  if (!canView) return <Alert severity="info">{t('trust.revocationDetail.readDenied')}</Alert>;
  if (typeof id !== 'string' || !id.trim()) return <Alert severity="error">{t('trust.revocationDetail.profileScopeMismatch')}</Alert>;
  const key = JSON.stringify([activeOrgId, id, location.key, location.pathname, location.search, location.hash, canView, canActivate]);
  return <RevocationProfileDetailContent key={key} id={id} organizationId={activeOrgId} canActivate={canActivate} />;
}

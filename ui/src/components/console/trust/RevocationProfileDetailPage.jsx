/**
 * Revocation Profile Detail Page
 *
 * Shows comprehensive details of a revocation profile including:
 * - Check mode and its policy implications
 * - Supported revocation mechanisms
 * - Status list endpoint configuration
 * - Grace period and soft-fail settings
 * - Timestamps and basic metadata
 */

import { useParams, useNavigate, Link as RouterLink } from 'react-router-dom';
import {
  Alert,
  Box,
  Breadcrumbs,
  Button,
  Chip,
  Divider,
  Grid,
  Link,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  Paper,
  Skeleton,
  Tooltip,
  Typography,
} from '@mui/material';
import ArrowBackIcon from '@mui/icons-material/ArrowBack';
import BlockIcon from '@mui/icons-material/Block';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import ErrorOutlineIcon from '@mui/icons-material/ErrorOutline';
import HelpOutlineIcon from '@mui/icons-material/HelpOutline';
import LayersIcon from '@mui/icons-material/Layers';
import LinkIcon from '@mui/icons-material/Link';
import ScheduleIcon from '@mui/icons-material/Schedule';
import SecurityIcon from '@mui/icons-material/Security';
import WarningAmberIcon from '@mui/icons-material/WarningAmber';
import { useTranslation } from 'react-i18next';

import { useAsyncData } from '../../../hooks/useAsyncData';
import { getRevocationProfile } from '../../../services/presentationPolicyApi';

// ─── Check Mode Meta ──────────────────────────────────────────────────────────

const CHECK_MODE_META = {
  HARD_FAIL: {
    color: 'success',
    icon: <BlockIcon fontSize="small" />,
    labelKey: 'trust.revocationDetail.checkModes.hardFail',
    descriptionKey: 'trust.revocationDetail.checkModes.hardFailDescription',
  },
  SOFT_FAIL: {
    color: 'warning',
    icon: <WarningAmberIcon fontSize="small" />,
    labelKey: 'trust.revocationDetail.checkModes.softFail',
    descriptionKey: 'trust.revocationDetail.checkModes.softFailDescription',
  },
  CACHED: {
    color: 'info',
    icon: <CheckCircleIcon fontSize="small" />,
    labelKey: 'trust.revocationDetail.checkModes.cached',
    descriptionKey: 'trust.revocationDetail.checkModes.cachedDescription',
  },
  SKIP: {
    color: 'default',
    icon: <HelpOutlineIcon fontSize="small" />,
    labelKey: 'trust.revocationDetail.checkModes.skip',
    descriptionKey: 'trust.revocationDetail.checkModes.skipDescription',
  },
};

function CheckModePanel({ checkMode }) {
  const { t } = useTranslation('console');
  const normalised = String(checkMode || 'HARD_FAIL').toUpperCase();
  const meta = CHECK_MODE_META[normalised] ?? CHECK_MODE_META.HARD_FAIL;

  return (
    <Paper sx={{ p: 3, mb: 3 }}>
      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 2 }}>
        <SecurityIcon color="primary" />
        <Typography variant="h6" fontWeight={600}>
          {t('trust.revocationDetail.checkModeTitle', 'Revocation Check Policy')}
        </Typography>
      </Box>

      <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, mb: 2 }}>
        <Chip
          icon={meta.icon}
          label={t(meta.labelKey, normalised.replace('_', ' '))}
          color={meta.color}
          variant="filled"
        />
      </Box>

      <Typography variant="body2" color="text.secondary">
        {t(meta.descriptionKey, {
          HARD_FAIL: 'Verification is rejected if the revocation check cannot be completed. Provides the strongest integrity guarantee.',
          SOFT_FAIL: 'Verification proceeds even when the revocation endpoint is unreachable. Reduces availability friction at the cost of weaker guarantees.',
          CACHED: 'Uses a locally cached revocation result if the endpoint is unavailable. Balances availability and integrity.',
          SKIP: 'Revocation checking is disabled. Use only in controlled or offline-first environments.',
        }[normalised] ?? '')}
      </Typography>
    </Paper>
  );
}

// ─── Mechanisms Panel ─────────────────────────────────────────────────────────

const MECHANISM_META = {
  StatusList2021: { icon: '🔗', description: 'W3C Status List 2021 – bit-indexed compact revocation list.' },
  BitstringStatusList: { icon: '🔢', description: 'W3C Bitstring Status List – successor to Status List 2021.' },
  OCSP: { icon: '🌐', description: 'Online Certificate Status Protocol – real-time X.509 certificate status.' },
  CRL: { icon: '📋', description: 'Certificate Revocation List – batch-published X.509 revocation.' },
  StatusList2021Revocation: { icon: '🔗', description: 'Status List 2021 Revocation entry type.' },
  StatusList2021Suspension: { icon: '⏸️', description: 'Status List 2021 Suspension entry type.' },
};

function MechanismsPanel({ mechanisms, statusListUrl }) {
  const { t } = useTranslation('console');
  const safeMechanisms = Array.isArray(mechanisms) ? mechanisms : [];

  return (
    <Paper sx={{ p: 3, mb: 3 }}>
      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 2 }}>
        <LayersIcon color="primary" />
        <Typography variant="h6" fontWeight={600}>
          {t('trust.revocationDetail.mechanismsTitle', 'Revocation Mechanisms')}
        </Typography>
      </Box>

      {safeMechanisms.length === 0 ? (
        <Typography variant="body2" color="text.secondary">
          {t('trust.revocationDetail.noMechanisms', 'No revocation mechanisms configured.')}
        </Typography>
      ) : (
        <List disablePadding>
          {safeMechanisms.map((mechanism) => {
            const meta = MECHANISM_META[mechanism];
            return (
              <ListItem key={mechanism} disableGutters sx={{ pb: 0.5 }}>
                <ListItemIcon sx={{ minWidth: 36 }}>
                  <Typography>{meta?.icon ?? '🔒'}</Typography>
                </ListItemIcon>
                <ListItemText
                  primary={
                    <Typography variant="body2" fontWeight={500}>
                      {mechanism}
                    </Typography>
                  }
                  secondary={
                    <Typography variant="caption" color="text.secondary">
                      {meta?.description ?? t('trust.revocationDetail.mechanism', 'Revocation mechanism')}
                    </Typography>
                  }
                />
              </ListItem>
            );
          })}
        </List>
      )}

      {statusListUrl && (
        <>
          <Divider sx={{ my: 2 }} />
          <Box sx={{ display: 'flex', alignItems: 'flex-start', gap: 1 }}>
            <LinkIcon color="action" fontSize="small" sx={{ mt: 0.3 }} />
            <Box>
              <Typography variant="subtitle2" gutterBottom>
                {t('trust.revocationDetail.statusListUrl', 'Status List Endpoint')}
              </Typography>
              <Tooltip title={statusListUrl}>
                <Typography
                  variant="body2"
                  sx={{
                    fontFamily: 'monospace',
                    fontSize: '0.75rem',
                    color: 'text.secondary',
                    wordBreak: 'break-all',
                  }}
                >
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

// ─── Metadata Panel ───────────────────────────────────────────────────────────

function MetadataPanel({ profile }) {
  const { t } = useTranslation('console');

  const rows = [
    {
      label: t('trust.revocationDetail.profileId', 'Profile ID'),
      value: profile.id,
      mono: true,
    },
    {
      label: t('trust.revocationDetail.organization', 'Organization'),
      value: profile.organization_id ?? '—',
      mono: true,
    },
    {
      label: t('trust.revocationDetail.created', 'Created'),
      value: profile.created_at ? new Date(profile.created_at).toLocaleString() : '—',
    },
    {
      label: t('trust.revocationDetail.updated', 'Last Updated'),
      value: profile.updated_at ? new Date(profile.updated_at).toLocaleString() : '—',
    },
  ];

  if (profile.grace_period_seconds != null) {
    rows.push({
      label: t('trust.revocationDetail.gracePeriod', 'Grace Period'),
      value: `${profile.grace_period_seconds}s`,
    });
  }

  if (profile.cache_ttl_seconds != null) {
    rows.push({
      label: t('trust.revocationDetail.cacheTtl', 'Cache TTL'),
      value: `${profile.cache_ttl_seconds}s`,
    });
  }

  return (
    <Paper sx={{ p: 3, mb: 3 }}>
      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 2 }}>
        <ScheduleIcon color="primary" />
        <Typography variant="h6" fontWeight={600}>
          {t('trust.revocationDetail.metadataTitle', 'Profile Metadata')}
        </Typography>
      </Box>

      <Grid container spacing={2}>
        {rows.map(({ label, value, mono }) => (
          <Grid item xs={12} sm={6} key={label}>
            <Typography variant="body2" color="text.secondary" gutterBottom>
              {label}
            </Typography>
            <Typography
              variant="body2"
              fontWeight={500}
              sx={mono ? { fontFamily: 'monospace', fontSize: '0.75rem', wordBreak: 'break-all' } : undefined}
            >
              {value}
            </Typography>
          </Grid>
        ))}

        {profile.description && (
          <Grid item xs={12}>
            <Divider sx={{ my: 1 }} />
            <Typography variant="body2" color="text.secondary" gutterBottom>
              {t('trust.revocationDetail.description', 'Description')}
            </Typography>
            <Typography variant="body2">{profile.description}</Typography>
          </Grid>
        )}
      </Grid>
    </Paper>
  );
}

// ─── Soft-fail Advisory ───────────────────────────────────────────────────────

function SoftFailAdvisory({ checkMode }) {
  const { t } = useTranslation('console');
  const normalised = String(checkMode || '').toUpperCase();
  if (normalised !== 'SOFT_FAIL' && normalised !== 'SKIP') return null;

  return (
    <Alert
      severity="warning"
      icon={<ErrorOutlineIcon />}
      sx={{ mb: 3 }}
    >
      {normalised === 'SKIP'
        ? t(
            'trust.revocationDetail.skipAdvisory',
            'Revocation checking is disabled for this profile. Credentials verified under this profile are not checked for revocation status. Only use this mode in offline or test environments.',
          )
        : t(
            'trust.revocationDetail.softFailAdvisory',
            "Soft-fail mode means verifications will succeed even when the revocation endpoint is unreachable. Ensure this aligns with your organisation's risk tolerance.",
          )}
    </Alert>
  );
}

// ─── Page ─────────────────────────────────────────────────────────────────────

function RevocationProfileDetailPage() {
  const { t } = useTranslation('console');
  const { id } = useParams();
  const navigate = useNavigate();

  const { data: profile, loading, error } = useAsyncData(
    () => (id ? getRevocationProfile(id) : Promise.resolve(null)),
    [id],
  );

  if (loading) {
    return (
      <Box sx={{ py: 2 }}>
        <Skeleton variant="text" width={340} height={40} sx={{ mb: 1 }} />
        <Skeleton variant="rectangular" height={120} sx={{ mb: 2 }} />
        <Skeleton variant="rectangular" height={200} sx={{ mb: 2 }} />
        <Skeleton variant="rectangular" height={160} />
      </Box>
    );
  }

  if (error || !profile) {
    return (
      <Box sx={{ py: 4 }}>
        <Alert severity="error">
          {error?.message ?? t('trust.revocationDetail.notFound', 'Revocation profile not found.')}
        </Alert>
        <Button
          startIcon={<ArrowBackIcon />}
          onClick={() => navigate('/console/org/trust/revocation')}
          sx={{ mt: 2 }}
        >
          {t('trust.revocationDetail.backToList', 'Back to Revocation Profiles')}
        </Button>
      </Box>
    );
  }

  return (
    <Box>
      {/* Breadcrumbs */}
      <Breadcrumbs sx={{ mb: 2 }}>
        <Link component={RouterLink} to="/console" underline="hover" color="inherit">
          {t('trust.breadcrumbs.console', 'Console')}
        </Link>
        <Link component={RouterLink} to="/console/org/trust" underline="hover" color="inherit">
          {t('trust.breadcrumbs.trust', 'Trust')}
        </Link>
        <Link
          component={RouterLink}
          to="/console/org/trust/revocation"
          underline="hover"
          color="inherit"
        >
          {t('trust.breadcrumbs.revocationProfiles', 'Revocation Profiles')}
        </Link>
        <Typography color="text.primary">{profile.name}</Typography>
      </Breadcrumbs>

      {/* Header */}
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', mb: 3 }}>
        <Box>
          <Typography variant="h4" component="h1" gutterBottom>
            {profile.name}
          </Typography>
          <Chip
            icon={<SecurityIcon />}
            label={
              String(profile.check_mode || 'HARD_FAIL')
                .replace('_', ' ')
                .toLowerCase()
                .replace(/^\w/, (c) => c.toUpperCase())
            }
            color={CHECK_MODE_META[String(profile.check_mode || 'HARD_FAIL').toUpperCase()]?.color ?? 'default'}
            size="small"
          />
        </Box>
        <Button
          variant="outlined"
          startIcon={<ArrowBackIcon />}
          onClick={() => navigate('/console/org/trust/revocation')}
        >
          {t('trust.revocationDetail.backToList', 'Back to Revocation Profiles')}
        </Button>
      </Box>

      {/* Soft-fail / skip advisory */}
      <SoftFailAdvisory checkMode={profile.check_mode} />

      {/* Check Mode */}
      <CheckModePanel checkMode={profile.check_mode} />

      {/* Mechanisms + Status List URL */}
      <MechanismsPanel
        mechanisms={profile.revocation_mechanism ?? profile.mechanisms ?? []}
        statusListUrl={profile.status_list_url ?? profile.status_list_endpoint}
      />

      {/* Metadata */}
      <MetadataPanel profile={profile} />

      {/* Footer nav */}
      <Box sx={{ display: 'flex', gap: 2 }}>
        <Button
          variant="outlined"
          startIcon={<ArrowBackIcon />}
          onClick={() => navigate('/console/org/trust/revocation')}
        >
          {t('trust.revocationDetail.backToList', 'Back to Revocation Profiles')}
        </Button>
      </Box>
    </Box>
  );
}

export default RevocationProfileDetailPage;

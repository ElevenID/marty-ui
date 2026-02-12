/**
 * Trust Profile Detail Page
 * 
 * Shows comprehensive details of a trust profile including:
 * - Basic information
 * - Trust anchors and provenance
 * - Wallet compatibility
 * - Revocation strategy
 */

import { useState, useEffect } from 'react';
import { useParams, useNavigate, Link as RouterLink } from 'react-router-dom';
import {
  Box,
  Paper,
  Typography,
  Grid,
  Chip,
  Button,
  Breadcrumbs,
  Link,
  Divider,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  Skeleton,
  Alert,
} from '@mui/material';
import ArrowBackIcon from '@mui/icons-material/ArrowBack';
import EditIcon from '@mui/icons-material/Edit';
import VerifiedUserIcon from '@mui/icons-material/VerifiedUser';
import AccountBalanceIcon from '@mui/icons-material/AccountBalance';
import PhoneAndroidIcon from '@mui/icons-material/PhoneAndroid';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import SecurityIcon from '@mui/icons-material/Security';
import { useTranslation } from 'react-i18next';

import { getTrustProfile, getTrustProfileWalletCompatibility } from '../../../services/presentationPolicyApi';

/**
 * Format badge icons for supported formats
 */
const FORMAT_ICONS = {
  'SD-JWT': '🔐',
  'mDL': '🪪',
  'W3C VC': '✓',
  'OBv3': '🎓',
  'VC-JWT': '🔑',
};

/**
 * Wallet Compatibility Panel Component
 */
function WalletCompatibilityPanel({ trustProfileId }) {
  const { t } = useTranslation('console');
  const [compatibility, setCompatibility] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function fetchCompatibility() {
      try {
        const data = await getTrustProfileWalletCompatibility(trustProfileId);
        setCompatibility(data);
      } catch (error) {
        console.error('Failed to load wallet compatibility:', error);
        // Set default empty state
        setCompatibility({ supported_formats: [], supported_wallets: [] });
      } finally {
        setLoading(false);
      }
    }

    if (trustProfileId) {
      fetchCompatibility();
    }
  }, [trustProfileId]);

  if (loading) {
    return <Skeleton variant="rectangular" height={200} />;
  }

  const formats = compatibility?.supported_formats || [];
  const wallets = compatibility?.supported_wallets || [];

  return (
    <Paper sx={{ p: 3, mb: 3 }}>
      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 2 }}>
        <PhoneAndroidIcon color="primary" />
        <Typography variant="h6" fontWeight={600}>
          {t('trust.trustProfileDetail.walletCompatibility')}
        </Typography>
      </Box>

      {/* Supported Formats */}
      <Box sx={{ mb: 3 }}>
        <Typography variant="subtitle2" gutterBottom>
          {t('trust.trustProfileDetail.supportedCredentialFormats')}
        </Typography>
        <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap', mt: 1 }}>
          {formats.length > 0 ? (
            formats.map((format) => (
              <Chip
                key={format}
                label={`${FORMAT_ICONS[format] || '📄'} ${format}`}
                color="primary"
                variant="outlined"
              />
            ))
          ) : (
            <Typography variant="body2" color="text.secondary">
              {t('trust.trustProfileDetail.noFormatsConfigured')}
            </Typography>
          )}
        </Box>
      </Box>

      {/* Supported Wallets */}
      <Box>
        <Typography variant="subtitle2" gutterBottom>
          {t('trust.trustProfileDetail.compatibleWalletApplications')}
        </Typography>
        {wallets.length > 0 ? (
          <List dense>
            {wallets.map((wallet, index) => (
              <ListItem key={index}>
                <ListItemIcon>
                  <CheckCircleIcon color="success" fontSize="small" />
                </ListItemIcon>
                <ListItemText
                  primary={wallet.name || wallet}
                  secondary={wallet.description || t('trust.trustProfileDetail.compatibleWallet')}
                />
              </ListItem>
            ))}
          </List>
        ) : (
          <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
            {t('trust.trustProfileDetail.standardCompliantWallets')}
          </Typography>
        )}
      </Box>
    </Paper>
  );
}

/**
 * Trust Profile Provenance Section
 */
function ProvenanceSection({ trustProfile }) {
  const { t } = useTranslation('console');
  const trustAnchors = trustProfile?.trust_anchors || [];
  const revocationStrategy = trustProfile?.revocation_strategy || 'dynamic';
  const issuerCount = trustAnchors.length;

  return (
    <Paper sx={{ p: 3, mb: 3 }}>
      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 2 }}>
        <AccountBalanceIcon color="primary" />
        <Typography variant="h6" fontWeight={600}>
          {t('trust.trustProfileDetail.trustProvenance')}
        </Typography>
      </Box>

      <Grid container spacing={3}>
        {/* Trust Anchors */}
        <Grid item xs={12} md={6}>
          <Typography variant="subtitle2" gutterBottom>
            {t('trust.trustProfileDetail.trustAnchors')}
          </Typography>
          {trustAnchors.length > 0 ? (
            <List dense>
              {trustAnchors.map((anchor, index) => (
                <ListItem key={index}>
                  <ListItemIcon>
                    <VerifiedUserIcon color="primary" fontSize="small" />
                  </ListItemIcon>
                  <ListItemText
                    primary={anchor.name || anchor.authority || t('trust.trustProfileDetail.anchor', { number: index + 1 })}
                    secondary={anchor.type || t('trust.trustProfileDetail.trustAuthority')}
                  />
                </ListItem>
              ))}
            </List>
          ) : (
            <Typography variant="body2" color="text.secondary">
              {t('trust.trustProfileDetail.noTrustAnchors')}
            </Typography>
          )}
        </Grid>

        {/* Metadata */}
        <Grid item xs={12} md={6}>
          <Typography variant="subtitle2" gutterBottom>
            {t('trust.trustProfileDetail.trustMetadata')}
          </Typography>
          <Box sx={{ mt: 1 }}>
            <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 1 }}>
              <Typography variant="body2" color="text.secondary">
                {t('trust.trustProfileDetail.trustedIssuersCount')}
              </Typography>
              <Typography variant="body2" fontWeight={600}>
                {issuerCount}
              </Typography>
            </Box>
            <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 1 }}>
              <Typography variant="body2" color="text.secondary">
                {t('trust.trustProfileDetail.revocationStrategy')}
              </Typography>
              <Chip
                label={revocationStrategy}
                size="small"
                color={revocationStrategy === 'dynamic' ? 'success' : 'default'}
              />
            </Box>
          </Box>
        </Grid>
      </Grid>

      {trustProfile?.description && (
        <>
          <Divider sx={{ my: 2 }} />
          <Typography variant="subtitle2" gutterBottom>
            {t('trust.trustProfileDetail.trustPolicyDescription')}
          </Typography>
          <Typography variant="body2" color="text.secondary">
            {trustProfile.description}
          </Typography>
        </>
      )}
    </Paper>
  );
}

/**
 * Trust Profile Detail Page Component
 */
export function TrustProfileDetailPage() {
  const { t } = useTranslation('console');
  const { id } = useParams();
  const navigate = useNavigate();
  const [profile, setProfile] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    async function fetchProfile() {
      try {
        setLoading(true);
        const data = await getTrustProfile(id);
        setProfile(data);
      } catch (err) {
        console.error('Failed to load trust profile:', err);
        setError(t('trust.trustProfileDetail.failedToLoad'));
      } finally {
        setLoading(false);
      }
    }

    if (id) {
      fetchProfile();
    }
  }, [id]);

  if (loading) {
    return (
      <Box sx={{ py: 4 }}>
        <Skeleton variant="text" width={300} height={40} />
        <Skeleton variant="rectangular" height={400} sx={{ mt: 2 }} />
      </Box>
    );
  }

  if (error || !profile) {
    return (
      <Box sx={{ py: 4 }}>
        <Alert severity="error">{error || t('trust.trustProfileDetail.notFound')}</Alert>
        <Button
          startIcon={<ArrowBackIcon />}
          onClick={() => navigate('/console/trust/profiles')}
          sx={{ mt: 2 }}
        >
          {t('trust.trustProfileDetail.backToProfiles')}
        </Button>
      </Box>
    );
  }

  return (
    <Box>
      {/* Breadcrumbs */}
      <Breadcrumbs sx={{ mb: 2 }}>
        <Link component={RouterLink} to="/console" underline="hover" color="inherit">
          {t('trust.breadcrumbs.console')}
        </Link>
        <Link component={RouterLink} to="/console/trust" underline="hover" color="inherit">
          {t('trust.breadcrumbs.trust')}
        </Link>
        <Link component={RouterLink} to="/console/trust/profiles" underline="hover" color="inherit">
          {t('trust.breadcrumbs.trustProfiles')}
        </Link>
        <Typography color="text.primary">{profile.name}</Typography>
      </Breadcrumbs>

      {/* Header */}
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', mb: 3 }}>
        <Box>
          <Typography variant="h4" component="h1" gutterBottom>
            {profile.name}
          </Typography>
          <Box sx={{ display: 'flex', gap: 1, alignItems: 'center' }}>
            <Chip
              icon={<SecurityIcon />}
              label={profile.status || 'Active'}
              color={profile.status === 'active' ? 'success' : 'default'}
              size="small"
            />
            {profile.is_default && (
              <Chip label={t('trust.trustProfileDetail.default')} color="primary" size="small" variant="outlined" />
            )}
          </Box>
        </Box>
        <Button
          variant="outlined"
          startIcon={<EditIcon />}
          onClick={() => navigate(`/console/trust/profiles/${id}/edit`)}
        >
          {t('actions.edit', { ns: 'common' })}
        </Button>
      </Box>

      {/* Basic Information */}
      <Paper sx={{ p: 3, mb: 3 }}>
        <Typography variant="h6" fontWeight={600} gutterBottom>
          {t('trust.trustProfileDetail.basicInformation')}
        </Typography>
        <Grid container spacing={2}>
          <Grid item xs={12} sm={6}>
            <Typography variant="body2" color="text.secondary">
              {t('trust.trustProfileDetail.profileId')}
            </Typography>
            <Typography variant="body1" fontWeight={500}>
              {profile.id}
            </Typography>
          </Grid>
          <Grid item xs={12} sm={6}>
            <Typography variant="body2" color="text.secondary">
              {t('trust.trustProfileDetail.created')}
            </Typography>
            <Typography variant="body1" fontWeight={500}>
              {profile.created_at ? new Date(profile.created_at).toLocaleDateString() : t('trust.trustProfileDetail.notAvailable')}
            </Typography>
          </Grid>
          {profile.description && (
            <Grid item xs={12}>
              <Typography variant="body2" color="text.secondary">
                {t('trust.trustProfileDetail.description')}
              </Typography>
              <Typography variant="body1">
                {profile.description}
              </Typography>
            </Grid>
          )}
        </Grid>
      </Paper>

      {/* Trust Provenance */}
      <ProvenanceSection trustProfile={profile} />

      {/* Wallet Compatibility */}
      <WalletCompatibilityPanel trustProfileId={id} />

      {/* Actions */}
      <Box sx={{ display: 'flex', gap: 2 }}>
        <Button
          variant="outlined"
          startIcon={<ArrowBackIcon />}
          onClick={() => navigate('/console/trust/profiles')}
        >
          {t('trust.trustProfileDetail.backToProfiles')}
        </Button>
      </Box>
    </Box>
  );
}

export default TrustProfileDetailPage;

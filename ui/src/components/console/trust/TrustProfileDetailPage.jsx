/**
 * Trust Profile Detail Page
 * 
 * Shows comprehensive details of a trust profile including:
 * - Basic information
 * - Trust anchors and provenance
 * - Wallet compatibility
 * - Revocation strategy
 */

import { useState, useCallback } from 'react';
import { useAsyncData } from '../../../hooks/useAsyncData';
import { useParams, useNavigate, Link as RouterLink } from 'react-router-dom';
import {
  Box,
  Button,
  Paper,
  Typography,
  Grid,
  Chip,
  Breadcrumbs,
  Link,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  Divider,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  Skeleton,
  Alert,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  TextField,
  Tooltip,
} from '@mui/material';
import AddIcon from '@mui/icons-material/Add';
import ArrowBackIcon from '@mui/icons-material/ArrowBack';
import EditIcon from '@mui/icons-material/Edit';
import VerifiedUserIcon from '@mui/icons-material/VerifiedUser';
import AccountBalanceIcon from '@mui/icons-material/AccountBalance';
import PhoneAndroidIcon from '@mui/icons-material/PhoneAndroid';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import SecurityIcon from '@mui/icons-material/Security';
import { useTranslation } from 'react-i18next';

import { getTrustProfile, getTrustProfileWalletCompatibility, listTrustProfileIssuers, addTrustProfileIssuer } from '../../../services/presentationPolicyApi';

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
  const { data: compatibility = { supported_formats: [], supported_wallets: [] }, loading } = useAsyncData(
    async () => {
      if (!trustProfileId) return { supported_formats: [], supported_wallets: [] };
      return await getTrustProfileWalletCompatibility(trustProfileId);
    },
    [trustProfileId]
  );

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
  const trustAnchors = trustProfile?.trust_sources || trustProfile?.trust_anchors || [];
  const revocationStrategy = trustProfile?.revocation_policy?.check_mode || trustProfile?.revocation_strategy || 'HARD_FAIL';
  const issuerCount = trustProfile?.trusted_issuers?.length
    || trustAnchors.filter((anchor) => anchor.issuer_did).length;

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
                    secondary={anchor.source_type || anchor.type || t('trust.trustProfileDetail.trustAuthority')}
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
                label={String(revocationStrategy).replaceAll('_', ' ')}
                size="small"
                color={String(revocationStrategy).toUpperCase() === 'HARD_FAIL' ? 'success' : 'default'}
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
 * Add Trusted Issuer Dialog
 */
function AddIssuerDialog({ open, profileId, onClose, onAdded }) {
  const { t } = useTranslation('console');
  const [form, setForm] = useState({ name: '', issuer_did: '', description: '' });
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState(null);

  const handleClose = () => {
    setForm({ name: '', issuer_did: '', description: '' });
    setError(null);
    onClose();
  };

  const handleSubmit = useCallback(async () => {
    if (!form.name.trim() || !form.issuer_did.trim()) return;
    setSubmitting(true);
    setError(null);
    try {
      const added = await addTrustProfileIssuer(profileId, {
        name: form.name.trim(),
        issuer_did: form.issuer_did.trim(),
        description: form.description.trim() || null,
      });
      onAdded(added);
      handleClose();
    } catch (err) {
      setError(err?.message || t('trust.addIssuerDialog.failed', 'Failed to add trusted issuer.'));
    } finally {
      setSubmitting(false);
    }
  }, [form, profileId, onAdded, t]);

  return (
    <Dialog open={open} onClose={handleClose} maxWidth="sm" fullWidth>
      <DialogTitle>{t('trust.addIssuerDialog.title', 'Add Trusted Issuer')}</DialogTitle>
      <DialogContent>
        {error && (
          <Alert severity="error" sx={{ mb: 2 }}>{error}</Alert>
        )}
        <TextField
          fullWidth
          required
          label={t('trust.addIssuerDialog.nameLabel', 'Name')}
          value={form.name}
          onChange={(e) => setForm((prev) => ({ ...prev, name: e.target.value }))}
          sx={{ mt: 1, mb: 2 }}
          helperText={t('trust.addIssuerDialog.nameHelper', 'A short display name for this issuer.')}
          slotProps={{
            htmlInput: { 'data-testid': 'addIssuer.name' }
          }}
        />
        <TextField
          fullWidth
          required
          label={t('trust.addIssuerDialog.didLabel', 'Issuer DID')}
          value={form.issuer_did}
          onChange={(e) => setForm((prev) => ({ ...prev, issuer_did: e.target.value }))}
          sx={{ mb: 2 }}
          placeholder="did:example:123..."
          helperText={t('trust.addIssuerDialog.didHelper', 'The decentralised identifier (DID) of the issuer.')}
          slotProps={{
            htmlInput: { 'data-testid': 'addIssuer.did', style: { fontFamily: 'monospace' } }
          }}
        />
        <TextField
          fullWidth
          multiline
          rows={2}
          label={t('trust.addIssuerDialog.descriptionLabel', 'Description (optional)')}
          value={form.description}
          onChange={(e) => setForm((prev) => ({ ...prev, description: e.target.value }))}
          slotProps={{
            htmlInput: { 'data-testid': 'addIssuer.description' }
          }}
        />
      </DialogContent>
      <DialogActions>
        <Button onClick={handleClose} disabled={submitting}>
          {t('actions.cancel', { ns: 'common', defaultValue: 'Cancel' })}
        </Button>
        <Button
          variant="contained"
          onClick={handleSubmit}
          disabled={submitting || !form.name.trim() || !form.issuer_did.trim()}
          data-testid="addIssuer.submit"
        >
          {submitting
            ? t('trust.addIssuerDialog.adding', 'Adding...')
            : t('trust.addIssuerDialog.addButton', 'Add Issuer')}
        </Button>
      </DialogActions>
    </Dialog>
  );
}

/**
 * Trusted Issuers Section
 */
function TrustedIssuersSection({ profileId }) {
  const { t } = useTranslation('console');
  const [dialogOpen, setDialogOpen] = useState(false);
  const [extraIssuers, setExtraIssuers] = useState([]);

  const { data: loadedIssuers = [], loading, error } = useAsyncData(
    () => (profileId ? listTrustProfileIssuers(profileId) : Promise.resolve([])),
    [profileId]
  );

  const safeIssuers = [...(Array.isArray(loadedIssuers) ? loadedIssuers : []), ...extraIssuers];

  const handleIssuerAdded = useCallback((issuer) => {
    setExtraIssuers((prev) => [...prev, issuer]);
  }, []);

  return (
    <Paper sx={{ p: 3, mb: 3 }}>
      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 2 }}>
        <VerifiedUserIcon color="primary" />
        <Typography variant="h6" fontWeight={600} sx={{ flex: 1 }}>
          {t('trust.trustedIssuers')}
        </Typography>
        <Chip label={safeIssuers.length} size="small" sx={{ mr: 1 }} />
        <Tooltip title={t('trust.addIssuerDialog.title', 'Add Trusted Issuer')}>
          <Button
            size="small"
            variant="outlined"
            startIcon={<AddIcon />}
            onClick={() => setDialogOpen(true)}
            data-testid="issuers.addButton"
          >
            {t('trust.addIssuer', 'Add Issuer')}
          </Button>
        </Tooltip>
      </Box>

      {loading ? (
        <Skeleton variant="rectangular" height={80} />
      ) : error ? (
        <Alert severity="error">
          {error.message || t('trust.trustedIssuersPage.loadFailed', 'Trusted issuers could not be loaded.')}
        </Alert>
      ) : safeIssuers.length === 0 ? (
        <Typography variant="body2" color="text.secondary">
          {t('trust.noIssuersConfigured', 'No trusted issuers configured for this profile.')}
        </Typography>
      ) : (
        <TableContainer>
          <Table size="small">
            <TableHead>
              <TableRow>
                <TableCell>{t('trust.trustedIssuersPage.tableHeaders.name', 'Name')}</TableCell>
                <TableCell>{t('trust.trustedIssuersPage.tableHeaders.did', 'DID')}</TableCell>
                <TableCell>{t('trust.trustedIssuersPage.tableHeaders.status', 'Status')}</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {safeIssuers.map((issuer) => (
                <TableRow key={issuer.id}>
                  <TableCell>{issuer.name}</TableCell>
                  <TableCell sx={{ fontFamily: 'monospace', fontSize: '0.75rem', maxWidth: 300, overflow: 'hidden', textOverflow: 'ellipsis' }}>
                    {issuer.did}
                  </TableCell>
                  <TableCell>
                    <Chip
                      label={issuer.status || 'Active'}
                      size="small"
                      color={String(issuer.status).toLowerCase() === 'active' ? 'success' : 'default'}
                    />
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>
      )}

      <AddIssuerDialog
        open={dialogOpen}
        profileId={profileId}
        onClose={() => setDialogOpen(false)}
        onAdded={handleIssuerAdded}
      />
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
  const { data: profile, loading, error } = useAsyncData(
    async () => {
      if (!id) return null;
      return await getTrustProfile(id);
    },
    [id]
  );

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
        <Alert severity="error">{error?.message || t('trust.trustProfileDetail.failedToLoad') || t('trust.trustProfileDetail.notFound')}</Alert>
        <Button
          startIcon={<ArrowBackIcon />}
          onClick={() => navigate('/console/org/trust/profiles')}
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
        <Link component={RouterLink} to="/console/org/trust" underline="hover" color="inherit">
          {t('trust.breadcrumbs.trust')}
        </Link>
        <Link component={RouterLink} to="/console/org/trust/profiles" underline="hover" color="inherit">
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
          onClick={() => navigate(`/console/org/trust/profiles/${id}/edit`)}
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

      {/* Trusted Issuers */}
      <TrustedIssuersSection profileId={id} />

      {/* Wallet Compatibility */}
      <WalletCompatibilityPanel trustProfileId={id} />

      {/* Actions */}
      <Box sx={{ display: 'flex', gap: 2 }}>
        <Button
          variant="outlined"
          startIcon={<ArrowBackIcon />}
          onClick={() => navigate('/console/org/trust/profiles')}
        >
          {t('trust.trustProfileDetail.backToProfiles')}
        </Button>
      </Box>
    </Box>
  );
}

export default TrustProfileDetailPage;

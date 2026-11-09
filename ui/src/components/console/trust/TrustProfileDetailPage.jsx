/**
 * Trust Profile Detail Page
 * 
 * Shows comprehensive details of a trust profile including:
 * - Basic information
 * - Trust anchors and provenance
 * - Wallet compatibility
 * - Revocation strategy
 */

import { useState, useCallback, useEffect, useRef } from 'react';
import { useAsyncActionScope } from '../../../hooks/useAsyncActionScope';
import { useConsole } from '../../../contexts/ConsoleContext';
import { usePermissions } from '../../../hooks/usePermissions';
import { useLocation, useParams, useNavigate, Link as RouterLink } from 'react-router';
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
import SecurityIcon from '@mui/icons-material/Security';
import { useTranslation } from 'react-i18next';

import { getTrustProfile, listTrustProfileIssuers, addTrustProfileIssuer } from '../../../services/presentationPolicyApi';

/** Link to the native credential-template wallet profiles without claiming evidence. */
function WalletProfileGuidance() {
  const { t } = useTranslation('console');
  return (
    <Paper sx={{ p: 3, mb: 3 }}>
      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 2 }}>
        <PhoneAndroidIcon color="primary" />
        <Typography variant="h6" sx={{ fontWeight: 600 }}>
          {t('trust.trustProfileDetail.walletCompatibility')}
        </Typography>
      </Box>
      <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
        {t('trust.trustProfileDetail.credentialWalletGuidance')}
      </Typography>
      <Button component={RouterLink} to="/console/org/templates/credentials" variant="outlined">
        {t('trust.trustProfileDetail.viewCredentialTemplates')}
      </Button>
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
        <Typography variant="h6" sx={{ fontWeight: 600 }}>
          {t('trust.trustProfileDetail.trustProvenance')}
        </Typography>
      </Box>

      <Grid container spacing={3}>
        {/* Trust Anchors */}
        <Grid size={{ xs: 12, md: 6 }}>
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
        <Grid size={{ xs: 12, md: 6 }}>
          <Typography variant="subtitle2" gutterBottom>
            {t('trust.trustProfileDetail.trustMetadata')}
          </Typography>
          <Box sx={{ mt: 1 }}>
            <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 1 }}>
              <Typography variant="body2" color="text.secondary">
                {t('trust.trustProfileDetail.trustedIssuersCount')}
              </Typography>
              <Typography variant="body2" sx={{ fontWeight: 600 }}>
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

const PROFILE_STATUSES = {
  DRAFT: 'statusDraft', ACTIVE: 'statusActive', SUSPENDED: 'statusSuspended', ARCHIVED: 'statusArchived',
};
const RELATIONSHIP_STATUSES = {
  TRUSTED: 'relationshipTrusted', DENIED: 'relationshipDenied', UNDER_REVIEW: 'relationshipUnderReview',
};
const ISSUER_COMPLIANCE = {
  ACCREDITED: 'complianceAccredited', COMPLIANT: 'complianceCompliant',
  SUSPENDED: 'complianceSuspended', REVOKED: 'complianceRevoked',
};

function statusLabel(value, labels, t) {
  const key = labels[String(value || '').toUpperCase()] || 'statusUnknown';
  return t('trust.trustProfileDetail.' + key);
}

function issuerInScope(issuer, profileId, organizationId, expectedDid) {
  const entity = issuer?.issuer_entity;
  return typeof issuer?.id === 'string' && issuer.id.trim()
    && issuer.trust_profile_id === profileId
    && typeof entity?.id === 'string' && entity.id.trim()
    && issuer.issuer_id === entity.id
    && typeof entity.issuer_id === 'string' && entity.issuer_id.trim()
    && issuer.did === entity.issuer_id
    && (expectedDid === undefined || issuer.did === expectedDid)
    && (entity.organization_id === organizationId
      || (entity.organization_id == null && entity.is_system_issuer === true));
}

function checkedIssuerInventory(rows, profileId, organizationId, message) {
  const ids = new Set();
  if (!Array.isArray(rows) || rows.some((issuer) => {
    if (!issuerInScope(issuer, profileId, organizationId) || ids.has(issuer.id)) return true;
    ids.add(issuer.id);
    return false;
  })) throw new Error(message);
  return rows;
}

function actionInView(action, isCurrentView) {
  const isCurrent = () => action.isCurrent() && isCurrentView();
  const requireCurrent = () => {
    if (!isCurrent()) {
      const error = new Error('The trust profile view or action changed.');
      error.name = 'AbortError';
      throw error;
    }
  };
  return {
    isCurrent,
    async run(operation, ...args) {
      requireCurrent();
      try {
        return await action.run(operation, ...args);
      } finally {
        requireCurrent();
      }
    },
  };
}

/** Mounted only while open, so close/reopen gets an independent action lifetime. */
function AddIssuerDialog({ profileId, organizationId, canAdd, isCurrentView, onClose, onAdded }) {
  const { t } = useTranslation('console');
  const beginAction = useAsyncActionScope();
  const busy = useRef(false);
  const acknowledged = useRef(null);
  const [form, setForm] = useState({ name: '', issuer_did: '', description: '' });
  const [submitting, setSubmitting] = useState(false);
  const [awaitingReadback, setAwaitingReadback] = useState(false);
  const [error, setError] = useState(null);

  const handleClose = useCallback(() => {
    if (!busy.current && isCurrentView()) onClose();
  }, [onClose, isCurrentView]);

  const handleSubmit = useCallback(async () => {
    if (busy.current || !canAdd || !isCurrentView() || !form.name.trim() || !form.issuer_did.trim()) return;
    const action = actionInView(beginAction(), isCurrentView);
    const issuerDid = form.issuer_did.trim();
    busy.current = true;
    setSubmitting(true);
    setError(null);
    try {
      let added = acknowledged.current;
      if (!added) {
        added = await action.run(addTrustProfileIssuer, profileId, organizationId, {
          name: form.name.trim(),
          issuer_did: issuerDid,
          description: form.description.trim() || null,
        }, { isCurrent: action.isCurrent });
        if (!issuerInScope(added, profileId, organizationId, issuerDid)) {
          throw new Error(t('trust.trustProfileDetail.issuerScopeMismatch'));
        }
        acknowledged.current = added;
        setAwaitingReadback(true);
      }
      // A failed readback is retried as a read; it never repeats an acknowledged
      // relationship write. Already dispatched writes are not rolled back.
      await action.run(onAdded, added, action);
      if (action.isCurrent()) onClose();
    } catch (reason) {
      if (action.isCurrent()) {
        setError(reason?.message || t('trust.trustProfileDetail.issuerAddFailed'));
      }
    } finally {
      if (action.isCurrent()) {
        busy.current = false;
        setSubmitting(false);
      }
    }
  }, [beginAction, canAdd, form, profileId, organizationId, isCurrentView, onAdded, onClose, t]);

  const fieldsDisabled = submitting || awaitingReadback;
  return (
    <Dialog open onClose={handleClose} disableEscapeKeyDown={submitting} maxWidth="sm" fullWidth>
      <DialogTitle>{t('trust.addIssuerDialog.title', 'Add Trusted Issuer')}</DialogTitle>
      <DialogContent>
        {error && <Alert severity="error" sx={{ mb: 2 }}>{error}</Alert>}
        {error && awaitingReadback && (
          <Typography variant="body2" sx={{ mb: 2 }}>
            {t('trust.trustProfileDetail.issuerAwaitingReadback')}
          </Typography>
        )}
        <TextField
          fullWidth required disabled={fieldsDisabled}
          label={t('trust.addIssuerDialog.nameLabel', 'Name')}
          value={form.name}
          onChange={(event) => setForm((previous) => ({ ...previous, name: event.target.value }))}
          sx={{ mt: 1, mb: 2 }}
          helperText={t('trust.addIssuerDialog.nameHelper', 'A short display name for this issuer.')}
          slotProps={{ htmlInput: { 'data-testid': 'addIssuer.name' } }}
        />
        <TextField
          fullWidth required disabled={fieldsDisabled}
          label={t('trust.addIssuerDialog.didLabel', 'Issuer DID')}
          value={form.issuer_did}
          onChange={(event) => setForm((previous) => ({ ...previous, issuer_did: event.target.value }))}
          sx={{ mb: 2 }}
          placeholder="did:example:123..."
          helperText={t('trust.addIssuerDialog.didHelper', 'The decentralised identifier (DID) of the issuer.')}
          slotProps={{ htmlInput: { 'data-testid': 'addIssuer.did', style: { fontFamily: 'monospace' } } }}
        />
        <TextField
          fullWidth multiline rows={2} disabled={fieldsDisabled}
          label={t('trust.addIssuerDialog.descriptionLabel', 'Description (optional)')}
          value={form.description}
          onChange={(event) => setForm((previous) => ({ ...previous, description: event.target.value }))}
          slotProps={{ htmlInput: { 'data-testid': 'addIssuer.description' } }}
        />
      </DialogContent>
      <DialogActions>
        <Button onClick={handleClose} disabled={submitting}>
          {t('actions.cancel', { ns: 'common', defaultValue: 'Cancel' })}
        </Button>
        <Button
          variant="contained" onClick={handleSubmit}
          disabled={submitting || !canAdd || !form.name.trim() || !form.issuer_did.trim()}
          data-testid="addIssuer.submit"
        >
          {submitting ? t('trust.addIssuerDialog.adding', 'Adding...')
            : awaitingReadback ? t('trust.trustProfileDetail.retryIssuers')
              : t('trust.addIssuerDialog.addButton', 'Add Issuer')}
        </Button>
      </DialogActions>
    </Dialog>
  );
}

/** Only mounted after both native read grants and the profile owner are checked. */
function TrustedIssuersSection({ profileId, organizationId, canAdd, isCurrentView }) {
  const { t } = useTranslation('console');
  const beginRead = useAsyncActionScope();
  const [dialogOpen, setDialogOpen] = useState(false);
  const [issuers, setIssuers] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const checkInventory = useCallback((rows) => checkedIssuerInventory(
    rows, profileId, organizationId, t('trust.trustProfileDetail.issuerScopeMismatch'),
  ), [profileId, organizationId, t]);

  const load = useCallback(async () => {
    const action = actionInView(beginRead(), isCurrentView);
    if (!action.isCurrent()) return;
    setLoading(true);
    setError(null);
    setIssuers(null);
    try {
      const rows = await action.run(listTrustProfileIssuers, profileId, organizationId, { isCurrent: action.isCurrent });
      if (action.isCurrent()) setIssuers(checkInventory(rows));
    } catch (reason) {
      if (action.isCurrent()) setError(reason?.message || t('trust.trustProfileDetail.issuerLoadFailed'));
    } finally {
      if (action.isCurrent()) setLoading(false);
    }
  }, [beginRead, profileId, organizationId, checkInventory, isCurrentView, t]);
  useEffect(() => { load(); }, [load]);

  const handleIssuerAdded = useCallback(async (added, action) => {
    if (!action.isCurrent()) return;
    // Invalidate an older standalone read without superseding the mutation's
    // independent lifetime. Never synthesize an extra row from a write response.
    beginRead();
    try {
      const rows = checkInventory(await action.run(
        listTrustProfileIssuers, profileId, organizationId, { isCurrent: action.isCurrent },
      ));
      if (!rows.some((row) => row.id === added.id && row.issuer_id === added.issuer_id && row.did === added.did)) {
        throw new Error(t('trust.trustProfileDetail.issuerNotConfirmed'));
      }
      if (action.isCurrent()) {
        setIssuers(rows);
        setError(null);
        setLoading(false);
      }
    } catch (reason) {
      if (action.isCurrent()) {
        // Preserve the unresolved inventory even if the user closes the dialog.
        setIssuers(null);
        setError(reason?.message || t('trust.trustProfileDetail.issuerLoadFailed'));
        setLoading(false);
      }
      throw reason;
    }
  }, [beginRead, checkInventory, profileId, organizationId, t]);

  return (
    <Paper sx={{ p: 3, mb: 3 }}>
      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 2 }}>
        <VerifiedUserIcon color="primary" />
        <Typography variant="h6" sx={{ fontWeight: 600, flex: 1 }}>{t('trust.trustedIssuers')}</Typography>
        {!loading && !error && issuers && <Chip label={issuers.length} size="small" sx={{ mr: 1 }} />}
        {canAdd && (
          <Tooltip title={t('trust.addIssuerDialog.title', 'Add Trusted Issuer')}>
            <span>
              <Button
                size="small" variant="outlined" startIcon={<AddIcon />}
                disabled={loading || Boolean(error) || !issuers}
                onClick={() => { if (isCurrentView()) setDialogOpen(true); }} data-testid="issuers.addButton"
              >
                {t('trust.addIssuer', 'Add Issuer')}
              </Button>
            </span>
          </Tooltip>
        )}
      </Box>
      {loading ? <Skeleton variant="rectangular" height={80} />
        : error ? (
          <Alert severity="error">
            {error}
            <Button onClick={load}>{t('trust.trustProfileDetail.retryIssuers')}</Button>
          </Alert>
        ) : issuers?.length === 0 ? (
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
                  <TableCell>{t('trust.trustProfileDetail.relationshipStatusLabel')}</TableCell>
                  <TableCell>{t('trust.trustProfileDetail.issuerComplianceLabel')}</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {(issuers || []).map((issuer) => (
                  <TableRow key={issuer.id}>
                    <TableCell>{issuer.name}</TableCell>
                    <TableCell sx={{ fontFamily: 'monospace', fontSize: '0.75rem', maxWidth: 300, overflow: 'hidden', textOverflow: 'ellipsis' }}>
                      {issuer.did}
                    </TableCell>
                    <TableCell>
                      <Chip label={statusLabel(issuer.relationship_status, RELATIONSHIP_STATUSES, t)} size="small"
                        color={issuer.relationship_status === 'TRUSTED' ? 'success' : 'default'} />
                    </TableCell>
                    <TableCell>
                      <Chip label={statusLabel(issuer.compliance_status, ISSUER_COMPLIANCE, t)} size="small"
                        color={['ACCREDITED', 'COMPLIANT'].includes(issuer.compliance_status) ? 'success' : 'default'} />
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        )}
      {dialogOpen && <AddIssuerDialog
        profileId={profileId} organizationId={organizationId} canAdd={canAdd} isCurrentView={isCurrentView}
        onClose={() => setDialogOpen(false)} onAdded={handleIssuerAdded}
      />}
    </Paper>
  );
}

/**
 * Trust Profile Detail Page Component
 */
function TrustProfileDetailContent({ id, organizationId, canEdit, canViewIssuers, canAddIssuer }) {
  const { t } = useTranslation('console');
  const navigate = useNavigate();
  const beginLoad = useAsyncActionScope();
  // BrowserRouter updates this entry before its React transition commits.
  // An old mounted view cannot start a follow-up or dispatch during that gap.
  const browserEntry = useRef(typeof window === 'undefined' ? null : {
    href: window.location.href,
    key: window.history.state?.key,
  });
  const isCurrentView = useCallback(() => !browserEntry.current || (
    typeof window !== 'undefined' && window.location.href === browserEntry.current.href
      && window.history.state?.key === browserEntry.current.key
  ), []);
  const [profile, setProfile] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const reload = useCallback(async () => {
    const action = actionInView(beginLoad(), isCurrentView);
    if (!action.isCurrent()) return;
    setProfile(null);
    setError(null);
    setLoading(true);
    try {
      const result = await action.run(getTrustProfile, id);
      if (result?.id !== id || result.organization_id !== organizationId) {
        throw new Error(t('trust.trustProfileDetail.profileScopeMismatch'));
      }
      if (action.isCurrent()) setProfile(result);
    } catch (reason) {
      if (action.isCurrent()) setError(reason instanceof Error ? reason : new Error(String(reason)));
    } finally {
      if (action.isCurrent()) setLoading(false);
    }
  }, [beginLoad, isCurrentView, id, organizationId, t]);
  useEffect(() => { reload(); }, [reload]);

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
        <Button onClick={reload} sx={{ mt: 2 }}>{t('trust.trustProfileDetail.retryProfile')}</Button>
        <Button
          startIcon={<ArrowBackIcon />}
          onClick={() => { if (isCurrentView()) navigate('/console/org/trust/profiles'); }}
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
              label={statusLabel(profile.status, PROFILE_STATUSES, t)}
              color={profile.status === 'active' ? 'success' : 'default'}
              size="small"
            />
            {profile.is_default && (
              <Chip label={t('trust.trustProfileDetail.default')} color="primary" size="small" variant="outlined" />
            )}
          </Box>
        </Box>
        {canEdit && <Button
          variant="outlined"
          startIcon={<EditIcon />}
          onClick={() => { if (isCurrentView()) navigate('/console/org/trust/profiles/' + encodeURIComponent(id) + '/edit'); }}
        >
          {t('actions.edit', { ns: 'common' })}
        </Button>}
      </Box>

      {/* Basic Information */}
      <Paper sx={{ p: 3, mb: 3 }}>
        <Typography variant="h6" gutterBottom sx={{ fontWeight: 600 }}>
          {t('trust.trustProfileDetail.basicInformation')}
        </Typography>
        <Grid container spacing={2}>
          <Grid size={{ xs: 12, sm: 6 }}>
            <Typography variant="body2" color="text.secondary">
              {t('trust.trustProfileDetail.profileId')}
            </Typography>
            <Typography variant="body1" sx={{ fontWeight: 500 }}>
              {profile.id}
            </Typography>
          </Grid>
          <Grid size={{ xs: 12, sm: 6 }}>
            <Typography variant="body2" color="text.secondary">
              {t('trust.trustProfileDetail.created')}
            </Typography>
            <Typography variant="body1" sx={{ fontWeight: 500 }}>
              {profile.created_at ? new Date(profile.created_at).toLocaleDateString() : t('trust.trustProfileDetail.notAvailable')}
            </Typography>
          </Grid>
          {profile.description && (
            <Grid size={12}>
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
      {canViewIssuers ? <TrustedIssuersSection
        profileId={id} organizationId={organizationId} canAdd={canAddIssuer} isCurrentView={isCurrentView}
      /> : <Alert severity="info" sx={{ mb: 3 }}>{t('trust.trustProfileDetail.issuerReadDenied')}</Alert>}

      {/* Wallet Compatibility */}
      <WalletProfileGuidance />

      {/* Actions */}
      <Box sx={{ display: 'flex', gap: 2 }}>
        <Button
          variant="outlined"
          startIcon={<ArrowBackIcon />}
          onClick={() => { if (isCurrentView()) navigate('/console/org/trust/profiles'); }}
        >
          {t('trust.trustProfileDetail.backToProfiles')}
        </Button>
      </Box>
    </Box>
  );
}

export function TrustProfileDetailPage() {
  const { t } = useTranslation('console');
  const { id } = useParams();
  const location = useLocation();
  const { activeOrgId } = useConsole();
  const { can, isLoading } = usePermissions();
  const grants = {
    view: can('trust-profile', 'view'),
    edit: can('trust-profile', 'edit'),
    issuerView: can('trusted-issuer', 'view'),
    profileCreate: can('trust-profile', 'create'),
    issuerCreate: can('trusted-issuer', 'create'),
  };
  if (isLoading) return <Skeleton variant="rectangular" height={400} />;
  if (typeof activeOrgId !== 'string' || !activeOrgId.trim()) {
    return <Alert severity="info">{t('trust.trustProfileDetail.selectOrganization')}</Alert>;
  }
  if (!grants.view) return <Alert severity="info">{t('trust.trustProfileDetail.profileReadDenied')}</Alert>;
  if (typeof id !== 'string' || !id.trim()) {
    return <Alert severity="error">{t('trust.trustProfileDetail.profileScopeMismatch')}</Alert>;
  }
  // usePermissions withdraws grants on account changes; ConsoleProvider also
  // remounts its session. Route entries and every relevant grant own local state.
  const key = JSON.stringify([activeOrgId, id, location.key, location.pathname, location.search, location.hash, ...Object.values(grants)]);
  return <TrustProfileDetailContent key={key} id={id} organizationId={activeOrgId}
    canEdit={grants.edit} canViewIssuers={grants.issuerView}
    canAddIssuer={grants.issuerView && grants.profileCreate && grants.issuerCreate} />;
}

export default TrustProfileDetailPage;

/**
 * CredentialCatalog Component
 * 
 * Displays available credentials for applicants to apply for.
 * Credentials are filtered based on the vendor organization's configuration.
 */

import React, { useState, useEffect, useMemo, useCallback } from 'react';
import {
  Container,
  Grid,
  Paper,
  Typography,
  Box,
  Card,
  CardContent,
  CardActions,
  Button,
  Chip,
  TextField,
  InputAdornment,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Skeleton,
  Alert,
  IconButton,
  Tooltip,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  Divider,
  Stack,
} from '@mui/material';
import {
  Search as SearchIcon,
  FilterList as FilterIcon,
  CardMembership as CredentialIcon,
  Info as InfoIcon,
  CheckCircle as CheckIcon,
  Schedule as PendingIcon,
  AttachMoney as PriceIcon,
  Business as BusinessIcon,
  Verified as VerifiedIcon,
} from '@mui/icons-material';
import { useLocation, useNavigate } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { useAuth } from '../../hooks/useAuth';
import { usePreview } from '../../contexts/PreviewContext';
import { get } from '../../services/api';
import { getCurrentCanvasLtiExperience } from '../../services/canvasLtiExperience';
import { listApplications } from '../../services/applicantApi';
import { listApplicationTemplates } from '../../services/applicationTemplatesApi';
import {
  buildCredentialApplicationNavigationState,
  extractApplicationStatusInfo,
  filterCredentialCatalogItems,
  getCredentialCatalogCategories,
  loadCredentialCatalogItems,
  loadExistingCredentialApplications,
  scopeCredentialCatalogItemsForCanvasLaunch,
} from '../../application/applications';

function getLtiSessionValue(session, key) {
  return session?.[key] || null;
}

function normalizeOrganizationIdCandidate(value) {
  if (value === null || value === undefined) {
    return null;
  }

  if (typeof value !== 'string' && typeof value !== 'number') {
    return null;
  }

  const normalized = String(value).trim();
  return normalized === '' ? null : normalized;
}

function getFirstOrganizationMembershipId(user) {
  const membershipCollections = [
    user?.organizations,
    user?.organization_memberships,
    user?.organizationMemberships,
    user?.memberships,
  ];

  for (const collection of membershipCollections) {
    const entries = Array.isArray(collection) ? collection : [];
    for (const entry of entries) {
      const directId = normalizeOrganizationIdCandidate(entry);
      if (directId) {
        return directId;
      }

      const candidates = [
        entry?.organization_id,
        entry?.organizationId,
        entry?.organization?.id,
        entry?.id,
      ];
      for (const candidate of candidates) {
        const normalized = normalizeOrganizationIdCandidate(candidate);
        if (normalized) {
          return normalized;
        }
      }
    }
  }

  return null;
}

function resolveEffectiveOrganizationId(organizationId, user) {
  const candidates = [
    organizationId,
    user?.current_organization_id,
    user?.currentOrganizationId,
    user?.default_organization_id,
    user?.defaultOrganizationId,
    user?.organization_id,
    user?.organizationId,
  ];

  for (const candidate of candidates) {
    const normalized = normalizeOrganizationIdCandidate(candidate);
    if (normalized) {
      return normalized;
    }
  }

  return getFirstOrganizationMembershipId(user);
}

function createEmptyApplicationStatusInfo() {
  return {
    statusByCredentialId: {},
    counts: { pending: 0, approved: 0, offered: 0, rejected: 0, credentialed: 0 },
  };
}

const CredentialCatalog = () => {
  const { t } = useTranslation('applicant');
  const navigate = useNavigate();
  const location = useLocation();
  const { organizationId, organizationName, user } = useAuth();
  const { isPreview } = usePreview?.() || { isPreview: false };
  
  const CATEGORIES = useMemo(() => getCredentialCatalogCategories(t), [t]);
  
  // State
  const [credentials, setCredentials] = useState([]);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');
  const [categoryFilter, setCategoryFilter] = useState('all');
  const [selectedCredential, setSelectedCredential] = useState(null);
  const [detailsOpen, setDetailsOpen] = useState(false);
  const [catalogLoadError, setCatalogLoadError] = useState(null);
  const [catalogMissingOrganization, setCatalogMissingOrganization] = useState(false);
  const [existingApplications, setExistingApplications] = useState([]);
  const [appStatusInfo, setAppStatusInfo] = useState(createEmptyApplicationStatusInfo);
  const [canvasLtiSession, setCanvasLtiSession] = useState(() => location.state?.canvasLtiSession || null);
  const [canvasLtiLoading, setCanvasLtiLoading] = useState(false);

  const canvasLtiState = useMemo(
    () => new URLSearchParams(location.search || '').get('canvas_lti_state') || '',
    [location.search]
  );
  const canvasLtiOrganizationId = useMemo(
    () => getLtiSessionValue(canvasLtiSession, 'organization_id'),
    [canvasLtiSession]
  );
  const effectiveOrganizationId = useMemo(
    () => canvasLtiOrganizationId || resolveEffectiveOrganizationId(organizationId, user),
    [canvasLtiOrganizationId, organizationId, user]
  );

  useEffect(() => {
    if (location.state?.canvasLtiSession) {
      setCanvasLtiSession(location.state.canvasLtiSession);
    }
  }, [location.state]);

  useEffect(() => {
    let alive = true;

    async function loadCanvasLtiSession() {
      if (!canvasLtiState || canvasLtiSession) {
        return;
      }

      setCanvasLtiLoading(true);
      try {
        const data = await getCurrentCanvasLtiExperience();
        if (alive) {
          setCanvasLtiSession(data);
        }
      } catch (error) {
        console.error('Failed to resolve Canvas LTI catalog context:', error);
      } finally {
        if (alive) {
          setCanvasLtiLoading(false);
        }
      }
    }

    loadCanvasLtiSession();
    return () => {
      alive = false;
    };
  }, [canvasLtiState, canvasLtiSession]);

  const listCredentialTemplates = useCallback((currentOrganizationId) => {
    const normalizedOrganizationId = normalizeOrganizationIdCandidate(currentOrganizationId);
    if (!normalizedOrganizationId) {
      return Promise.resolve([]);
    }

    return get(`/v1/credential-templates?organization_id=${encodeURIComponent(normalizedOrganizationId)}&status=active`);
  }, []);

  const listApplicantApplications = useCallback(async () => {
    const result = await listApplications({ limit: 100 });
    return result.items;
  }, []);

  /**
   * Fetch credentials available to applicants of this organization
   */
  const fetchAvailableCredentials = useCallback(async () => {
    setLoading(true);
    if (!effectiveOrganizationId) {
      setCredentials([]);
      setCatalogLoadError(new Error('Choose or join an organization to view its credential catalog.'));
      setCatalogMissingOrganization(true);
      setLoading(false);
      return;
    }
    try {
      const [result, applicationTemplates] = await Promise.all([
        loadCredentialCatalogItems({
          organizationId: effectiveOrganizationId,
          organizationName,
          listCredentialTemplates,
        }),
        listApplicationTemplates(effectiveOrganizationId),
      ]);
      const activeApplicationTemplateByCredential = new Map(
        (applicationTemplates || [])
          .filter((template) => String(template.status || '').toUpperCase() === 'ACTIVE')
          .map((template) => [template.credential_template_id, template]),
      );
      setCredentials(result.credentials
        .map((credential) => {
          const applicationTemplate = activeApplicationTemplateByCredential.get(credential.id);
          return applicationTemplate
            ? { ...credential, application_template_id: applicationTemplate.id, application_template: applicationTemplate }
            : null;
        })
        .filter(Boolean));
      setCatalogLoadError(result.error || null);
      setCatalogMissingOrganization(Boolean(result.missingOrganization));
      if (result.error && !result.missingOrganization) {
        console.error('Failed to fetch credentials:', result.error);
      }
    } catch (error) {
      console.error('Failed to fetch credentials:', error);
      setCredentials([]);
      setCatalogLoadError(error);
      setCatalogMissingOrganization(false);
    } finally {
      setLoading(false);
    }
  }, [effectiveOrganizationId, organizationName, listCredentialTemplates]);

  /**
   * Fetch applicant's existing applications (with status data)
   */
  const fetchExistingApplications = useCallback(async () => {
    if (!effectiveOrganizationId || !user?.user_id) {
      setExistingApplications([]);
      setAppStatusInfo(createEmptyApplicationStatusInfo());
      return;
    }

    try {
      const applications = await listApplicantApplications();
      const applicationIds = applications.map((application) => application.credential_template_id).filter(Boolean);
      setExistingApplications(applicationIds);

      // Also fetch raw application data for status counts
      setAppStatusInfo(extractApplicationStatusInfo(applications));
    } catch (error) {
      console.error('Failed to fetch applications:', error);
      setExistingApplications([]);
      setAppStatusInfo(createEmptyApplicationStatusInfo());
    }
  }, [effectiveOrganizationId, user?.user_id, listApplicantApplications]);

  // Fetch data when component mounts or organizationId changes
  useEffect(() => {
    fetchAvailableCredentials();
    fetchExistingApplications();
  }, [fetchAvailableCredentials, fetchExistingApplications]);

  /**
   * Filter credentials based on search and category
   */
  const canvasLtiCredentialTemplateId = useMemo(
    () => getLtiSessionValue(canvasLtiSession, 'credential_template_id'),
    [canvasLtiSession]
  );
  const canvasLtiApplicationTemplateId = useMemo(
    () => getLtiSessionValue(canvasLtiSession, 'application_template_id'),
    [canvasLtiSession]
  );
  const canvasScopedCredentials = useMemo(() => {
    return scopeCredentialCatalogItemsForCanvasLaunch(credentials, {
      credentialTemplateIds: canvasLtiCredentialTemplateId ? [canvasLtiCredentialTemplateId] : [],
    });
  }, [credentials, canvasLtiCredentialTemplateId]);
  const filteredCredentials = useMemo(() => {
    return filterCredentialCatalogItems(canvasScopedCredentials, { searchTerm, categoryFilter });
  }, [canvasScopedCredentials, searchTerm, categoryFilter]);

  const canvasLtiNavigationContext = useMemo(() => {
    if (!canvasLtiState) {
      return null;
    }
    return {
      state: canvasLtiState,
      canvas_program_binding_id: getLtiSessionValue(canvasLtiSession, 'canvas_program_binding_id'),
      canvas_platform_id: getLtiSessionValue(canvasLtiSession, 'canvas_platform_id'),
      application_template_id: canvasLtiApplicationTemplateId,
      credential_template_id: canvasLtiCredentialTemplateId,
    };
  }, [canvasLtiApplicationTemplateId, canvasLtiCredentialTemplateId, canvasLtiSession, canvasLtiState]);

  /**
   * Handle credential application
   */
  const handleApply = (credential) => {
    const navigation = buildCredentialApplicationNavigationState(credential, {
      currentPathname: location.pathname,
      isPreview,
      canvasLtiContext: canvasLtiNavigationContext,
      canvasLtiSession,
    });
    navigate(navigation.path, { state: navigation.state });
  };

  /**
   * Open credential details modal
   */
  const handleViewDetails = (credential) => {
    setSelectedCredential(credential);
    setDetailsOpen(true);
  };

  /**
   * Check if already applied for credential
   */
  const hasExistingApplication = (credentialId) => {
    return existingApplications.includes(credentialId);
  };

  /**
   * Get per-credential application status chip
   */
  const getApplicationStatus = (credentialId) => {
    const status = appStatusInfo.statusByCredentialId[credentialId];
    if (!status) return null;
    if (['credentialed', 'issued'].includes(status)) {
      return <Chip icon={<CheckIcon />} label="Issued" size="small" color="success" sx={{ mt: 1 }} />;
    }
    if (status === 'approved') {
      return <Chip icon={<CheckIcon />} label="Approved" size="small" color="primary" sx={{ mt: 1 }} />;
    }
    if (status === 'offered') {
      return <Chip icon={<CheckIcon />} label="Wallet Invite Ready" size="small" color="primary" sx={{ mt: 1 }} />;
    }
    if (status === 'rejected') {
      return <Chip label="Rejected" size="small" color="error" sx={{ mt: 1 }} />;
    }
    return (
      <Chip icon={<PendingIcon />} label={t('catalog.card.status.pending')} size="small" color="warning" sx={{ mt: 1 }} />
    );
  };

  const { counts } = appStatusInfo;
  const hasAnyApplications = counts.pending + counts.approved + counts.offered + counts.rejected + counts.credentialed > 0;
  const catalogLoadAlertMessage = catalogLoadError
    ? catalogMissingOrganization
      ? 'We could not determine your organization yet. Refresh after sign-in, or choose or join an organization before browsing credentials.'
      : 'We could not load credential templates. Refresh the page, then contact support if the catalog still does not appear.'
    : null;

  return (
    <Container maxWidth="lg" data-testid="credential-catalog-page">
      {/* Organization Metadata Header */}
      {organizationName && (
        <Paper elevation={1} sx={{ p: 3, mb: 3, bgcolor: 'primary.light', color: 'primary.contrastText' }}>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
            <BusinessIcon sx={{ fontSize: 48 }} />
            <Box>
              <Typography variant="h5" component="h2" gutterBottom sx={{ mb: 0.5 }}>
                {organizationName}
              </Typography>
              <Typography variant="body2" sx={{ opacity: 0.9 }}>
                {t('catalog.orgHeader.subtitle', { defaultValue: 'Browse and apply for available credentials' })}
              </Typography>
            </Box>
          </Box>
        </Paper>
      )}

      {/* Application Status Bar */}
      {hasAnyApplications && (
        <Paper variant="outlined" sx={{ p: 2, mb: 3 }}>
          <Typography variant="subtitle2" color="text.secondary" sx={{ mb: 1 }}>
            Application Status
          </Typography>
          <Stack direction="row" spacing={2} flexWrap="wrap" useFlexGap>
            {counts.pending > 0 && (
              <Chip
                icon={<PendingIcon />}
                label={`Pending (${counts.pending})`}
                color="warning"
                size="small"
                onClick={() => navigate('/console/applicant/identity?filter=in-progress')}
                clickable
              />
            )}
            {counts.approved > 0 && (
              <Chip
                icon={<CheckIcon />}
                label={`Approved (${counts.approved})`}
                color="primary"
                size="small"
                onClick={() => navigate('/console/applicant/identity?filter=action')}
                clickable
              />
            )}
            {counts.offered > 0 && (
              <Chip
                icon={<CheckIcon />}
                label={`Wallet Invite Ready (${counts.offered})`}
                color="primary"
                size="small"
                onClick={() => navigate('/console/applicant/identity?filter=in-progress')}
                clickable
              />
            )}
            {counts.credentialed > 0 && (
              <Chip
                icon={<VerifiedIcon />}
                label={`Issued (${counts.credentialed})`}
                color="success"
                size="small"
                onClick={() => navigate('/console/applicant/identity?filter=issued')}
                clickable
              />
            )}
            {counts.rejected > 0 && (
              <Chip
                label={`Rejected (${counts.rejected})`}
                color="error"
                size="small"
                onClick={() => navigate('/console/applicant/identity')}
                clickable
              />
            )}
          </Stack>
        </Paper>
      )}

      <Box sx={{ mb: 4 }}>
        <Typography variant="h4" component="h1" gutterBottom data-testid="catalog-title">
          <CredentialIcon sx={{ mr: 2, verticalAlign: 'middle' }} />
          {t('catalog.title')}
        </Typography>
        <Typography variant="subtitle1" color="text.secondary">
          {organizationName 
            ? t('catalog.descriptionWithOrg', { organizationName })
            : t('catalog.description')}
        </Typography>
      </Box>

      {/* Search and Filters */}
      <Paper sx={{ p: 2, mb: 3 }} data-testid="catalog-filters">
        <Grid container spacing={2} alignItems="center">
          <Grid item xs={12} md={6}>
            <TextField
              fullWidth
              placeholder={t('catalog.searchPlaceholder')}
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              data-testid="credential-search"
              InputProps={{
                startAdornment: (
                  <InputAdornment position="start">
                    <SearchIcon />
                  </InputAdornment>
                )
              }}
            />
          </Grid>
          <Grid item xs={12} md={4}>
            <FormControl fullWidth>
              <InputLabel>{t('catalog.filters.category')}</InputLabel>
              <Select
                value={categoryFilter}
                label={t('catalog.filters.category')}
                onChange={(e) => setCategoryFilter(e.target.value)}
                data-testid="category-filter"
                startAdornment={
                  <InputAdornment position="start">
                    <FilterIcon />
                  </InputAdornment>
                }
              >
                {CATEGORIES.map(cat => (
                  <MenuItem key={cat.value} value={cat.value}>
                    {cat.label}
                  </MenuItem>
                ))}
              </Select>
            </FormControl>
          </Grid>
          <Grid item xs={12} md={2}>
            <Typography variant="body2" color="text.secondary" textAlign="center" data-testid="credentials-count">
              {t('catalog.resultsCount', { count: filteredCredentials.length })}
            </Typography>
          </Grid>
        </Grid>
      </Paper>

      {/* Credential Grid */}
      <Grid container spacing={3}>
        {loading || canvasLtiLoading ? (
          // Loading skeletons
          [...Array(6)].map((_, index) => (
            <Grid item xs={12} sm={6} md={4} key={index}>
              <Card>
                <Skeleton variant="rectangular" height={140} />
                <CardContent>
                  <Skeleton variant="text" width="60%" />
                  <Skeleton variant="text" />
                  <Skeleton variant="text" width="80%" />
                </CardContent>
              </Card>
            </Grid>
          ))
        ) : catalogLoadAlertMessage ? (
          <Grid item xs={12}>
            <Alert severity={catalogMissingOrganization ? 'warning' : 'error'} data-testid="catalog-load-alert">
              {catalogLoadAlertMessage}
            </Alert>
          </Grid>
        ) : filteredCredentials.length === 0 ? (
          <Grid item xs={12}>
            <Alert severity="info">
              {t('catalog.empty.message')}
            </Alert>
          </Grid>
        ) : (
          filteredCredentials.map((credential) => {
            const IconComponent = credential.icon || CredentialIcon;
            const hasApplied = hasExistingApplication(credential.id);
            const applicationStatus = appStatusInfo.statusByCredentialId[credential.id];
            const canClaim = ['approved', 'offered'].includes(applicationStatus);
            const alreadyIssued = ['credentialed', 'issued'].includes(applicationStatus);
            const isDisabled = !isPreview && hasApplied && !canClaim;
            const actionLabel = isPreview
              ? t('catalog.card.actions.preview')
              : canClaim
                ? t('catalog.card.actions.claim', 'Claim')
                : alreadyIssued
                  ? t('catalog.card.status.issued', 'Issued')
                  : (hasApplied ? t('catalog.card.status.pending') : t('catalog.card.actions.apply'));
            
            return (
              <Grid item xs={12} sm={6} md={4} key={credential.id}>
                <Card 
                  data-testid={`credential-card-${credential.id}`}
                  data-credential-type={credential.id}
                  data-credential-status={hasApplied ? 'applied' : 'available'}
                  sx={{ 
                    height: '100%', 
                    display: 'flex', 
                    flexDirection: 'column',
                    opacity: hasApplied ? 0.8 : 1
                  }}
                >
                  <Box 
                    sx={{ 
                      p: 3, 
                      display: 'flex', 
                      justifyContent: 'center',
                      bgcolor: 'primary.light',
                      color: 'white'
                    }}
                  >
                    <IconComponent sx={{ fontSize: 64 }} />
                  </Box>
                  <CardContent sx={{ flexGrow: 1 }}>
                    <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                      <Typography variant="h6" gutterBottom data-testid="credential-name">
                        {credential.name}
                      </Typography>
                      <Tooltip title={t('catalog.card.viewDetails')}>
                        <IconButton 
                          size="small" 
                          onClick={() => handleViewDetails(credential)}
                          data-testid="credential-details-btn"
                        >
                          <InfoIcon />
                        </IconButton>
                      </Tooltip>
                    </Box>
                    <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }} data-testid="credential-description">
                      {credential.description}
                    </Typography>
                    <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap', mb: 1 }}>
                      <Chip 
                        label={credential.category} 
                        size="small" 
                        variant="outlined" 
                        data-testid="credential-category"
                      />
                      <Chip 
                        icon={<PriceIcon />}
                        label={credential.processingFee ? `$${credential.processingFee}` : t('catalog.card.free')} 
                        size="small" 
                        color={credential.processingFee ? 'default' : 'success'}
                        data-testid="credential-fee"
                      />
                      {credential.format && (
                        <Chip label={credential.format} size="small" variant="outlined" color="info" />
                      )}
                    </Box>
                    {credential.worksWithLabel && (
                      <Typography variant="caption" color="text.secondary" sx={{ display: 'block', mb: 0.5 }}>
                        Works with: {credential.worksWithLabel}
                      </Typography>
                    )}
                    {getApplicationStatus(credential.id)}
                  </CardContent>
                  <CardActions sx={{ p: 2, pt: 0 }}>
                    <Button
                      fullWidth
                      variant={hasApplied ? 'outlined' : 'contained'}
                      disabled={isDisabled}
                      onClick={() => handleApply(credential)}
                      data-testid="apply-btn"
                    >
                      {actionLabel}
                    </Button>
                  </CardActions>
                </Card>
              </Grid>
            );
          })
        )}
      </Grid>

      {/* Credential Details Dialog */}
      <Dialog
        open={detailsOpen}
        onClose={() => setDetailsOpen(false)}
        maxWidth="sm"
        fullWidth
      >
        {selectedCredential && (
          <>
            <DialogTitle>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                {React.createElement(selectedCredential.icon || CredentialIcon)}
                {selectedCredential.name}
              </Box>
            </DialogTitle>
            <DialogContent>
              <Typography variant="body1" paragraph>
                {selectedCredential.description}
              </Typography>

              {(selectedCredential.format || selectedCredential.standard) && (
                <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap', mb: 2 }}>
                  {selectedCredential.standard && (
                    <Chip label={selectedCredential.standard} size="small" color="info" variant="outlined" />
                  )}
                  {selectedCredential.format && (
                    <Chip label={selectedCredential.format} size="small" variant="outlined" />
                  )}
                  {selectedCredential.worksWithLabel && (
                    <Chip label={`Works with: ${selectedCredential.worksWithLabel}`} size="small" variant="outlined" />
                  )}
                </Box>
              )}
              
              <Divider sx={{ my: 2 }} />
              
              <Typography variant="subtitle2" gutterBottom>
                {t('catalog.detailsDialog.processingTime')}
              </Typography>
              <Typography variant="body2" color="text.secondary" paragraph>
                {selectedCredential.processingTime}
              </Typography>
              
              <Typography variant="subtitle2" gutterBottom>
                {t('catalog.detailsDialog.processingFee')}
              </Typography>
              <Typography variant="body2" color="text.secondary" paragraph>
                {selectedCredential.processingFee 
                  ? `$${selectedCredential.processingFee}` 
                  : t('catalog.detailsDialog.noFee')}
              </Typography>
              
              <Typography variant="subtitle2" gutterBottom>
                {t('catalog.detailsDialog.requirements')}
              </Typography>
              <List dense>
                {(selectedCredential.requirements || []).map((req, index) => (
                  <ListItem key={index}>
                    <ListItemIcon>
                      <CheckIcon color="success" fontSize="small" />
                    </ListItemIcon>
                    <ListItemText primary={req} />
                  </ListItem>
                ))}
              </List>
              
              {selectedCredential.submissionInstructions && (
                <>
                  <Typography variant="subtitle2" gutterBottom sx={{ mt: 2 }}>
                    {t('catalog.detailsDialog.instructions')}
                  </Typography>
                  <Typography variant="body2" color="text.secondary" paragraph>
                    {selectedCredential.submissionInstructions}
                  </Typography>
                </>
              )}
              
              {(selectedCredential.requiredFields?.length > 0 || selectedCredential.customFields?.length > 0) && (
                <>
                  <Typography variant="subtitle2" gutterBottom sx={{ mt: 2 }}>
                    {t('catalog.detailsDialog.requiredInfo')}
                  </Typography>
                  <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5 }}>
                    {selectedCredential.requiredFields?.map((field) => (
                      <Chip key={field} label={field.replace(/_/g, ' ')} size="small" color="primary" />
                    ))}
                    {selectedCredential.customFields?.filter(f => f.validation?.required).map((field) => (
                      <Chip key={field.name} label={field.label} size="small" color="primary" />
                    ))}
                  </Box>
                </>
              )}
              
              {selectedCredential.vendorName && (
                <>
                  <Divider sx={{ my: 2 }} />
                  <Typography variant="caption" color="text.secondary">
                    {t('catalog.detailsDialog.offeredBy', { vendorName: selectedCredential.vendorName })}
                    {selectedCredential.templateVersion && ` • ${t('catalog.detailsDialog.templateVersion', { version: selectedCredential.templateVersion })}`}
                  </Typography>
                </>
              )}
            </DialogContent>
            <DialogActions>
              <Button onClick={() => setDetailsOpen(false)}>
                {t('actions.close', { ns: 'common' })}
              </Button>
              <Button
                variant="contained"
                onClick={() => {
                  setDetailsOpen(false);
                  handleApply(selectedCredential);
                }}
                disabled={
                  !isPreview &&
                  hasExistingApplication(selectedCredential.id) &&
                  !['approved', 'offered'].includes(appStatusInfo.statusByCredentialId[selectedCredential.id])
                }
              >
                {isPreview
                  ? t('catalog.card.actions.preview')
                  : ['approved', 'offered'].includes(appStatusInfo.statusByCredentialId[selectedCredential.id])
                    ? t('catalog.card.actions.claim', 'Claim')
                    : t('catalog.card.actions.apply')}
              </Button>
            </DialogActions>
          </>
        )}
      </Dialog>
    </Container>
  );
};

export default CredentialCatalog;

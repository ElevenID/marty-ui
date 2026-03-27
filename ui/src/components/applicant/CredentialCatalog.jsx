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
import { useNavigate } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { useAuth } from '../../hooks/useAuth';
import { usePreview } from '../../contexts/PreviewContext';
import { get } from '../../services/api';
import { getApplicantByUser } from '../../services/applicantApi';
import {
  buildCredentialApplicationNavigationState,
  extractApplicationStatusInfo,
  filterCredentialCatalogItems,
  getCredentialCatalogCategories,
  loadCredentialCatalogItems,
  loadExistingCredentialApplications,
} from '../../application/applications';

const CredentialCatalog = () => {
  const { t } = useTranslation('applicant');
  const navigate = useNavigate();
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
  const [existingApplications, setExistingApplications] = useState([]);
  const [appStatusInfo, setAppStatusInfo] = useState({ statusByCredentialId: {}, counts: { pending: 0, approved: 0, rejected: 0, credentialed: 0 } });

  const listCredentialTemplates = useCallback((currentOrganizationId) => {
    return get(`/v1/credential-templates?organization_id=${currentOrganizationId}&status=active`);
  }, []);

  const listApplicantApplications = useCallback((applicantId) => {
    return get(`/v1/applicants/profiles/${applicantId}/applications`);
  }, []);

  /**
   * Fetch credentials available to applicants of this organization
   */
  const fetchAvailableCredentials = useCallback(async () => {
    setLoading(true);
    try {
      const result = await loadCredentialCatalogItems({
        organizationId,
        organizationName,
        listCredentialTemplates,
      });
      setCredentials(result.credentials);
    } catch (error) {
      console.error('Failed to fetch credentials:', error);
      setCredentials([]);
    } finally {
      setLoading(false);
    }
  }, [organizationId, organizationName, listCredentialTemplates]);

  /**
   * Fetch applicant's existing applications (with status data)
   */
  const fetchExistingApplications = useCallback(async () => {
    try {
      const applicationIds = await loadExistingCredentialApplications({
        organizationId,
        userId: user?.user_id,
        getApplicantByUser,
        listApplicantApplications,
      });
      setExistingApplications(applicationIds);

      // Also fetch raw application data for status counts
      const applicant = await getApplicantByUser(user?.user_id);
      if (applicant?.id) {
        const data = await listApplicantApplications(applicant.id);
        const apps = Array.isArray(data) ? data : (data?.applications || []);
        setAppStatusInfo(extractApplicationStatusInfo(apps));
      }
    } catch (error) {
      console.error('Failed to fetch applications:', error);
    }
  }, [organizationId, user?.user_id, listApplicantApplications]);

  // Fetch data when component mounts or organizationId changes
  useEffect(() => {
    fetchAvailableCredentials();
    fetchExistingApplications();
  }, [fetchAvailableCredentials, fetchExistingApplications]);

  /**
   * Filter credentials based on search and category
   */
  const filteredCredentials = useMemo(() => {
    return filterCredentialCatalogItems(credentials, { searchTerm, categoryFilter });
  }, [credentials, searchTerm, categoryFilter]);

  /**
   * Handle credential application
   */
  const handleApply = (credential) => {
    const navigation = buildCredentialApplicationNavigationState(credential);
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
    if (status === 'rejected') {
      return <Chip label="Rejected" size="small" color="error" sx={{ mt: 1 }} />;
    }
    return (
      <Chip icon={<PendingIcon />} label={t('catalog.card.status.pending')} size="small" color="warning" sx={{ mt: 1 }} />
    );
  };

  const { counts } = appStatusInfo;
  const hasAnyApplications = counts.pending + counts.approved + counts.rejected + counts.credentialed > 0;

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
        {loading ? (
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
                      disabled={hasApplied}
                      onClick={() => handleApply(credential)}
                      data-testid="apply-btn"
                    >
                      {isPreview 
                        ? t('catalog.card.actions.preview') 
                        : (hasApplied ? t('catalog.card.status.pending') : t('catalog.card.actions.apply'))}
                    </Button>
                  </CardActions>
                </Card>
              </Grid>
            );
          })
        )}
      </Grid>

      {/* Multi-standard explanation */}
      <Paper variant="outlined" sx={{ p: 3, mt: 4, mb: 3 }}>
        <Stack direction="row" spacing={1} alignItems="center" sx={{ mb: 1.5 }}>
          <VerifiedIcon color="primary" />
          <Typography variant="h6">Why multiple credential types?</Typography>
        </Stack>
        <Typography variant="body2" color="text.secondary" paragraph sx={{ mb: 2 }}>
          Different wallets support different standards. ElevenID supports both so you can choose
          the format that works best for your device and use case.
        </Typography>
        <Grid container spacing={2}>
          <Grid item xs={12} sm={6}>
            <Box sx={{ p: 2, borderRadius: 1, border: 1, borderColor: 'divider' }}>
              <Typography variant="subtitle2" gutterBottom>Open Badge / VC (W3C)</Typography>
              <Typography variant="caption" color="text.secondary" display="block">
                Use for: Web login, professional credentials
              </Typography>
              <Typography variant="caption" color="text.secondary" display="block">
                Format: SD-JWT Verifiable Credential
              </Typography>
              <Typography variant="caption" color="text.secondary" display="block">
                Compatible with: Web & VC wallets
              </Typography>
            </Box>
          </Grid>
          <Grid item xs={12} sm={6}>
            <Box sx={{ p: 2, borderRadius: 1, border: 1, borderColor: 'divider' }}>
              <Typography variant="subtitle2" gutterBottom>mDoc (ISO 18013-5)</Typography>
              <Typography variant="caption" color="text.secondary" display="block">
                Use for: Mobile-first verification, in-person ID
              </Typography>
              <Typography variant="caption" color="text.secondary" display="block">
                Format: ISO mDoc (CBOR)
              </Typography>
              <Typography variant="caption" color="text.secondary" display="block">
                Compatible with: Mobile wallets (Apple / Google)
              </Typography>
            </Box>
          </Grid>
        </Grid>
      </Paper>

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
                disabled={hasExistingApplication(selectedCredential.id)}
              >
                {isPreview ? t('catalog.card.actions.preview') : t('catalog.card.actions.apply')}
              </Button>
            </DialogActions>
          </>
        )}
      </Dialog>
    </Container>
  );
};

export default CredentialCatalog;

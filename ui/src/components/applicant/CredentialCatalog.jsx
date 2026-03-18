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
  Divider
} from '@mui/material';
import {
  Search as SearchIcon,
  FilterList as FilterIcon,
  CardMembership as CredentialIcon,
  Info as InfoIcon,
  CheckCircle as CheckIcon,
  Schedule as PendingIcon,
  AttachMoney as PriceIcon,
  Business as BusinessIcon
} from '@mui/icons-material';
import { useNavigate } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { useAuth } from '../../hooks/useAuth';
import { usePreview } from '../../contexts/PreviewContext';
import { get } from '../../services/api';
import { getApplicantByUser } from '../../services/applicantApi';
import {
  buildCredentialApplicationNavigationState,
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
   * Fetch applicant's existing applications
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
   * Get application status chip
   */
  const getApplicationStatus = (credentialId) => {
    if (hasExistingApplication(credentialId)) {
      return (
        <Chip
          icon={<PendingIcon />}
          label={t('catalog.card.status.pending')}
          size="small"
          color="warning"
          sx={{ mt: 1 }}
        />
      );
    }
    return null;
  };

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
                    </Box>
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

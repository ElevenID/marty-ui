/**
 * CredentialCatalog Component
 * 
 * Displays available credentials for applicants to apply for.
 * Credentials are filtered based on the vendor organization's configuration.
 */

import React, { useState, useEffect, useMemo } from 'react';
import {
  Container,
  Grid,
  Paper,
  Typography,
  Box,
  Card,
  CardContent,
  CardMedia,
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
  Flight as PassportIcon,
  DirectionsCar as DLIcon,
  Badge as BadgeIcon,
  Info as InfoIcon,
  CheckCircle as CheckIcon,
  Schedule as PendingIcon,
  AttachMoney as PriceIcon
} from '@mui/icons-material';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../../hooks/useAuth';

const API_URL = process.env.REACT_APP_API_URL || '';

// Credential types configuration
const CREDENTIAL_TYPES = {
  passport: {
    description: 'ICAO 9303 compliant digital travel credential with NFC capability',
    icon: PassportIcon,
    category: 'travel',
    processingTime: '5-10 business days',
    requirements: ['Government-issued ID', 'Proof of citizenship', 'Biometric photo']
  },
  drivers_license: {
    description: 'ISO/IEC 18013-5 compliant mobile driving license',
    icon: DLIcon,
    category: 'identity',
    processingTime: '3-5 business days',
    requirements: ['Current driver\'s license', 'Proof of residence', 'Biometric photo']
  },
  travel_visa: {
    description: 'Digitally issued travel visa credential for approved applicants',
    icon: PassportIcon,
    category: 'travel',
    processingTime: '5-10 business days',
    requirements: ['Valid passport', 'Proof of travel intent']
  },
  access_badge: {
    description: 'Corporate access badge credential for authorized personnel',
    icon: BadgeIcon,
    category: 'enterprise',
    processingTime: '1-2 business days',
    requirements: ['Employment verification', 'Photo ID']
  },
  national_id: {
    description: 'National identity credential for verified applicants',
    icon: CredentialIcon,
    category: 'identity',
    processingTime: '5-10 business days',
    requirements: ['Government-issued ID', 'Biometric photo']
  },
  dtc: {
    description: 'Digital Travel Credential per ICAO DTC specification',
    icon: PassportIcon,
    category: 'travel',
    processingTime: '3-5 business days',
    requirements: ['Valid passport', 'Biometric photo']
  },
  open_badge: {
    description: 'Open Badge credential aligned with the Open Badges standard',
    icon: BadgeIcon,
    category: 'enterprise',
    processingTime: '1-2 business days',
    requirements: ['Issuer approval']
  }
};

const CATEGORIES = [
  { value: 'all', label: 'All Categories' },
  { value: 'travel', label: 'Travel Documents' },
  { value: 'identity', label: 'Identity Documents' },
  { value: 'enterprise', label: 'Enterprise Credentials' }
];

const CredentialCatalog = () => {
  const navigate = useNavigate();
  const { organizationId, organizationName, user } = useAuth();
  
  // State
  const [credentials, setCredentials] = useState([]);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');
  const [categoryFilter, setCategoryFilter] = useState('all');
  const [selectedCredential, setSelectedCredential] = useState(null);
  const [detailsOpen, setDetailsOpen] = useState(false);
  const [existingApplications, setExistingApplications] = useState([]);

  useEffect(() => {
    fetchAvailableCredentials();
    fetchExistingApplications();
  }, [organizationId]);

  /**
   * Fetch credentials available to applicants of this organization
   */
  const fetchAvailableCredentials = async () => {
    setLoading(true);
    try {
      const response = await fetch(
        `${API_URL}/api/organizations/${organizationId}/credential-types`,
        { credentials: 'include' }
      );
      if (response.ok) {
        const data = await response.json();
        const configs = data.credential_types || [];
        
        // Filter to only published, non-system templates
        const publishedConfigs = configs.filter(
          (config) => config.is_published && !config.is_system_template && config.is_active
        );
        
        const mapped = publishedConfigs.map((config) => {
          // Use backend metadata instead of hardcoded CREDENTIAL_TYPES
          const meta = CREDENTIAL_TYPES[config.credential_type] || {};
          
          // Parse eligibility criteria into requirements array
          const requirements = config.eligibility_criteria
            ? config.eligibility_criteria.split('\n').filter(r => r.trim())
            : meta.requirements || [];
          
          return {
            id: config.id,
            credentialType: config.credential_type,
            name: config.display_name,
            // Use backend description, fallback to hardcoded if not available
            description: config.description || meta.description || config.display_name,
            icon: meta.icon || CredentialIcon,
            category: meta.category || 'identity',
            // Use backend processing time, fallback to hardcoded
            processingTime: config.estimated_processing_time || meta.processingTime || '3-5 business days',
            requirements: requirements,
            requiredFields: config.required_fields || [],
            optionalFields: config.optional_fields || [],
            customFields: config.custom_fields || [],
            eligibilityCriteria: config.eligibility_criteria,
            submissionInstructions: config.submission_instructions,
            processingFee: 0,
            available: config.is_active,
            vendorName: organizationName || 'Issuer',
            templateVersion: config.template_version,
            visibility: config.visibility,
          };
        });
        setCredentials(mapped);
      } else {
        console.warn('Credentials API not available');
        setCredentials([]);
      }
    } catch (error) {
      console.error('Failed to fetch credentials:', error);
      setCredentials([]);
    } finally {
      setLoading(false);
    }
  };

  /**
   * Fetch applicant's existing applications
   */
  const fetchExistingApplications = async () => {
    try {
      if (!organizationId || !user?.user_id) {
        return;
      }
      const applicantResponse = await fetch(`${API_URL}/api/applicants/by-user/${user?.user_id}`, {
        credentials: 'include',
      });
      if (!applicantResponse.ok) {
        return;
      }
      const applicant = await applicantResponse.json();
      if (!applicant?.id) {
        return;
      }
      const response = await fetch(`${API_URL}/api/applicants/${applicant.id}/applications`, {
        credentials: 'include',
      });
      if (!response.ok) {
        return;
      }
      const data = await response.json();
      const apps = Array.isArray(data) ? data : (data.applications || []);
      setExistingApplications(apps.map(app => app.credential_configuration_id).filter(Boolean));
    } catch (error) {
      console.error('Failed to fetch applications:', error);
    }
  };

  /**
   * Filter credentials based on search and category
   */
  const filteredCredentials = useMemo(() => {
    return credentials.filter(cred => {
      const matchesSearch = cred.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
                           cred.description.toLowerCase().includes(searchTerm.toLowerCase());
      const matchesCategory = categoryFilter === 'all' || cred.category === categoryFilter;
      return matchesSearch && matchesCategory;
    });
  }, [credentials, searchTerm, categoryFilter]);

  /**
   * Handle credential application
   */
  const handleApply = (credential) => {
    navigate(`/apply/${credential.id}`, {
      state: {
        credential,
      }
    });
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
          label="Application Pending"
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
      <Box sx={{ mb: 4 }}>
        <Typography variant="h4" component="h1" gutterBottom data-testid="catalog-title">
          <CredentialIcon sx={{ mr: 2, verticalAlign: 'middle' }} />
          Credential Catalog
        </Typography>
        <Typography variant="subtitle1" color="text.secondary">
          Browse and apply for available credentials
          {organizationName && ` from ${organizationName}`}
        </Typography>
      </Box>

      {/* Search and Filters */}
      <Paper sx={{ p: 2, mb: 3 }} data-testid="catalog-filters">
        <Grid container spacing={2} alignItems="center">
          <Grid item xs={12} md={6}>
            <TextField
              fullWidth
              placeholder="Search credentials..."
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
              <InputLabel>Category</InputLabel>
              <Select
                value={categoryFilter}
                label="Category"
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
              {filteredCredentials.length} credential{filteredCredentials.length !== 1 ? 's' : ''} found
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
              No credentials match your search criteria. Try adjusting your filters.
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
                      <Tooltip title="View details">
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
                        label={credential.processingFee ? `$${credential.processingFee}` : 'Free'} 
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
                      {hasApplied ? 'Application Pending' : 'Apply Now'}
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
                Processing Time
              </Typography>
              <Typography variant="body2" color="text.secondary" paragraph>
                {selectedCredential.processingTime}
              </Typography>
              
              <Typography variant="subtitle2" gutterBottom>
                Processing Fee
              </Typography>
              <Typography variant="body2" color="text.secondary" paragraph>
                {selectedCredential.processingFee 
                  ? `$${selectedCredential.processingFee}` 
                  : 'No fee required'}
              </Typography>
              
              <Typography variant="subtitle2" gutterBottom>
                Requirements
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
                    Submission Instructions
                  </Typography>
                  <Typography variant="body2" color="text.secondary" paragraph>
                    {selectedCredential.submissionInstructions}
                  </Typography>
                </>
              )}
              
              {(selectedCredential.requiredFields?.length > 0 || selectedCredential.customFields?.length > 0) && (
                <>
                  <Typography variant="subtitle2" gutterBottom sx={{ mt: 2 }}>
                    Required Information
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
                    Offered by: {selectedCredential.vendorName}
                    {selectedCredential.templateVersion && ` • Template v${selectedCredential.templateVersion}`}
                  </Typography>
                </>
              )}
            </DialogContent>
            <DialogActions>
              <Button onClick={() => setDetailsOpen(false)}>
                Close
              </Button>
              <Button
                variant="contained"
                onClick={() => {
                  setDetailsOpen(false);
                  handleApply(selectedCredential);
                }}
                disabled={hasExistingApplication(selectedCredential.id)}
              >
                Apply Now
              </Button>
            </DialogActions>
          </>
        )}
      </Dialog>
    </Container>
  );
};

export default CredentialCatalog;

/**
 * Organization Settings Component
 * 
 * Allows organization administrators to view and update organization details:
 * - Organization name
 * - Logo URL
 * - Website URL
 * - Contact email
 * - View subscription tier and limits (readonly)
 */

import { useState, useEffect, useCallback } from 'react';
import { useTranslation } from 'react-i18next';
import {
  Box,
  Paper,
  Typography,
  TextField,
  Button,
  Alert,
  CircularProgress,
  Grid,
  Divider,
  Card,
  CardContent,
  Chip,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableRow,
} from '@mui/material';
import SaveIcon from '@mui/icons-material/Save';
import BusinessIcon from '@mui/icons-material/Business';
import { useAuth } from '../../hooks/useAuth';
import {
  getOrganization,
  updateOrganization,
  getOrganizationSubscription,
  getErrorMessage,
} from '../../services/organizationsApi';

/**
 * Organization Settings Component
 */
export default function OrganizationSettings() {
  const { t } = useTranslation('vendor');
  const { organizationId } = useAuth();
  
  // Organization details state
  const [organizationName, setOrganizationName] = useState('');
  const [logoUrl, setLogoUrl] = useState('');
  const [websiteUrl, setWebsiteUrl] = useState('');
  const [contactEmail, setContactEmail] = useState('');
  const [slug, setSlug] = useState('');
  const [createdAt, setCreatedAt] = useState('');
  
  // Subscription state
  const [subscription, setSubscription] = useState(null);
  
  // UI state
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState(null);
  const [successMessage, setSuccessMessage] = useState('');

  useEffect(() => {
    if (organizationId) {
      loadOrganizationData();
    }
  }, [organizationId, loadOrganizationData]);

  const loadOrganizationData = useCallback(async () => {
    setLoading(true);
    setError(null);
    
    try {
      // Load organization details
      const orgData = await getOrganization(organizationId);
      setOrganizationName(orgData.name || '');
      setSlug(orgData.slug || '');
      setCreatedAt(orgData.created_at || '');
      
      // Load settings
      const settings = orgData.settings || {};
      setLogoUrl(settings.logo_url || '');
      setWebsiteUrl(settings.website_url || '');
      setContactEmail(settings.contact_email || '');
      
      // Load subscription details
      try {
        const subData = await getOrganizationSubscription(organizationId);
        setSubscription(subData);
      } catch (err) {
        // Subscription might not exist yet, that's okay
        console.warn('Could not load subscription:', err);
      }
    } catch (err) {
      setError(getErrorMessage(err));
    } finally {
      setLoading(false);
    }
  }, [organizationId]);

  const handleSave = async () => {
    if (!organizationName.trim()) {
      setError(t('organizationSettings.nameRequired'));
      return;
    }

    setSaving(true);
    setError(null);
    setSuccessMessage('');

    try {
      await updateOrganization(organizationId, {
        name: organizationName.trim(),
        logoUrl: logoUrl.trim(),
        websiteUrl: websiteUrl.trim(),
        contactEmail: contactEmail.trim(),
      });
      
      setSuccessMessage(t('organizationSettings.updateSuccess'));
    } catch (err) {
      setError(getErrorMessage(err));
    } finally {
      setSaving(false);
    }
  };

  if (loading) {
    return (
      <Box sx={{ display: 'flex', justifyContent: 'center', p: 4 }}>
        <CircularProgress />
      </Box>
    );
  }

  return (
    <Box data-testid="organization-settings">
      {/* Header */}
      <Box sx={{ mb: 3 }}>
        <Typography variant="h5" gutterBottom>
          <BusinessIcon sx={{ verticalAlign: 'middle', mr: 1 }} />
          {t('organizationSettings.title')}
        </Typography>
        <Typography variant="body2" color="text.secondary">
          {t('organizationSettings.description')}
        </Typography>
      </Box>

      {/* Error Alert */}
      {error && (
        <Alert severity="error" onClose={() => setError(null)} sx={{ mb: 3 }}>
          {error}
        </Alert>
      )}

      {/* Success Alert */}
      {successMessage && (
        <Alert severity="success" onClose={() => setSuccessMessage('')} sx={{ mb: 3 }}>
          {successMessage}
        </Alert>
      )}

      <Grid container spacing={3}>
        {/* Organization Details */}
        <Grid item xs={12} md={8}>
          <Paper sx={{ p: 3 }}>
            <Typography variant="h6" gutterBottom>
              {t('organizationSettings.details.title')}
            </Typography>
            <Divider sx={{ mb: 3 }} />

            <Box sx={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
              <TextField
                label={t('organizationSettings.details.nameLabel')}
                fullWidth
                value={organizationName}
                onChange={(e) => setOrganizationName(e.target.value)}
                required
                helperText={t('organizationSettings.details.nameHelper')}
              />

              <TextField
                label={t('organizationSettings.details.slugLabel')}
                fullWidth
                value={slug}
                disabled
                helperText={t('organizationSettings.details.slugHelper')}
              />

              <TextField
                label={t('organizationSettings.details.logoUrlLabel')}
                fullWidth
                value={logoUrl}
                onChange={(e) => setLogoUrl(e.target.value)}
                placeholder={t('organizationSettings.details.logoUrlPlaceholder')}
                helperText={t('organizationSettings.details.logoUrlHelper')}
              />

              <TextField
                label={t('organizationSettings.details.websiteUrlLabel')}
                fullWidth
                value={websiteUrl}
                onChange={(e) => setWebsiteUrl(e.target.value)}
                placeholder={t('organizationSettings.details.websiteUrlPlaceholder')}
                helperText={t('organizationSettings.details.websiteUrlHelper')}
              />

              <TextField
                label={t('organizationSettings.details.contactEmailLabel')}
                fullWidth
                type="email"
                value={contactEmail}
                onChange={(e) => setContactEmail(e.target.value)}
                placeholder={t('organizationSettings.details.contactEmailPlaceholder')}
                helperText={t('organizationSettings.details.contactEmailHelper')}
              />

              <Box sx={{ display: 'flex', justifyContent: 'flex-end', gap: 2 }}>
                <Button
                  variant="outlined"
                  onClick={loadOrganizationData}
                  disabled={saving}
                >
                  {t('organizationSettings.details.cancelButton')}
                </Button>
                <Button
                  variant="contained"
                  startIcon={<SaveIcon />}
                  onClick={handleSave}
                  disabled={saving || !organizationName.trim()}
                >
                  {saving ? t('organizationSettings.details.saving') : t('organizationSettings.details.saveButton')}
                </Button>
              </Box>
            </Box>
          </Paper>
        </Grid>

        {/* Subscription Info */}
        <Grid item xs={12} md={4}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                {t('organizationSettings.subscription.title')}
              </Typography>
              <Divider sx={{ mb: 2 }} />

              {subscription ? (
                <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
                  <Box>
                    <Typography variant="body2" color="text.secondary">
                      {t('organizationSettings.subscription.currentPlan')}
                    </Typography>
                    <Chip
                      label={subscription.tier || t('organizationSettings.subscription.free')}
                      color="primary"
                      sx={{ mt: 0.5 }}
                    />
                  </Box>

                  <Box>
                    <Typography variant="body2" color="text.secondary" gutterBottom>
                      {t('organizationSettings.subscription.status')}
                    </Typography>
                    <Chip
                      label={subscription.status || t('organizationSettings.subscription.active')}
                      color={subscription.status === 'active' ? 'success' : 'default'}
                      size="small"
                    />
                  </Box>

                  {subscription.limits && (
                    <Box>
                      <Typography variant="body2" color="text.secondary" gutterBottom>
                        {t('organizationSettings.subscription.limits')}
                      </Typography>
                      <TableContainer>
                        <Table size="small">
                          <TableBody>
                            {Object.entries(subscription.limits).map(([key, value]) => (
                              <TableRow key={key}>
                                <TableCell sx={{ border: 'none', py: 0.5, pl: 0 }}>
                                  <Typography variant="caption">
                                    {key.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())}
                                  </Typography>
                                </TableCell>
                                <TableCell sx={{ border: 'none', py: 0.5, pr: 0 }} align="right">
                                  <Typography variant="caption" fontWeight="bold">
                                    {typeof value === 'boolean' ? (value ? 'Yes' : 'No') : value}
                                  </Typography>
                                </TableCell>
                              </TableRow>
                            ))}
                          </TableBody>
                        </Table>
                      </TableContainer>
                    </Box>
                  )}

                  {(subscription.current_period_start || subscription.current_period_end) && (
                    <Box>
                      <Typography variant="body2" color="text.secondary" gutterBottom>
                        {t('organizationSettings.subscription.billingPeriod')}
                      </Typography>
                      <Typography variant="caption">
                        {subscription.current_period_start &&
                          new Date(subscription.current_period_start).toLocaleDateString()}
                        {' - '}
                        {subscription.current_period_end &&
                          new Date(subscription.current_period_end).toLocaleDateString()}
                      </Typography>
                    </Box>
                  )}
                </Box>
              ) : (
                <Alert severity="info">
                  {t('organizationSettings.subscription.noSubscription')}
                </Alert>
              )}
            </CardContent>
          </Card>

          {/* Organization Info */}
          <Card sx={{ mt: 2 }}>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                {t('organizationSettings.info.title')}
              </Typography>
              <Divider sx={{ mb: 2 }} />

              <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
                <Box>
                  <Typography variant="body2" color="text.secondary">
                    {t('organizationSettings.info.created')}
                  </Typography>
                  <Typography variant="body2">
                    {createdAt ? new Date(createdAt).toLocaleDateString() : t('organizationSettings.info.notAvailable')}
                  </Typography>
                </Box>

                <Box>
                  <Typography variant="body2" color="text.secondary">
                    {t('organizationSettings.info.organizationId')}
                  </Typography>
                  <Typography variant="caption" sx={{ fontFamily: 'monospace', wordBreak: 'break-all' }}>
                    {organizationId}
                  </Typography>
                </Box>
              </Box>
            </CardContent>
          </Card>
        </Grid>
      </Grid>
    </Box>
  );
}

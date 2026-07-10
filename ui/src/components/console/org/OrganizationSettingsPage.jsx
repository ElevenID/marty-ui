/**
 * Organization Settings Page
 * 
 * Organization profile and configuration.
 */

import { useState, useEffect } from 'react';
import { useTranslation } from 'react-i18next';
import {
  Box,
  Paper,
  Typography,
  TextField,
  Button,
  Grid,
  Alert,
  LinearProgress,
  Avatar,
  Card,
  CardContent,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Chip,
  FormHelperText,
  Switch,
  FormControlLabel,
} from '@mui/material';
import EditIcon from '@mui/icons-material/Edit';
import SaveIcon from '@mui/icons-material/Save';
import BusinessIcon from '@mui/icons-material/Business';
import AddIcon from '@mui/icons-material/Add';

import { ResourcePage } from '../../common';
import { useAuth } from '../../../hooks/useAuth';
import { useConsole } from '../../../contexts/ConsoleContext';
import OrgDefaultsSection from './OrgDefaultsSection';
import { loadOrgSettings, saveOrgSettings } from '../../../application/orgSettings';
import { listRoles } from '../../../services/rbacApi';

/**
 * Get organization tabs with translations
 */
const getOrgTabs = (t) => [
  { label: t('org.tabs.organization'), path: '/console/org/settings' },
  { label: t('org.tabs.team'), path: '/console/org/team' },
  { label: t('org.tabs.apiKeys', 'API Keys'), path: '/console/org/api-keys' },
  { label: t('org.tabs.webhooks'), path: '/console/org/webhooks' },
];

/**
 * Get breadcrumbs with translations
 */
const getBreadcrumbs = (t) => [
  { label: t('org.breadcrumbs.console'), path: '/console' },
  { label: t('org.breadcrumbs.org'), path: '/console/org' },
  { label: t('org.breadcrumbs.organization'), path: '/console/org/settings' },
];

function OrganizationSettingsPage() {
  const { t } = useTranslation('console');
  const { organizationId, organizationName } = useAuth();
  const { activeOrgId } = useConsole();
  const effectiveOrgId = activeOrgId || organizationId;
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState(null);
  const [success, setSuccess] = useState(false);
  const [editMode, setEditMode] = useState(false);
  const [availableRoles, setAvailableRoles] = useState([]);
  const [roleLoadError, setRoleLoadError] = useState(null);
  const [org, setOrg] = useState({
    name: '',
    displayName: '',
    description: '',
    website: '',
    contactEmail: '',
    address: '',
    country: '',
    // Email domain settings
    isDiscoverable: false,
    membershipMode: 'invite_only',
    allowedEmailDomains: [],
    domainJoinPolicy: 'approval',
    defaultRole: 'applicant',
    // Device security settings
    requireDeviceRegistration: false,
    allowPushNotifications: true,
    deviceRegistrationPrompt: 'first_action',
  });
  const [newDomain, setNewDomain] = useState('');

  useEffect(() => {
    const loadOrg = async () => {
      try {
        setRoleLoadError(null);
        const [{ org: loaded, error: loadError }, rolesResult] = await Promise.all([
          loadOrgSettings({ organizationName }),
          effectiveOrgId
            ? listRoles(effectiveOrgId).then(
                (rolesResponse) => ({ status: 'fulfilled', value: rolesResponse }),
                (rolesError) => ({ status: 'rejected', reason: rolesError }),
              )
            : Promise.resolve({ status: 'fulfilled', value: [] }),
        ]);
        if (loadError) throw new Error(loadError);
        const rolesResponse = rolesResult.status === 'fulfilled' ? rolesResult.value : [];
        const roles = (rolesResponse?.roles || rolesResponse || []).filter((role) => role.name !== 'owner');
        setAvailableRoles(roles);
        if (rolesResult.status === 'rejected') {
          setRoleLoadError(rolesResult.reason);
        }
        setOrg(loaded);
      } catch (err) {
        setError(t('org.settings.errorLoading'));
        console.error(err);
      } finally {
        setLoading(false);
      }
    };
    loadOrg();
  }, [effectiveOrgId, organizationName, t]);

  const handleSave = async () => {
    setSaving(true);
    setError(null);
    try {
      const { error: saveError } = await saveOrgSettings({ org });
      if (saveError) throw new Error(saveError);
      setSuccess(true);
      setEditMode(false);
      setTimeout(() => setSuccess(false), 3000);
    } catch (err) {
      setError(err.message || t('org.settings.errorSaving'));
      console.error(err);
    } finally {
      setSaving(false);
    }
  };

  const handleChange = (field) => (event) => {
    setOrg((prev) => ({ ...prev, [field]: event.target.value }));
  };
  
  const handleAddDomain = () => {
    if (newDomain.trim() && !org.allowedEmailDomains.includes(newDomain.trim().toLowerCase())) {
      setOrg(prev => ({
        ...prev,
        allowedEmailDomains: [...prev.allowedEmailDomains, newDomain.trim().toLowerCase()],
      }));
      setNewDomain('');
    }
  };
  
  const handleRemoveDomain = (domain) => {
    setOrg(prev => ({
      ...prev,
      allowedEmailDomains: prev.allowedEmailDomains.filter(d => d !== domain),
    }));
  };

  if (loading) {
    return (
      <ResourcePage
        title={t('org.title')}
        tabs={getOrgTabs(t)}
        breadcrumbs={getBreadcrumbs(t)}
      >
        <LinearProgress />
      </ResourcePage>
    );
  }

  return (
    <ResourcePage
      title={t('org.title')}
      description={t('org.settings.description')}
      tabs={getOrgTabs(t)}
      breadcrumbs={getBreadcrumbs(t)}
      actions={
        editMode ? (
          <Box sx={{ display: 'flex', gap: 1 }}>
            <Button variant="outlined" onClick={() => setEditMode(false)}>
              {t('actions.cancel', { ns: 'common' })}
            </Button>
            <Button
              variant="contained"
              startIcon={<SaveIcon />}
              onClick={handleSave}
              disabled={saving}
            >
              {saving ? t('org.settings.saving') : t('org.settings.saveChanges')}
            </Button>
          </Box>
        ) : (
          <Button
            variant="outlined"
            startIcon={<EditIcon />}
            onClick={() => setEditMode(true)}
          >
            {t('org.settings.editMode')}
          </Button>
        )
      }
    >
      {error && (
        <Alert severity="error" sx={{ mb: 3 }}>
          {error}
        </Alert>
      )}

      {success && (
        <Alert severity="success" sx={{ mb: 3 }}>
          {t('org.settings.successMessage')}
        </Alert>
      )}
      {roleLoadError && (
        <Alert severity="warning" sx={{ mb: 3 }}>
          {roleLoadError?.message || t('org.settings.membership.rolesLoadFailed', 'Organization roles could not be loaded. Default role settings are unavailable until this is retried.')}
        </Alert>
      )}

      {/* Organization Header */}
      <Card sx={{ mb: 3 }}>
        <CardContent>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
            <Avatar sx={{ width: 64, height: 64, bgcolor: 'primary.main' }}>
              <BusinessIcon sx={{ fontSize: 32 }} />
            </Avatar>
            <Box>
              <Typography variant="h5">{org.displayName}</Typography>
              <Typography variant="body2" color="text.secondary">
                {t('org.settings.organizationId')}: {organizationId || 'org-12345'}
              </Typography>
            </Box>
          </Box>
        </CardContent>
      </Card>

      {/* Basic Information */}
      <Paper sx={{ p: 3, mb: 3 }}>
        <Typography variant="h6" gutterBottom>
          {t('org.settings.profile.title')}
        </Typography>
        <Grid container spacing={3}>
          <Grid item xs={12} sm={6}>
            <TextField
              fullWidth
              label={t('org.settings.profile.name')}
              value={org.name}
              onChange={handleChange('name')}
              disabled={!editMode}
            />
          </Grid>
          <Grid item xs={12} sm={6}>
            <TextField
              fullWidth
              label={t('org.settings.profile.displayName')}
              value={org.displayName}
              onChange={handleChange('displayName')}
              disabled={!editMode}
            />
          </Grid>
          <Grid item xs={12}>
            <TextField
              fullWidth
              label={t('org.settings.profile.description')}
              value={org.description}
              onChange={handleChange('description')}
              disabled={!editMode}
              multiline
              rows={2}
            />
          </Grid>
        </Grid>
      </Paper>

      {/* Contact Information */}
      <Paper sx={{ p: 3, mb: 3 }}>
        <Typography variant="h6" gutterBottom>
          {t('org.settings.profile.contactInfo')}
        </Typography>
        <Grid container spacing={3}>
          <Grid item xs={12} sm={6}>
            <TextField
              fullWidth
              label={t('org.settings.profile.website')}
              value={org.website}
              onChange={handleChange('website')}
              disabled={!editMode}
            />
          </Grid>
          <Grid item xs={12} sm={6}>
            <TextField
              fullWidth
              label={t('org.settings.profile.contactEmail')}
              value={org.contactEmail}
              onChange={handleChange('contactEmail')}
              disabled={!editMode}
            />
          </Grid>
          <Grid item xs={12} sm={8}>
            <TextField
              fullWidth
              label={t('org.settings.profile.address')}
              value={org.address}
              onChange={handleChange('address')}
              disabled={!editMode}
            />
          </Grid>
          <Grid item xs={12} sm={4}>
            <TextField
              fullWidth
              label={t('org.settings.profile.country')}
              value={org.country}
              onChange={handleChange('country')}
              disabled={!editMode}
            />
          </Grid>
        </Grid>
      </Paper>

      {/* Organization Defaults */}
      <OrgDefaultsSection />

      {/* Danger Zone */}
      <Paper sx={{ p: 3, mb: 3 }}>        <Typography variant="h6" gutterBottom>
          {t('org.settings.membership.title')}
        </Typography>
        <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
          {t('org.settings.membership.description')}
        </Typography>
        
        <Grid container spacing={3}>
          <Grid item xs={12}>
            <FormControlLabel
              control={
                <Switch
                  checked={org.isDiscoverable}
                  onChange={(e) => setOrg(prev => ({ ...prev, isDiscoverable: e.target.checked }))}
                  disabled={!editMode}
                />
              }
              label={t('org.settings.membership.discoverable')}
            />
            <FormHelperText>
              {t('org.settings.membership.discoverableHelp')}
            </FormHelperText>
          </Grid>
          
          <Grid item xs={12}>
            <Typography variant="subtitle2" gutterBottom>
              {t('org.settings.membership.domains')}
            </Typography>
            <Box sx={{ display: 'flex', gap: 1, mb: 1, flexWrap: 'wrap' }}>
              {org.allowedEmailDomains.map((domain) => (
                <Chip
                  key={domain}
                  label={domain}
                  onDelete={editMode ? () => handleRemoveDomain(domain) : undefined}
                  color="primary"
                  variant="outlined"
                />
              ))}
            </Box>
            {editMode && (
              <Box sx={{ display: 'flex', gap: 1 }}>
                <TextField
                  size="small"
                  placeholder={t('org.settings.membership.domainPlaceholder')}
                  value={newDomain}
                  onChange={(e) => setNewDomain(e.target.value)}
                  onKeyPress={(e) => e.key === 'Enter' && handleAddDomain()}
                  fullWidth
                />
                <Button
                  variant="outlined"
                  startIcon={<AddIcon />}
                  onClick={handleAddDomain}
                  disabled={!newDomain.trim()}
                >
                  {t('org.settings.membership.addDomain')}
                </Button>
              </Box>
            )}
            <FormHelperText>
              {t('org.settings.membership.domainsHelp')}
            </FormHelperText>
          </Grid>
          
          <Grid item xs={12} sm={6}>
            <FormControl fullWidth disabled={!editMode}>
              <InputLabel>{t('org.settings.membership.joinPolicy')}</InputLabel>
              <Select
                value={org.domainJoinPolicy}
                label={t('org.settings.membership.joinPolicy')}
                onChange={(e) => setOrg(prev => ({ ...prev, domainJoinPolicy: e.target.value }))}
              >
                <MenuItem value="auto">{t('org.settings.membership.modes.auto')}</MenuItem>
                <MenuItem value="approval">{t('org.settings.membership.modes.approval')}</MenuItem>
                <MenuItem value="closed">{t('org.settings.membership.modes.closed')}</MenuItem>
              </Select>
              <FormHelperText>
                {org.domainJoinPolicy === 'auto' && t('org.settings.membership.joinPolicies.auto')}
                {org.domainJoinPolicy === 'approval' && t('org.settings.membership.joinPolicies.approval')}
                {org.domainJoinPolicy === 'closed' && t('org.settings.membership.joinPolicies.closed')}
              </FormHelperText>
            </FormControl>
          </Grid>
          
          <Grid item xs={12} sm={6}>
            <FormControl fullWidth disabled={!editMode || Boolean(roleLoadError)}>
              <InputLabel>{t('org.settings.membership.defaultRole')}</InputLabel>
              <Select
                value={org.defaultRole}
                label={t('org.settings.membership.defaultRole')}
                onChange={(e) => setOrg(prev => ({ ...prev, defaultRole: e.target.value }))}
              >
                {availableRoles.map((role) => (
                  <MenuItem key={role.id} value={role.name}>
                    {role.display_name || role.name}
                  </MenuItem>
                ))}
              </Select>
              <FormHelperText>
                {t('org.settings.membership.defaultRoleHelp')}
              </FormHelperText>
            </FormControl>
          </Grid>
        </Grid>
      </Paper>

      {/* Device Security Settings */}
      <Paper sx={{ p: 3, mb: 3 }}>
        <Typography variant="h6" gutterBottom>
          {t('org.settings.devices.title')}
        </Typography>
        <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
          {t('org.settings.devices.description')}
        </Typography>
        
        <Grid container spacing={3}>
          <Grid item xs={12}>
            <FormControlLabel
              control={
                <Switch
                  checked={org.requireDeviceRegistration}
                  onChange={(e) => setOrg(prev => ({ ...prev, requireDeviceRegistration: e.target.checked }))}
                  disabled={!editMode}
                />
              }
              label={t('org.settings.devices.requireRegistration')}
            />
            <Typography variant="caption" display="block" color="text.secondary" sx={{ ml: 4 }}>
              {t('org.settings.devices.requireRegistrationHelp')}
            </Typography>
          </Grid>
          
          <Grid item xs={12}>
            <FormControlLabel
              control={
                <Switch
                  checked={org.allowPushNotifications}
                  onChange={(e) => setOrg(prev => ({ ...prev, allowPushNotifications: e.target.checked }))}
                  disabled={!editMode}
                />
              }
              label={t('org.settings.devices.allowPushNotifications')}
            />
            <Typography variant="caption" display="block" color="text.secondary" sx={{ ml: 4 }}>
              {t('org.settings.devices.pushNotificationsHelp')}
            </Typography>
          </Grid>
          
          <Grid item xs={12} sm={6}>
            <FormControl fullWidth disabled={!editMode}>
              <InputLabel>{t('org.settings.devices.registrationPrompt')}</InputLabel>
              <Select
                value={org.deviceRegistrationPrompt}
                label={t('org.settings.devices.registrationPrompt')}
                onChange={(e) => setOrg(prev => ({ ...prev, deviceRegistrationPrompt: e.target.value }))}
              >
                <MenuItem value="onboarding">{t('org.settings.devices.prompts.onboarding')}</MenuItem>
                <MenuItem value="first_action">{t('org.settings.devices.prompts.firstAction')}</MenuItem>
                <MenuItem value="never">{t('org.settings.devices.prompts.never')}</MenuItem>
              </Select>
              <FormHelperText>
                {org.deviceRegistrationPrompt === 'onboarding' && t('org.settings.devices.promptHelp.onboarding')}
                {org.deviceRegistrationPrompt === 'first_action' && t('org.settings.devices.promptHelp.firstAction')}
                {org.deviceRegistrationPrompt === 'never' && t('org.settings.devices.promptHelp.never')}
              </FormHelperText>
            </FormControl>
          </Grid>
        </Grid>
      </Paper>

      {/* Danger Zone */}
      <Paper sx={{ p: 3, border: 1, borderColor: 'error.main' }}>
        <Typography variant="h6" color="error" gutterBottom>
          {t('org.settings.danger.title')}
        </Typography>
        <Typography variant="body2" color="text.secondary" paragraph>
          {t('org.settings.danger.description')}
        </Typography>
        <Button variant="outlined" color="error" disabled>
          {t('org.settings.danger.deleteOrganization')}
        </Button>
      </Paper>
    </ResourcePage>
  );
}

export default OrganizationSettingsPage;

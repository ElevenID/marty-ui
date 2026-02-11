/**
 * Organization Settings Page
 * 
 * Organization profile and configuration.
 */

import { useState, useEffect } from 'react';
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
// import { Link } from 'react-router-dom';

import { ResourcePage } from '../../common';
import { useAuth } from '../../../hooks/useAuth';
import OrgDefaultsSection from './OrgDefaultsSection';

const ORG_TABS = [
  { label: 'Organization', path: '/console/org/settings' },
  { label: 'Team', path: '/console/org/team' },
  { label: 'Webhooks', path: '/console/org/webhooks' },
];

const BREADCRUMBS = [
  { label: 'Console', path: '/console' },
  { label: 'Org', path: '/console/org' },
  { label: 'Organization', path: '/console/org/settings' },
];

function OrganizationSettingsPage() {
  const { organizationId, organizationName } = useAuth();
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState(null);
  const [success, setSuccess] = useState(false);
  const [editMode, setEditMode] = useState(false);
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
    defaultRole: 'member',
    // Device security settings
    requireDeviceRegistration: false,
    allowPushNotifications: true,
    deviceRegistrationPrompt: 'first_action',
  });
  const [newDomain, setNewDomain] = useState('');

  useEffect(() => {
    // Load organization settings from API
    const loadOrg = async () => {
      try {
        const response = await fetch('/api/onboarding/org-settings', {
          credentials: 'include',
        });
        
        if (response.ok) {
          const data = await response.json();
          setOrg({
            name: data.organization_name || 'My Organization',
            displayName: data.organization_name || 'My Organization',
            description: 'Digital identity services provider',
            website: 'https://example.com',
            contactEmail: 'contact@example.com',
            address: '123 Identity Street',
            country: 'Germany',
            isDiscoverable: data.is_discoverable || false,
            membershipMode: data.membership_mode || 'invite_only',
            allowedEmailDomains: data.allowed_email_domains || [],
            domainJoinPolicy: data.domain_join_policy || 'approval',
            defaultRole: data.default_role || 'member',
            requireDeviceRegistration: data.require_device_registration || false,
            allowPushNotifications: data.allow_push_notifications !== false,
            deviceRegistrationPrompt: data.device_registration_prompt || 'first_action',
          });
        } else {
          // Fallback to mock data
          setOrg({
            name: organizationName || 'My Organization',
            displayName: organizationName || 'My Organization',
            description: 'Digital identity services provider',
            website: 'https://example.com',
            contactEmail: 'contact@example.com',
            address: '123 Identity Street',
            country: 'Germany',
            isDiscoverable: false,
            membershipMode: 'invite_only',
            allowedEmailDomains: [],
            domainJoinPolicy: 'approval',
            defaultRole: 'member',
            requireDeviceRegistration: false,
            allowPushNotifications: true,
            deviceRegistrationPrompt: 'first_action',
          });
        }
      } catch (err) {
        setError('Failed to load organization details');
        console.error(err);
      } finally {
        setLoading(false);
      }
    };
    loadOrg();
  }, [organizationName]);

  const handleSave = async () => {
    setSaving(true);
    setError(null);
    try {
      const response = await fetch('/api/onboarding/org-settings', {
        method: 'PUT',
        credentials: 'include',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          is_discoverable: org.isDiscoverable,
          membership_mode: org.membershipMode,
          allowed_email_domains: org.allowedEmailDomains,
          domain_join_policy: org.domainJoinPolicy,
          default_role: org.defaultRole,
          require_device_registration: org.requireDeviceRegistration,
          allow_push_notifications: org.allowPushNotifications,
          device_registration_prompt: org.deviceRegistrationPrompt,
        }),
      });
      
      if (!response.ok) {
        throw new Error('Failed to save organization settings');
      }
      
      setSuccess(true);
      setEditMode(false);
      setTimeout(() => setSuccess(false), 3000);
    } catch (err) {
      setError(err.message || 'Failed to save organization settings');
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
        title="Organization"
        tabs={ORG_TABS}
        breadcrumbs={BREADCRUMBS}
      >
        <LinearProgress />
      </ResourcePage>
    );
  }

  return (
    <ResourcePage
      title="Organization"
      description="Manage your organization profile and settings."
      tabs={ORG_TABS}
      breadcrumbs={BREADCRUMBS}
      actions={
        editMode ? (
          <Box sx={{ display: 'flex', gap: 1 }}>
            <Button variant="outlined" onClick={() => setEditMode(false)}>
              Cancel
            </Button>
            <Button
              variant="contained"
              startIcon={<SaveIcon />}
              onClick={handleSave}
              disabled={saving}
            >
              {saving ? 'Saving...' : 'Save Changes'}
            </Button>
          </Box>
        ) : (
          <Button
            variant="outlined"
            startIcon={<EditIcon />}
            onClick={() => setEditMode(true)}
          >
            Edit
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
          Organization settings saved successfully.
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
                Organization ID: {organizationId || 'org-12345'}
              </Typography>
            </Box>
          </Box>
        </CardContent>
      </Card>

      {/* Basic Information */}
      <Paper sx={{ p: 3, mb: 3 }}>
        <Typography variant="h6" gutterBottom>
          Basic Information
        </Typography>
        <Grid container spacing={3}>
          <Grid item xs={12} sm={6}>
            <TextField
              fullWidth
              label="Organization Name"
              value={org.name}
              onChange={handleChange('name')}
              disabled={!editMode}
            />
          </Grid>
          <Grid item xs={12} sm={6}>
            <TextField
              fullWidth
              label="Display Name"
              value={org.displayName}
              onChange={handleChange('displayName')}
              disabled={!editMode}
            />
          </Grid>
          <Grid item xs={12}>
            <TextField
              fullWidth
              label="Description"
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
          Contact Information
        </Typography>
        <Grid container spacing={3}>
          <Grid item xs={12} sm={6}>
            <TextField
              fullWidth
              label="Website"
              value={org.website}
              onChange={handleChange('website')}
              disabled={!editMode}
            />
          </Grid>
          <Grid item xs={12} sm={6}>
            <TextField
              fullWidth
              label="Contact Email"
              value={org.contactEmail}
              onChange={handleChange('contactEmail')}
              disabled={!editMode}
            />
          </Grid>
          <Grid item xs={12} sm={8}>
            <TextField
              fullWidth
              label="Address"
              value={org.address}
              onChange={handleChange('address')}
              disabled={!editMode}
            />
          </Grid>
          <Grid item xs={12} sm={4}>
            <TextField
              fullWidth
              label="Country"
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
          Email Domain-Based Membership
        </Typography>
        <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
          Allow users with specific email domains to automatically discover and join your organization.
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
              label="Make organization discoverable"
            />
            <FormHelperText>
              When enabled, users can find your organization in the directory.
            </FormHelperText>
          </Grid>
          
          <Grid item xs={12}>
            <Typography variant="subtitle2" gutterBottom>
              Allowed Email Domains
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
                  placeholder="e.g., example.com"
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
                  Add Domain
                </Button>
              </Box>
            )}
            <FormHelperText>
              Users with these email domains can discover your organization.
            </FormHelperText>
          </Grid>
          
          <Grid item xs={12} sm={6}>
            <FormControl fullWidth disabled={!editMode}>
              <InputLabel>Domain Join Policy</InputLabel>
              <Select
                value={org.domainJoinPolicy}
                label="Domain Join Policy"
                onChange={(e) => setOrg(prev => ({ ...prev, domainJoinPolicy: e.target.value }))}
              >
                <MenuItem value="auto">Auto-join (instant access)</MenuItem>
                <MenuItem value="approval">Requires approval</MenuItem>
                <MenuItem value="closed">Closed (no new members)</MenuItem>
              </Select>
              <FormHelperText>
                {org.domainJoinPolicy === 'auto' && 'Users are automatically added as members'}
                {org.domainJoinPolicy === 'approval' && 'Join requests must be approved by admin'}
                {org.domainJoinPolicy === 'closed' && 'Domain matching is disabled'}
              </FormHelperText>
            </FormControl>
          </Grid>
          
          <Grid item xs={12} sm={6}>
            <FormControl fullWidth disabled={!editMode}>
              <InputLabel>Default Role</InputLabel>
              <Select
                value={org.defaultRole}
                label="Default Role"
                onChange={(e) => setOrg(prev => ({ ...prev, defaultRole: e.target.value }))}
              >
                <MenuItem value="member">Member</MenuItem>
                <MenuItem value="admin">Admin</MenuItem>
                <MenuItem value="owner">Owner</MenuItem>
              </Select>
              <FormHelperText>
                Role assigned to users who join via email domain
              </FormHelperText>
            </FormControl>
          </Grid>
        </Grid>
      </Paper>

      {/* Device Security Settings */}
      <Paper sx={{ p: 3, mb: 3 }}>
        <Typography variant="h6" gutterBottom>
          Device Security
        </Typography>
        <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
          Configure device registration and push notification settings for credential holders.
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
              label="Require Device Registration"
            />
            <Typography variant="caption" display="block" color="text.secondary" sx={{ ml: 4 }}>
              When enabled, users must register their mobile device before they can receive or use credentials.
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
              label="Allow Push Notifications"
            />
            <Typography variant="caption" display="block" color="text.secondary" sx={{ ml: 4 }}>
              Enable push notifications for credential updates, verification requests, and other time-sensitive events.
            </Typography>
          </Grid>
          
          <Grid item xs={12} sm={6}>
            <FormControl fullWidth disabled={!editMode}>
              <InputLabel>Device Registration Prompt</InputLabel>
              <Select
                value={org.deviceRegistrationPrompt}
                label="Device Registration Prompt"
                onChange={(e) => setOrg(prev => ({ ...prev, deviceRegistrationPrompt: e.target.value }))}
              >
                <MenuItem value="onboarding">During onboarding</MenuItem>
                <MenuItem value="first_action">Before first credential action</MenuItem>
                <MenuItem value="never">Never (optional)</MenuItem>
              </Select>
              <FormHelperText>
                {org.deviceRegistrationPrompt === 'onboarding' && 'Users prompted to register device immediately after account creation'}
                {org.deviceRegistrationPrompt === 'first_action' && 'Users prompted when they first apply for or use a credential'}
                {org.deviceRegistrationPrompt === 'never' && 'Device registration is optional unless required above'}
              </FormHelperText>
            </FormControl>
          </Grid>
        </Grid>
      </Paper>

      {/* Danger Zone */}
      <Paper sx={{ p: 3, border: 1, borderColor: 'error.main' }}>
        <Typography variant="h6" color="error" gutterBottom>
          Danger Zone
        </Typography>
        <Typography variant="body2" color="text.secondary" paragraph>
          Deleting your organization will permanently remove all data including credentials, 
          templates, policies, and team members. This action cannot be undone.
        </Typography>
        <Button variant="outlined" color="error" disabled>
          Delete Organization
        </Button>
      </Paper>
    </ResourcePage>
  );
}

export default OrganizationSettingsPage;

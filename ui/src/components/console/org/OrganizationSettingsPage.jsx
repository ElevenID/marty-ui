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
} from '@mui/material';
import EditIcon from '@mui/icons-material/Edit';
import SaveIcon from '@mui/icons-material/Save';
import BusinessIcon from '@mui/icons-material/Business';
// import { Link } from 'react-router-dom';

import { ResourcePage } from '../../common';
import { useAuth } from '../../../hooks/useAuth';

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
  });

  useEffect(() => {
    // TODO: Fetch organization details from API
    const loadOrg = async () => {
      try {
        await new Promise((resolve) => setTimeout(resolve, 500));
        setOrg({
          name: organizationName || 'My Organization',
          displayName: organizationName || 'My Organization',
          description: 'Digital identity services provider',
          website: 'https://example.com',
          contactEmail: 'contact@example.com',
          address: '123 Identity Street',
          country: 'Germany',
        });
      } catch (err) {
        setError('Failed to load organization details');
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
      // TODO: Save to API
      await new Promise((resolve) => setTimeout(resolve, 500));
      setSuccess(true);
      setEditMode(false);
      setTimeout(() => setSuccess(false), 3000);
    } catch (err) {
      setError('Failed to save organization settings');
    } finally {
      setSaving(false);
    }
  };

  const handleChange = (field) => (event) => {
    setOrg((prev) => ({ ...prev, [field]: event.target.value }));
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

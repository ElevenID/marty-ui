/**
 * Organization Defaults Section
 * 
 * Configure default resources for new flows and operations:
 * - Default Trust Profile
 * - Default Presentation Policy
 * - Default Credential Template
 */

import { useState, useEffect } from 'react';
import {
  Paper,
  Typography,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Button,
  Box,
  Alert,
  CircularProgress,
} from '@mui/material';
import SaveIcon from '@mui/icons-material/Save';

import { useAuth } from '../../../hooks/useAuth';
import {
  getOrganizationDefaults,
  updateOrganizationDefaults,
} from '../../../services/organizationsApi';
import {
  listTrustProfiles,
  listPresentationPolicies,
  listCredentialTemplates,
} from '../../../services/presentationPolicyApi';

/**
 * Organization Defaults Section Component
 */
export function OrgDefaultsSection() {
  const { organizationId } = useAuth();
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState(null);
  const [success, setSuccess] = useState(false);

  // Defaults state
  const [defaults, setDefaults] = useState({
    default_trust_profile_id: '',
    default_policy_id: '',
    default_template_id: '',
  });

  // Available resources
  const [trustProfiles, setTrustProfiles] = useState([]);
  const [policies, setPolicies] = useState([]);
  const [templates, setTemplates] = useState([]);

  useEffect(() => {
    async function loadData() {
      if (!organizationId) return;

      setLoading(true);
      try {
        // Load defaults and available resources in parallel
        const [defaultsData, profilesData, policiesData, templatesData] = await Promise.all([
          getOrganizationDefaults(organizationId).catch(() => ({})),
          listTrustProfiles({ organization_id: organizationId }).catch(() => []),
          listPresentationPolicies({ organization_id: organizationId }).catch(() => []),
          listCredentialTemplates({ organization_id: organizationId }).catch(() => []),
        ]);

        setDefaults({
          default_trust_profile_id: defaultsData?.default_trust_profile_id || '',
          default_policy_id: defaultsData?.default_policy_id || '',
          default_template_id: defaultsData?.default_template_id || '',
        });

        setTrustProfiles(Array.isArray(profilesData) ? profilesData : profilesData?.items || []);
        setPolicies(Array.isArray(policiesData) ? policiesData : policiesData?.items || []);
        setTemplates(Array.isArray(templatesData) ? templatesData : templatesData?.items || []);
      } catch (err) {
        console.error('Failed to load org defaults:', err);
        setError('Failed to load organization defaults');
      } finally {
        setLoading(false);
      }
    }

    loadData();
  }, [organizationId]);

  const handleSave = async () => {
    setSaving(true);
    setError(null);
    setSuccess(false);

    try {
      await updateOrganizationDefaults(organizationId, defaults);
      setSuccess(true);
      setTimeout(() => setSuccess(false), 3000);
    } catch (err) {
      console.error('Failed to save org defaults:', err);
      setError('Failed to save organization defaults');
    } finally {
      setSaving(false);
    }
  };

  const handleChange = (field, value) => {
    setDefaults(prev => ({
      ...prev,
      [field]: value,
    }));
  };

  if (loading) {
    return (
      <Paper sx={{ p: 3, mb: 3, textAlign: 'center' }}>
        <CircularProgress />
      </Paper>
    );
  }

  return (
    <Paper sx={{ p: 3, mb: 3 }}>
      <Typography variant="h6" gutterBottom>
        Organization Defaults
      </Typography>
      <Typography variant="body2" color="text.secondary" paragraph>
        Set default resources that will be automatically selected when creating new flows and configurations.
      </Typography>

      {error && (
        <Alert severity="error" sx={{ mb: 2 }}>
          {error}
        </Alert>
      )}

      {success && (
        <Alert severity="success" sx={{ mb: 2 }}>
          Organization defaults saved successfully
        </Alert>
      )}

      <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
        {/* Default Trust Profile */}
        <FormControl fullWidth>
          <InputLabel>Default Trust Profile</InputLabel>
          <Select
            value={defaults.default_trust_profile_id}
            onChange={(e) => handleChange('default_trust_profile_id', e.target.value)}
            label="Default Trust Profile"
          >
            <MenuItem value="">
              <em>None (manual selection required)</em>
            </MenuItem>
            {trustProfiles.map((profile) => (
              <MenuItem key={profile.id} value={profile.id}>
                {profile.name}
              </MenuItem>
            ))}
          </Select>
        </FormControl>

        {/* Default Presentation Policy */}
        <FormControl fullWidth>
          <InputLabel>Default Presentation Policy</InputLabel>
          <Select
            value={defaults.default_policy_id}
            onChange={(e) => handleChange('default_policy_id', e.target.value)}
            label="Default Presentation Policy"
          >
            <MenuItem value="">
              <em>None (manual selection required)</em>
            </MenuItem>
            {policies.map((policy) => (
              <MenuItem key={policy.id} value={policy.id}>
                {policy.name}
              </MenuItem>
            ))}
          </Select>
        </FormControl>

        {/* Default Credential Template */}
        <FormControl fullWidth>
          <InputLabel>Default Credential Template</InputLabel>
          <Select
            value={defaults.default_template_id}
            onChange={(e) => handleChange('default_template_id', e.target.value)}
            label="Default Credential Template"
          >
            <MenuItem value="">
              <em>None (manual selection required)</em>
            </MenuItem>
            {templates.map((template) => (
              <MenuItem key={template.id} value={template.id}>
                {template.name}
              </MenuItem>
            ))}
          </Select>
        </FormControl>

        {/* Save Button */}
        <Box sx={{ display: 'flex', justifyContent: 'flex-end', mt: 1 }}>
          <Button
            variant="contained"
            startIcon={saving ? <CircularProgress size={16} /> : <SaveIcon />}
            onClick={handleSave}
            disabled={saving}
          >
            {saving ? 'Saving...' : 'Save Defaults'}
          </Button>
        </Box>
      </Box>
    </Paper>
  );
}

export default OrgDefaultsSection;

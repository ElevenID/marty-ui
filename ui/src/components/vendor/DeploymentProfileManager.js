/**
 * Deployment Profile Manager Component
 * 
 * Manages deployment profiles that define how digital identity systems
 * are configured for specific physical deployment scenarios.
 * Hierarchy: Organization → Site → Deployment Profile → Lane(s) → Device(s)
 */

import React, { useState, useEffect } from 'react';
import {
  Box,
  Paper,
  Typography,
  Button,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  IconButton,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  TextField,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Chip,
  Alert,
  CircularProgress,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  Grid,
  Card,
  CardContent,
  CardActions,
  Tooltip,
  FormGroup,
  FormControlLabel,
  Checkbox,
  Tabs,
  Tab,
} from '@mui/material';
import AddIcon from '@mui/icons-material/Add';
import EditIcon from '@mui/icons-material/Edit';
import DeleteIcon from '@mui/icons-material/Delete';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import SettingsIcon from '@mui/icons-material/Settings';
import DevicesIcon from '@mui/icons-material/Devices';
import PublicIcon from '@mui/icons-material/Public';
import OfflineBoltIcon from '@mui/icons-material/OfflineBolt';

import deploymentProfilesApi from '../../services/deploymentProfilesApi';
import LaneManager from './LaneManager';

const NETWORK_MODES = [
  { value: 'ONLINE', label: 'Online', description: 'Full cloud connectivity', icon: <PublicIcon /> },
  { value: 'OFFLINE', label: 'Offline', description: 'No network required', icon: <OfflineBoltIcon /> },
  { value: 'HYBRID', label: 'Hybrid', description: 'Sync when available', icon: <DevicesIcon /> },
];

const DeploymentProfileManager = () => {
  const [profiles, setProfiles] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [dialogOpen, setDialogOpen] = useState(false);
  const [editMode, setEditMode] = useState(false);
  const [selectedProfile, setSelectedProfile] = useState(null);
  const [currentProfile, setCurrentProfile] = useState({
    name: '',
    description: '',
    site_id: '',
    network_mode: 'ONLINE',
    trust_profile_ids: [],
    enabled_credential_template_ids: [],
    enabled_presentation_policy_ids: [],
    environment_config: {
      ux_theme: 'default',
      language: 'en',
      signage_config: {},
      accessibility_features: [],
    },
  });
  const [activeTab, setActiveTab] = useState(0);

  useEffect(() => {
    loadProfiles();
  }, []);

  const loadProfiles = async () => {
    setLoading(true);
    try {
      const data = await deploymentProfilesApi.listDeploymentProfiles();
      setProfiles(data);
      setError(null);
    } catch (err) {
      console.error('Failed to load deployment profiles:', err);
      setError('Failed to load deployment profiles');
    } finally {
      setLoading(false);
    }
  };

  const handleCreate = () => {
    setCurrentProfile({
      name: '',
      description: '',
      site_id: '',
      network_mode: 'ONLINE',
      trust_profile_ids: [],
      enabled_credential_template_ids: [],
      enabled_presentation_policy_ids: [],
      environment_config: {
        ux_theme: 'default',
        language: 'en',
        signage_config: {},
        accessibility_features: [],
      },
    });
    setEditMode(false);
    setDialogOpen(true);
  };

  const handleEdit = (profile) => {
    setCurrentProfile(profile);
    setEditMode(true);
    setDialogOpen(true);
  };

  const handleSave = async () => {
    try {
      if (editMode) {
        await deploymentProfilesApi.updateDeploymentProfile(currentProfile.id, currentProfile);
      } else {
        await deploymentProfilesApi.createDeploymentProfile(currentProfile);
      }
      setDialogOpen(false);
      loadProfiles();
    } catch (err) {
      console.error('Failed to save deployment profile:', err);
      setError(`Failed to save: ${err.message}`);
    }
  };

  const handleDelete = async (profileId) => {
    if (!window.confirm('Are you sure you want to delete this deployment profile?')) {
      return;
    }
    try {
      await deploymentProfilesApi.deleteDeploymentProfile(profileId);
      loadProfiles();
    } catch (err) {
      console.error('Failed to delete deployment profile:', err);
      setError(`Failed to delete: ${err.message}`);
    }
  };

  const handleViewLanes = (profile) => {
    setSelectedProfile(profile);
    setActiveTab(1);
  };

  if (loading) {
    return (
      <Box display="flex" justifyContent="center" alignItems="center" minHeight="400px">
        <CircularProgress />
      </Box>
    );
  }

  return (
    <Box>
      <Tabs value={activeTab} onChange={(e, v) => setActiveTab(v)} sx={{ mb: 3 }}>
        <Tab label="Deployment Profiles" />
        <Tab label="Lanes" disabled={!selectedProfile} />
      </Tabs>

      {activeTab === 0 && (
        <>
          <Box display="flex" justifyContent="space-between" alignItems="center" mb={3}>
            <Box>
              <Typography variant="h4">Deployment Profiles</Typography>
              <Typography variant="body2" color="text.secondary">
                Configure physical deployment scenarios (kiosks, border crossings, etc.)
              </Typography>
            </Box>
            <Button
              variant="contained"
              color="primary"
              startIcon={<AddIcon />}
              onClick={handleCreate}
            >
              Create Profile
            </Button>
          </Box>

          {error && (
            <Alert severity="error" sx={{ mb: 2 }} onClose={() => setError(null)}>
              {error}
            </Alert>
          )}

          <Grid container spacing={3}>
            {profiles.map((profile) => (
              <Grid item xs={12} md={6} lg={4} key={profile.id}>
                <Card>
                  <CardContent>
                    <Box display="flex" alignItems="center" mb={1}>
                      <SettingsIcon sx={{ mr: 1 }} color="primary" />
                      <Typography variant="h6">{profile.name}</Typography>
                    </Box>
                    <Typography variant="body2" color="text.secondary" mb={2}>
                      {profile.description}
                    </Typography>
                    <Box display="flex" gap={1} mb={1}>
                      {NETWORK_MODES.find(m => m.value === profile.network_mode)?.icon}
                      <Typography variant="body2">
                        {NETWORK_MODES.find(m => m.value === profile.network_mode)?.label}
                      </Typography>
                    </Box>
                    <Box display="flex" gap={1} flexWrap="wrap">
                      <Chip label={`${profile.enabled_credential_template_ids?.length || 0} Templates`} size="small" />
                      <Chip label={`${profile.enabled_presentation_policy_ids?.length || 0} Policies`} size="small" />
                    </Box>
                  </CardContent>
                  <CardActions>
                    <Button size="small" onClick={() => handleEdit(profile)}>
                      <EditIcon sx={{ mr: 0.5 }} fontSize="small" />
                      Edit
                    </Button>
                    <Button size="small" onClick={() => handleViewLanes(profile)}>
                      <DevicesIcon sx={{ mr: 0.5 }} fontSize="small" />
                      Lanes
                    </Button>
                    <Button size="small" color="error" onClick={() => handleDelete(profile.id)}>
                      <DeleteIcon sx={{ mr: 0.5 }} fontSize="small" />
                      Delete
                    </Button>
                  </CardActions>
                </Card>
              </Grid>
            ))}
            {profiles.length === 0 && (
              <Grid item xs={12}>
                <Paper sx={{ p: 4, textAlign: 'center' }}>
                  <Typography color="text.secondary">
                    No deployment profiles. Create one to configure your physical deployment.
                  </Typography>
                </Paper>
              </Grid>
            )}
          </Grid>
        </>
      )}

      {activeTab === 1 && selectedProfile && (
        <LaneManager deploymentProfile={selectedProfile} onBack={() => setActiveTab(0)} />
      )}

      {/* Create/Edit Dialog */}
      <Dialog open={dialogOpen} onClose={() => setDialogOpen(false)} maxWidth="md" fullWidth>
        <DialogTitle>
          {editMode ? 'Edit Deployment Profile' : 'Create Deployment Profile'}
        </DialogTitle>
        <DialogContent>
          <Box sx={{ mt: 2 }}>
            <TextField
              fullWidth
              label="Name"
              value={currentProfile.name}
              onChange={(e) => setCurrentProfile({ ...currentProfile, name: e.target.value })}
              sx={{ mb: 2 }}
              required
            />

            <TextField
              fullWidth
              label="Description"
              value={currentProfile.description}
              onChange={(e) => setCurrentProfile({ ...currentProfile, description: e.target.value })}
              multiline
              rows={2}
              sx={{ mb: 2 }}
            />

            <FormControl fullWidth sx={{ mb: 2 }}>
              <InputLabel>Network Mode</InputLabel>
              <Select
                value={currentProfile.network_mode}
                onChange={(e) => setCurrentProfile({ ...currentProfile, network_mode: e.target.value })}
                label="Network Mode"
              >
                {NETWORK_MODES.map((mode) => (
                  <MenuItem key={mode.value} value={mode.value}>
                    <Box display="flex" alignItems="center" gap={1}>
                      {mode.icon}
                      {mode.label} - {mode.description}
                    </Box>
                  </MenuItem>
                ))}
              </Select>
            </FormControl>

            <Accordion>
              <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                <Typography>Environment Configuration</Typography>
              </AccordionSummary>
              <AccordionDetails>
                <Grid container spacing={2}>
                  <Grid item xs={6}>
                    <FormControl fullWidth>
                      <InputLabel>UX Theme</InputLabel>
                      <Select
                        value={currentProfile.environment_config.ux_theme}
                        onChange={(e) => setCurrentProfile({
                          ...currentProfile,
                          environment_config: {
                            ...currentProfile.environment_config,
                            ux_theme: e.target.value,
                          },
                        })}
                        label="UX Theme"
                      >
                        <MenuItem value="default">Default</MenuItem>
                        <MenuItem value="high_contrast">High Contrast</MenuItem>
                        <MenuItem value="large_text">Large Text</MenuItem>
                      </Select>
                    </FormControl>
                  </Grid>
                  <Grid item xs={6}>
                    <FormControl fullWidth>
                      <InputLabel>Language</InputLabel>
                      <Select
                        value={currentProfile.environment_config.language}
                        onChange={(e) => setCurrentProfile({
                          ...currentProfile,
                          environment_config: {
                            ...currentProfile.environment_config,
                            language: e.target.value,
                          },
                        })}
                        label="Language"
                      >
                        <MenuItem value="en">English</MenuItem>
                        <MenuItem value="es">Spanish</MenuItem>
                        <MenuItem value="fr">French</MenuItem>
                        <MenuItem value="de">German</MenuItem>
                      </Select>
                    </FormControl>
                  </Grid>
                </Grid>

                <Typography variant="subtitle2" sx={{ mt: 2, mb: 1 }}>
                  Accessibility Features
                </Typography>
                <FormGroup>
                  {['screen_reader', 'voice_guidance', 'keyboard_navigation'].map((feature) => (
                    <FormControlLabel
                      key={feature}
                      control={
                        <Checkbox
                          checked={currentProfile.environment_config.accessibility_features?.includes(feature) || false}
                          onChange={(e) => {
                            const features = currentProfile.environment_config.accessibility_features || [];
                            const newFeatures = e.target.checked
                              ? [...features, feature]
                              : features.filter(f => f !== feature);
                            setCurrentProfile({
                              ...currentProfile,
                              environment_config: {
                                ...currentProfile.environment_config,
                                accessibility_features: newFeatures,
                              },
                            });
                          }}
                        />
                      }
                      label={feature.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())}
                    />
                  ))}
                </FormGroup>
              </AccordionDetails>
            </Accordion>
          </Box>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setDialogOpen(false)}>Cancel</Button>
          <Button onClick={handleSave} variant="contained" color="primary">
            {editMode ? 'Update' : 'Create'}
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
};

export default DeploymentProfileManager;

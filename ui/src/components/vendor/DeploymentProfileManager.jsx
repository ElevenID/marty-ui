/**
 * Deployment Profile Manager Component
 * 
 * Manages deployment profiles that configure how digital identity systems
 * integrate with APIs, kiosks, lanes/devices in online and offline environments.
 * Hierarchy: Organization → Site → Deployment Profile → Lane(s) → Device(s)
 */

import { useState, useEffect } from 'react';
import { useTranslation } from 'react-i18next';
import {
  Box,
  Paper,
  Typography,
  Button,
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
  Accordion,
  AccordionSummary,
  AccordionDetails,
  Grid,
  Card,
  CardContent,
  CardActions,
  FormGroup,
  FormControlLabel,
  Checkbox,
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
import { CardSkeleton } from '../common/skeletons';
import ErrorState from '../common/ErrorState';

const DeploymentProfileManager = () => {
  const { t } = useTranslation('vendor');
  const NETWORK_MODES = [
    { value: 'ONLINE', label: t('deploymentProfiles.networkModes.online'), description: t('deploymentProfiles.networkModes.onlineDesc'), icon: <PublicIcon /> },
    { value: 'OFFLINE', label: t('deploymentProfiles.networkModes.offline'), description: t('deploymentProfiles.networkModes.offlineDesc'), icon: <OfflineBoltIcon /> },
    { value: 'HYBRID', label: t('deploymentProfiles.networkModes.hybrid'), description: t('deploymentProfiles.networkModes.hybridDesc'), icon: <DevicesIcon /> },
  ];
  const [profiles, setProfiles] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [dialogOpen, setDialogOpen] = useState(false);
  const [editMode, setEditMode] = useState(false);
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
      setError(t('deploymentProfiles.loadFailed'));
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
      setError(t('deploymentProfiles.saveFailed', { error: err.message }));
    }
  };

  const handleDelete = async (profileId) => {
    if (!window.confirm(t('deploymentProfiles.deleteConfirm'))) {
      return;
    }
    try {
      await deploymentProfilesApi.deleteDeploymentProfile(profileId);
      loadProfiles();
    } catch (err) {
      console.error('Failed to delete deployment profile:', err);
      setError(t('deploymentProfiles.deleteFailed', { error: err.message }));
    }
  };

  // Show header always
  const header = (
    <Box display="flex" justifyContent="space-between" alignItems="center" mb={3}>
      <Box>
        <Typography variant="h4">{t('deploymentProfiles.title')}</Typography>
        <Typography variant="body2" color="text.secondary">
          {t('deploymentProfiles.description')}
        </Typography>
      </Box>
      <Button
        variant="contained"
        color="primary"
        startIcon={<AddIcon />}
        onClick={handleCreate}
        disabled={loading}
      >
        {t('deploymentProfiles.createButton')}
      </Button>
    </Box>
  );

  if (loading) {
    return (
      <Box>
        {header}
        <Grid container spacing={3}>
          {Array.from({ length: 3 }).map((_, index) => (
            <Grid item xs={12} md={6} lg={4} key={index}>
              <CardSkeleton showHeader={true} showActions={true} lines={4} />
            </Grid>
          ))}
        </Grid>
      </Box>
    );
  }

  if (error) {
    return (
      <Box>
        {header}
        <ErrorState
          error={error}
          onRetry={loadProfiles}
          variant="inline"
        />
      </Box>
    );
  }

  return (
    <Box>
      {header}

      {/* Show empty state OR profiles */}
      {profiles.length === 0 ? (
        <Paper sx={{ p: 6, textAlign: 'center', borderStyle: 'dashed', borderColor: 'divider' }}>
          <Typography color="text.secondary" gutterBottom>
            {t('deploymentProfiles.empty.title')}
          </Typography>
          <Typography variant="body2" color="text.secondary">
            {t('deploymentProfiles.empty.description')}
          </Typography>
        </Paper>
      ) : (
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
                      <Chip label={t('deploymentProfiles.card.templates', { count: profile.enabled_credential_template_ids?.length || 0 })} size="small" />
                      <Chip label={t('deploymentProfiles.card.policies', { count: profile.enabled_presentation_policy_ids?.length || 0 })} size="small" />
                    </Box>
                  </CardContent>
                  <CardActions>
                    <Button size="small" onClick={() => handleEdit(profile)}>
                      <EditIcon sx={{ mr: 0.5 }} fontSize="small" />
                      {t('deploymentProfiles.card.editButton')}
                    </Button>
                    <Button size="small" color="error" onClick={() => handleDelete(profile.id)}>
                      <DeleteIcon sx={{ mr: 0.5 }} fontSize="small" />
                      {t('deploymentProfiles.card.deleteButton')}
                    </Button>
                  </CardActions>
                </Card>
              </Grid>
            ))}
          </Grid>
        )}

      {/* Create/Edit Dialog */}
      <Dialog open={dialogOpen} onClose={() => setDialogOpen(false)} maxWidth="md" fullWidth>
        <DialogTitle>
          {editMode ? t('deploymentProfiles.dialog.editTitle') : t('deploymentProfiles.dialog.createTitle')}
        </DialogTitle>
        <DialogContent>
          <Box sx={{ mt: 2 }}>
            <TextField
              fullWidth
              label={t('deploymentProfiles.dialog.nameLabel')}
              value={currentProfile.name}
              onChange={(e) => setCurrentProfile({ ...currentProfile, name: e.target.value })}
              sx={{ mb: 2 }}
              required
            />

            <TextField
              fullWidth
              label={t('deploymentProfiles.dialog.descriptionLabel')}
              value={currentProfile.description}
              onChange={(e) => setCurrentProfile({ ...currentProfile, description: e.target.value })}
              multiline
              rows={2}
              sx={{ mb: 2 }}
            />

            <FormControl fullWidth sx={{ mb: 2 }}>
              <InputLabel>{t('deploymentProfiles.dialog.networkModeLabel')}</InputLabel>
              <Select
                value={currentProfile.network_mode}
                onChange={(e) => setCurrentProfile({ ...currentProfile, network_mode: e.target.value })}
                label={t('deploymentProfiles.dialog.networkModeLabel')}
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
                <Typography>{t('deploymentProfiles.dialog.environmentConfig')}</Typography>
              </AccordionSummary>
              <AccordionDetails>
                <Grid container spacing={2}>
                  <Grid item xs={6}>
                    <FormControl fullWidth>
                      <InputLabel>{t('deploymentProfiles.dialog.uxThemeLabel')}</InputLabel>
                      <Select
                        value={currentProfile.environment_config.ux_theme}
                        onChange={(e) => setCurrentProfile({
                          ...currentProfile,
                          environment_config: {
                            ...currentProfile.environment_config,
                            ux_theme: e.target.value,
                          },
                        })}
                        label={t('deploymentProfiles.dialog.uxThemeLabel')}
                      >
                        <MenuItem value="default">{t('deploymentProfiles.dialog.themes.default')}</MenuItem>
                        <MenuItem value="high_contrast">{t('deploymentProfiles.dialog.themes.highContrast')}</MenuItem>
                        <MenuItem value="large_text">{t('deploymentProfiles.dialog.themes.largeText')}</MenuItem>
                      </Select>
                    </FormControl>
                  </Grid>
                  <Grid item xs={6}>
                    <FormControl fullWidth>
                      <InputLabel>{t('deploymentProfiles.dialog.languageLabel')}</InputLabel>
                      <Select
                        value={currentProfile.environment_config.language}
                        onChange={(e) => setCurrentProfile({
                          ...currentProfile,
                          environment_config: {
                            ...currentProfile.environment_config,
                            language: e.target.value,
                          },
                        })}
                        label={t('deploymentProfiles.dialog.languageLabel')}
                      >
                        <MenuItem value="en">{t('deploymentProfiles.dialog.languages.en')}</MenuItem>
                        <MenuItem value="es">{t('deploymentProfiles.dialog.languages.es')}</MenuItem>
                        <MenuItem value="fr">{t('deploymentProfiles.dialog.languages.fr')}</MenuItem>
                        <MenuItem value="de">{t('deploymentProfiles.dialog.languages.de')}</MenuItem>
                      </Select>
                    </FormControl>
                  </Grid>
                </Grid>

                <Typography variant="subtitle2" sx={{ mt: 2, mb: 1 }}>
                  {t('deploymentProfiles.dialog.accessibilityFeatures')}
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
          <Button onClick={() => setDialogOpen(false)}>{t('deploymentProfiles.dialog.cancelButton')}</Button>
          <Button onClick={handleSave} variant="contained" color="primary">
            {editMode ? t('deploymentProfiles.dialog.updateButton') : t('deploymentProfiles.dialog.createButton')}
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
};

export default DeploymentProfileManager;

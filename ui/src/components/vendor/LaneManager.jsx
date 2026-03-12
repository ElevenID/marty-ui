/**
 * Lane Manager Component
 * 
 * Manages lanes within a deployment profile.
 * Lanes represent individual processing stations (e.g., kiosk lanes at border crossing).
 * Each lane can have:
 * - Assigned devices
 * - Lane-specific policy overrides
 * - Metadata (zone, operator info)
 */

import { useState, useEffect, useCallback } from 'react';
import { useTranslation } from 'react-i18next';
import {
  Box,
  Paper,
  Typography,
  Button,
  IconButton,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  TextField,
  Alert,
  CircularProgress,
  Grid,
  Card,
  CardContent,
  CardActions,
  List,
  ListItem,
  ListItemText,
  ListItemSecondaryAction,
} from '@mui/material';
import AddIcon from '@mui/icons-material/Add';
import EditIcon from '@mui/icons-material/Edit';
import DeleteIcon from '@mui/icons-material/Delete';
import ArrowBackIcon from '@mui/icons-material/ArrowBack';
import DevicesIcon from '@mui/icons-material/Devices';
import AddCircleIcon from '@mui/icons-material/AddCircle';
import RemoveCircleIcon from '@mui/icons-material/RemoveCircle';

import deploymentProfilesApi from '../../services/deploymentProfilesApi';
import { useDialog } from '../../hooks/useDialog';

const LaneManager = ({ deploymentProfile, onBack }) => {
  const { t } = useTranslation('vendor');
  const [lanes, setLanes] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [dialogOpen, setDialogOpen] = useState(false);
  const [editMode, setEditMode] = useState(false);
  const deviceDialog = useDialog();
  const [currentLane, setCurrentLane] = useState({
    name: '',
    description: '',
    deployment_profile_id: deploymentProfile.id,
    policy_overrides: {},
    metadata: {
      zone: '',
      operator_info: '',
    },
  });
  const [deviceToAssign, setDeviceToAssign] = useState('');

  useEffect(() => {
    loadLanes();
  }, [loadLanes]);

  const loadLanes = useCallback(async () => {
    setLoading(true);
    try {
      const data = await deploymentProfilesApi.listLanes(deploymentProfile.id);
      setLanes(data);
      setError(null);
    } catch (err) {
      console.error('Failed to load lanes:', err);
      setError(t('laneManager.loadFailed'));
    } finally {
      setLoading(false);
    }
  }, [deploymentProfile.id]);

  const handleCreate = () => {
    setCurrentLane({
      name: '',
      description: '',
      deployment_profile_id: deploymentProfile.id,
      policy_overrides: {},
      metadata: {
        zone: '',
        operator_info: '',
      },
    });
    setEditMode(false);
    setDialogOpen(true);
  };

  const handleEdit = (lane) => {
    setCurrentLane(lane);
    setEditMode(true);
    setDialogOpen(true);
  };

  const handleSave = async () => {
    try {
      if (editMode) {
        await deploymentProfilesApi.updateLane(currentLane.id, currentLane);
      } else {
        await deploymentProfilesApi.createLane(currentLane);
      }
      setDialogOpen(false);
      loadLanes();
    } catch (err) {
      console.error('Failed to save lane:', err);
      setError(t('laneManager.saveFailed', { error: err.message }));
    }
  };

  const handleDelete = async (laneId) => {
    if (!window.confirm(t('laneManager.deleteConfirm'))) {
      return;
    }
    try {
      await deploymentProfilesApi.deleteLane(laneId);
      loadLanes();
    } catch (err) {
      console.error('Failed to delete lane:', err);
      setError(t('laneManager.deleteFailed', { error: err.message }));
    }
  };

  const handleAssignDevice = async () => {
    if (!deviceToAssign || !deviceDialog.data) return;
    try {
      await deploymentProfilesApi.assignDeviceToLane(deviceDialog.data.id, deviceToAssign);
      deviceDialog.close();
      loadLanes();
    } catch (err) {
      setError(t('laneManager.assignDeviceFailed', { error: err.message }));
    }
  };

  const handleUnassignDevice = async (laneId, deviceId) => {
    if (!window.confirm(t('laneManager.removeDeviceConfirm'))) {
      return;
    }
    try {
      await deploymentProfilesApi.unassignDeviceFromLane(laneId, deviceId);
      loadLanes();
    } catch (err) {
      console.error('Failed to unassign device:', err);
      setError(t('laneManager.unassignDeviceFailed', { error: err.message }));
    }
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
      <Box display="flex" alignItems="center" mb={3}>
        <IconButton onClick={onBack} sx={{ mr: 2 }}>
          <ArrowBackIcon />
        </IconButton>
        <Box flex={1}>
          <Typography variant="h4">{t('laneManager.title', { profileName: deploymentProfile.name })}</Typography>
          <Typography variant="body2" color="text.secondary">
            {t('laneManager.description')}
          </Typography>
        </Box>
        <Button
          variant="contained"
          color="primary"
          startIcon={<AddIcon />}
          onClick={handleCreate}
        >
          {t('laneManager.createButton')}
        </Button>
      </Box>

      {error && (
        <Alert severity="error" sx={{ mb: 2 }} onClose={() => setError(null)}>
          {error}
        </Alert>
      )}

      <Grid container spacing={3}>
        {lanes.map((lane) => (
          <Grid item xs={12} md={6} key={lane.id}>
            <Card>
              <CardContent>
                <Box display="flex" alignItems="center" mb={1}>
                  <DevicesIcon sx={{ mr: 1 }} color="primary" />
                  <Typography variant="h6">{lane.name}</Typography>
                </Box>
                <Typography variant="body2" color="text.secondary" mb={2}>
                  {lane.description}
                </Typography>
                
                {lane.metadata?.zone && (
                  <Typography variant="caption" display="block" mb={1}>
                    <strong>{t('laneManager.card.zone')}:</strong> {lane.metadata.zone}
                  </Typography>
                )}
                
                {lane.metadata?.operator_info && (
                  <Typography variant="caption" display="block" mb={1}>
                    <strong>{t('laneManager.card.operator')}:</strong> {lane.metadata.operator_info}
                  </Typography>
                )}

                <Typography variant="subtitle2" sx={{ mt: 2, mb: 1 }}>
                  {t('laneManager.card.assignedDevices', { count: lane.assigned_devices?.length || 0 })}
                </Typography>
                <List dense>
                  {lane.assigned_devices?.map((device) => (
                    <ListItem key={device.id}>
                      <ListItemText
                        primary={device.name || device.id}
                        secondary={device.status || 'Active'}
                      />
                      <ListItemSecondaryAction>
                        <IconButton
                          edge="end"
                          size="small"
                          onClick={() => handleUnassignDevice(lane.id, device.id)}
                        >
                          <RemoveCircleIcon />
                        </IconButton>
                      </ListItemSecondaryAction>
                    </ListItem>
                  )) || (
                    <Typography variant="body2" color="text.secondary">
                      {t('laneManager.card.noDevices')}
                    </Typography>
                  )}
                </List>
              </CardContent>
              <CardActions>
                <Button size="small" onClick={() => handleEdit(lane)}>
                  <EditIcon sx={{ mr: 0.5 }} fontSize="small" />
                  {t('laneManager.card.editButton')}
                </Button>
                <Button size="small" onClick={() => { setDeviceToAssign(''); deviceDialog.open(lane); }}>
                  <AddCircleIcon sx={{ mr: 0.5 }} fontSize="small" />
                  {t('laneManager.card.assignDeviceButton')}
                </Button>
                <Button size="small" color="error" onClick={() => handleDelete(lane.id)}>
                  <DeleteIcon sx={{ mr: 0.5 }} fontSize="small" />
                  {t('laneManager.card.deleteButton')}
                </Button>
              </CardActions>
            </Card>
          </Grid>
        ))}
        {lanes.length === 0 && (
          <Grid item xs={12}>
            <Paper sx={{ p: 4, textAlign: 'center' }}>
              <Typography color="text.secondary">
                {t('laneManager.empty')}
              </Typography>
            </Paper>
          </Grid>
        )}
      </Grid>

      {/* Create/Edit Lane Dialog */}
      <Dialog open={dialogOpen} onClose={() => setDialogOpen(false)} maxWidth="sm" fullWidth>
        <DialogTitle>
          {editMode ? t('laneManager.dialog.editTitle') : t('laneManager.dialog.createTitle')}
        </DialogTitle>
        <DialogContent>
          <Box sx={{ mt: 2 }}>
            <TextField
              fullWidth
              label={t('laneManager.dialog.nameLabel')}
              value={currentLane.name}
              onChange={(e) => setCurrentLane({ ...currentLane, name: e.target.value })}
              sx={{ mb: 2 }}
              required
            />

            <TextField
              fullWidth
              label={t('laneManager.dialog.descriptionLabel')}
              value={currentLane.description}
              onChange={(e) => setCurrentLane({ ...currentLane, description: e.target.value })}
              multiline
              rows={2}
              sx={{ mb: 2 }}
            />

            <TextField
              fullWidth
              label={t('laneManager.dialog.zoneLabel')}
              value={currentLane.metadata?.zone || ''}
              onChange={(e) => setCurrentLane({
                ...currentLane,
                metadata: {
                  ...currentLane.metadata,
                  zone: e.target.value,
                },
              })}
              sx={{ mb: 2 }}
              helperText={t('laneManager.dialog.zoneHelper')}
            />

            <TextField
              fullWidth
              label={t('laneManager.dialog.operatorLabel')}
              value={currentLane.metadata?.operator_info || ''}
              onChange={(e) => setCurrentLane({
                ...currentLane,
                metadata: {
                  ...currentLane.metadata,
                  operator_info: e.target.value,
                },
              })}
              helperText={t('laneManager.dialog.operatorHelper')}
            />
          </Box>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setDialogOpen(false)}>{t('laneManager.dialog.cancelButton')}</Button>
          <Button onClick={handleSave} variant="contained" color="primary">
            {editMode ? t('laneManager.dialog.updateButton') : t('laneManager.dialog.createButton')}
          </Button>
        </DialogActions>
      </Dialog>

      {/* Assign Device Dialog */}
      <Dialog open={deviceDialog.isOpen} onClose={deviceDialog.close} maxWidth="sm" fullWidth>
        <DialogTitle>{t('laneManager.deviceDialog.title')}</DialogTitle>
        <DialogContent>
          <Box sx={{ mt: 2 }}>
            <Alert severity="info" sx={{ mb: 2 }}>
              {t('laneManager.deviceDialog.infoMessage', { laneName: deviceDialog.data?.name })}
            </Alert>
            <TextField
              fullWidth
              label={t('laneManager.deviceDialog.deviceIdLabel')}
              value={deviceToAssign}
              onChange={(e) => setDeviceToAssign(e.target.value)}
              placeholder={t('laneManager.deviceDialog.deviceIdPlaceholder')}
            />
          </Box>
        </DialogContent>
        <DialogActions>
          <Button onClick={deviceDialog.close}>{t('laneManager.deviceDialog.cancelButton')}</Button>
          <Button onClick={handleAssignDevice} variant="contained" color="primary">
            {t('laneManager.deviceDialog.assignButton')}
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
};

export default LaneManager;

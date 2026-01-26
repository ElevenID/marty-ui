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
  Grid,
  Card,
  CardContent,
  CardActions,
  Tooltip,
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

const LaneManager = ({ deploymentProfile, onBack }) => {
  const [lanes, setLanes] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [dialogOpen, setDialogOpen] = useState(false);
  const [editMode, setEditMode] = useState(false);
  const [deviceDialogOpen, setDeviceDialogOpen] = useState(false);
  const [selectedLane, setSelectedLane] = useState(null);
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
  }, [deploymentProfile.id]);

  const loadLanes = async () => {
    setLoading(true);
    try {
      const data = await deploymentProfilesApi.listLanes(deploymentProfile.id);
      setLanes(data);
      setError(null);
    } catch (err) {
      console.error('Failed to load lanes:', err);
      setError('Failed to load lanes');
    } finally {
      setLoading(false);
    }
  };

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
      setError(`Failed to save: ${err.message}`);
    }
  };

  const handleDelete = async (laneId) => {
    if (!window.confirm('Are you sure you want to delete this lane?')) {
      return;
    }
    try {
      await deploymentProfilesApi.deleteLane(laneId);
      loadLanes();
    } catch (err) {
      console.error('Failed to delete lane:', err);
      setError(`Failed to delete: ${err.message}`);
    }
  };

  const handleOpenDeviceDialog = (lane) => {
    setSelectedLane(lane);
    setDeviceToAssign('');
    setDeviceDialogOpen(true);
  };

  const handleAssignDevice = async () => {
    if (!deviceToAssign || !selectedLane) return;
    try {
      await deploymentProfilesApi.assignDeviceToLane(selectedLane.id, deviceToAssign);
      setDeviceDialogOpen(false);
      loadLanes();
    } catch (err) {
      console.error('Failed to assign device:', err);
      setError(`Failed to assign device: ${err.message}`);
    }
  };

  const handleUnassignDevice = async (laneId, deviceId) => {
    if (!window.confirm('Remove this device from the lane?')) {
      return;
    }
    try {
      await deploymentProfilesApi.unassignDeviceFromLane(laneId, deviceId);
      loadLanes();
    } catch (err) {
      console.error('Failed to unassign device:', err);
      setError(`Failed to unassign device: ${err.message}`);
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
          <Typography variant="h4">Lanes - {deploymentProfile.name}</Typography>
          <Typography variant="body2" color="text.secondary">
            Manage processing lanes and device assignments
          </Typography>
        </Box>
        <Button
          variant="contained"
          color="primary"
          startIcon={<AddIcon />}
          onClick={handleCreate}
        >
          Create Lane
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
                    <strong>Zone:</strong> {lane.metadata.zone}
                  </Typography>
                )}
                
                {lane.metadata?.operator_info && (
                  <Typography variant="caption" display="block" mb={1}>
                    <strong>Operator:</strong> {lane.metadata.operator_info}
                  </Typography>
                )}

                <Typography variant="subtitle2" sx={{ mt: 2, mb: 1 }}>
                  Assigned Devices ({lane.assigned_devices?.length || 0})
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
                      No devices assigned
                    </Typography>
                  )}
                </List>
              </CardContent>
              <CardActions>
                <Button size="small" onClick={() => handleEdit(lane)}>
                  <EditIcon sx={{ mr: 0.5 }} fontSize="small" />
                  Edit
                </Button>
                <Button size="small" onClick={() => handleOpenDeviceDialog(lane)}>
                  <AddCircleIcon sx={{ mr: 0.5 }} fontSize="small" />
                  Assign Device
                </Button>
                <Button size="small" color="error" onClick={() => handleDelete(lane.id)}>
                  <DeleteIcon sx={{ mr: 0.5 }} fontSize="small" />
                  Delete
                </Button>
              </CardActions>
            </Card>
          </Grid>
        ))}
        {lanes.length === 0 && (
          <Grid item xs={12}>
            <Paper sx={{ p: 4, textAlign: 'center' }}>
              <Typography color="text.secondary">
                No lanes configured. Create a lane to define processing stations.
              </Typography>
            </Paper>
          </Grid>
        )}
      </Grid>

      {/* Create/Edit Lane Dialog */}
      <Dialog open={dialogOpen} onClose={() => setDialogOpen(false)} maxWidth="sm" fullWidth>
        <DialogTitle>
          {editMode ? 'Edit Lane' : 'Create Lane'}
        </DialogTitle>
        <DialogContent>
          <Box sx={{ mt: 2 }}>
            <TextField
              fullWidth
              label="Lane Name"
              value={currentLane.name}
              onChange={(e) => setCurrentLane({ ...currentLane, name: e.target.value })}
              sx={{ mb: 2 }}
              required
            />

            <TextField
              fullWidth
              label="Description"
              value={currentLane.description}
              onChange={(e) => setCurrentLane({ ...currentLane, description: e.target.value })}
              multiline
              rows={2}
              sx={{ mb: 2 }}
            />

            <TextField
              fullWidth
              label="Zone"
              value={currentLane.metadata?.zone || ''}
              onChange={(e) => setCurrentLane({
                ...currentLane,
                metadata: {
                  ...currentLane.metadata,
                  zone: e.target.value,
                },
              })}
              sx={{ mb: 2 }}
              helperText="e.g., 'Terminal A', 'North Wing'"
            />

            <TextField
              fullWidth
              label="Operator Info"
              value={currentLane.metadata?.operator_info || ''}
              onChange={(e) => setCurrentLane({
                ...currentLane,
                metadata: {
                  ...currentLane.metadata,
                  operator_info: e.target.value,
                },
              })}
              helperText="e.g., 'Station 12', 'Supervisor: John Doe'"
            />
          </Box>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setDialogOpen(false)}>Cancel</Button>
          <Button onClick={handleSave} variant="contained" color="primary">
            {editMode ? 'Update' : 'Create'}
          </Button>
        </DialogActions>
      </Dialog>

      {/* Assign Device Dialog */}
      <Dialog open={deviceDialogOpen} onClose={() => setDeviceDialogOpen(false)} maxWidth="sm" fullWidth>
        <DialogTitle>Assign Device to Lane</DialogTitle>
        <DialogContent>
          <Box sx={{ mt: 2 }}>
            <Alert severity="info" sx={{ mb: 2 }}>
              Enter the device ID to assign to {selectedLane?.name}
            </Alert>
            <TextField
              fullWidth
              label="Device ID"
              value={deviceToAssign}
              onChange={(e) => setDeviceToAssign(e.target.value)}
              placeholder="device-uuid-here"
            />
          </Box>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setDeviceDialogOpen(false)}>Cancel</Button>
          <Button onClick={handleAssignDevice} variant="contained" color="primary">
            Assign
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
};

export default LaneManager;

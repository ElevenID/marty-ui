/**
 * Device Management Page
 * 
 * Allows users to view and manage their registered devices
 */

import { useState, useEffect } from 'react';
import {
  Box,
  Typography,
  Paper,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  IconButton,
  Chip,
  Alert,
  Button,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogContentText,
  DialogActions,
  CircularProgress,
  Tooltip,
} from '@mui/material';
import DeleteIcon from '@mui/icons-material/Delete';
import PhoneAndroidIcon from '@mui/icons-material/PhoneAndroid';
import PhoneIphoneIcon from '@mui/icons-material/PhoneIphone';
import LaptopIcon from '@mui/icons-material/Laptop';
import RefreshIcon from '@mui/icons-material/Refresh';
import SecurityIcon from '@mui/icons-material/Security';
import { listDevices, unregisterDevice } from '../../../services/devicesApi';

const DeviceManagementPage = () => {
  const [devices, setDevices] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false);
  const [deviceToDelete, setDeviceToDelete] = useState(null);
  const [deleting, setDeleting] = useState(false);

  useEffect(() => {
    loadDevices();
  }, []);

  const loadDevices = async () => {
    try {
      setLoading(true);
      setError(null);
      const data = await listDevices();
      setDevices(data.devices || []);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleDeleteClick = (device) => {
    setDeviceToDelete(device);
    setDeleteDialogOpen(true);
  };

  const handleDeleteConfirm = async () => {
    if (!deviceToDelete) return;

    try {
      setDeleting(true);
      await unregisterDevice(deviceToDelete.device_id);
      setDevices(devices.filter((d) => d.device_id !== deviceToDelete.device_id));
      setDeleteDialogOpen(false);
      setDeviceToDelete(null);
    } catch (err) {
      setError(`Failed to unregister device: ${err.message}`);
    } finally {
      setDeleting(false);
    }
  };

  const handleDeleteCancel = () => {
    setDeleteDialogOpen(false);
    setDeviceToDelete(null);
  };

  const getPlatformIcon = (platform) => {
    switch (platform?.toLowerCase()) {
      case 'ios':
        return <PhoneIphoneIcon />;
      case 'android':
        return <PhoneAndroidIcon />;
      case 'web':
        return <LaptopIcon />;
      default:
        return <PhoneAndroidIcon />;
    }
  };

  const formatDate = (dateString) => {
    if (!dateString) return 'Never';
    try {
      return new Date(dateString).toLocaleString();
    } catch {
      return dateString;
    }
  };

  if (loading) {
    return (
      <Box sx={{ display: 'flex', justifyContent: 'center', py: 8 }}>
        <CircularProgress />
      </Box>
    );
  }

  return (
    <Box>
      <Box sx={{ mb: 3, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <Typography variant="h4" component="h1">
          Device Management
        </Typography>
        <Button
          startIcon={<RefreshIcon />}
          onClick={loadDevices}
          disabled={loading}
        >
          Refresh
        </Button>
      </Box>

      {error && (
        <Alert severity="error" onClose={() => setError(null)} sx={{ mb: 3 }}>
          {error}
        </Alert>
      )}

      <Alert severity="info" sx={{ mb: 3 }}>
        Registered devices can receive push notifications and securely sign verification challenges.
        Remove devices you no longer use to maintain security.
      </Alert>

      {devices.length === 0 ? (
        <Paper sx={{ p: 4, textAlign: 'center' }}>
          <SecurityIcon sx={{ fontSize: 80, color: 'text.secondary', mb: 2 }} />
          <Typography variant="h6" gutterBottom>
            No Devices Registered
          </Typography>
          <Typography variant="body2" color="text.secondary">
            Register your mobile wallet app to receive push notifications and use secure verification features.
          </Typography>
        </Paper>
      ) : (
        <TableContainer component={Paper}>
          <Table>
            <TableHead>
              <TableRow>
                <TableCell>Device</TableCell>
                <TableCell>Platform</TableCell>
                <TableCell>App Version</TableCell>
                <TableCell>Registered</TableCell>
                <TableCell>Last Seen</TableCell>
                <TableCell>Security</TableCell>
                <TableCell align="right">Actions</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {devices.map((device) => (
                <TableRow key={device.device_id}>
                  <TableCell>
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                      {getPlatformIcon(device.platform)}
                      <Box>
                        <Typography variant="body2" fontWeight="medium">
                          {device.device_id}
                        </Typography>
                        {device.is_active && (
                          <Chip label="Active" size="small" color="success" sx={{ mt: 0.5 }} />
                        )}
                      </Box>
                    </Box>
                  </TableCell>
                  <TableCell>
                    <Chip
                      label={device.platform?.toUpperCase() || 'Unknown'}
                      size="small"
                      variant="outlined"
                    />
                  </TableCell>
                  <TableCell>{device.app_version || 'N/A'}</TableCell>
                  <TableCell>{formatDate(device.created_at)}</TableCell>
                  <TableCell>{formatDate(device.last_seen_at)}</TableCell>
                  <TableCell>
                    {device.has_public_key ? (
                      <Tooltip title="Device has registered a public key for challenge signing">
                        <Chip
                          icon={<SecurityIcon />}
                          label="Secured"
                          size="small"
                          color="primary"
                          variant="outlined"
                        />
                      </Tooltip>
                    ) : (
                      <Chip label="Basic" size="small" variant="outlined" />
                    )}
                  </TableCell>
                  <TableCell align="right">
                    <Tooltip title="Unregister device">
                      <IconButton
                        size="small"
                        color="error"
                        onClick={() => handleDeleteClick(device)}
                      >
                        <DeleteIcon />
                      </IconButton>
                    </Tooltip>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>
      )}

      {/* Delete Confirmation Dialog */}
      <Dialog open={deleteDialogOpen} onClose={handleDeleteCancel}>
        <DialogTitle>Unregister Device?</DialogTitle>
        <DialogContent>
          <DialogContentText>
            Are you sure you want to unregister this device? This will prevent it from receiving
            push notifications and using secure verification features.
            {deviceToDelete && (
              <Box sx={{ mt: 2, p: 2, bgcolor: 'grey.100', borderRadius: 1 }}>
                <Typography variant="body2" fontWeight="medium">
                  Device ID: {deviceToDelete.device_id}
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  Platform: {deviceToDelete.platform?.toUpperCase()}
                </Typography>
              </Box>
            )}
          </DialogContentText>
        </DialogContent>
        <DialogActions>
          <Button onClick={handleDeleteCancel} disabled={deleting}>
            Cancel
          </Button>
          <Button onClick={handleDeleteConfirm} color="error" disabled={deleting}>
            {deleting ? <CircularProgress size={20} /> : 'Unregister'}
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
};

export default DeviceManagementPage;

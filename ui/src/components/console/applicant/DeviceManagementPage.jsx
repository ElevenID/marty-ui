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
import { useTranslation } from 'react-i18next';
import { useDialog } from '../../../hooks/useDialog';
import { listDevices, unregisterDevice } from '../../../services/devicesApi';

const DeviceManagementPage = () => {
  const { t } = useTranslation('applicant');
  const [devices, setDevices] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const deleteDialog = useDialog();
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

  const handleDeleteConfirm = async () => {
    try {
      setDeleting(true);
      await unregisterDevice(deleteDialog.data.device_id);
      setDevices(devices.filter((d) => d.device_id !== deleteDialog.data.device_id));
      deleteDialog.close();
    } catch (err) {
      setError(t('devices.errorUnregistering', { message: err.message }));
    } finally {
      setDeleting(false);
    }
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
    if (!dateString) return t('devices.formatDate.never');
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
          {t('devices.title')}
        </Typography>
        <Button
          startIcon={<RefreshIcon />}
          onClick={loadDevices}
          disabled={loading}
        >
          {t('devices.refresh')}
        </Button>
      </Box>

      {error && (
        <Alert severity="error" onClose={() => setError(null)} sx={{ mb: 3 }}>
          {error}
        </Alert>
      )}

      <Alert severity="info" sx={{ mb: 3 }}>
        {t('devices.info')}
      </Alert>

      {devices.length === 0 ? (
        <Paper sx={{ p: 4, textAlign: 'center' }}>
          <SecurityIcon sx={{ fontSize: 80, color: 'text.secondary', mb: 2 }} />
          <Typography variant="h6" gutterBottom>
            {t('devices.empty.title')}
          </Typography>
          <Typography variant="body2" color="text.secondary">
            {t('devices.empty.description')}
          </Typography>
        </Paper>
      ) : (
        <TableContainer component={Paper}>
          <Table>
            <TableHead>
              <TableRow>
                <TableCell>{t('devices.tableHeaders.device')}</TableCell>
                <TableCell>{t('devices.tableHeaders.platform')}</TableCell>
                <TableCell>{t('devices.tableHeaders.appVersion')}</TableCell>
                <TableCell>{t('devices.tableHeaders.registered')}</TableCell>
                <TableCell>{t('devices.tableHeaders.lastSeen')}</TableCell>
                <TableCell>{t('devices.tableHeaders.security')}</TableCell>
                <TableCell align="right">{t('devices.tableHeaders.actions')}</TableCell>
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
                          <Chip label={t('devices.status.active')} size="small" color="success" sx={{ mt: 0.5 }} />
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
                      <Tooltip title={t('devices.security.hasPublicKey')}>
                        <Chip
                          icon={<SecurityIcon />}
                          label={t('devices.status.secured')}
                          size="small"
                          color="primary"
                          variant="outlined"
                        />
                      </Tooltip>
                    ) : (
                      <Chip label={t('devices.status.basic')} size="small" variant="outlined" />
                    )}
                  </TableCell>
                  <TableCell align="right">
                    <Tooltip title={t('devices.actions.unregister')}>
                      <IconButton
                        size="small"
                        color="error"
                        onClick={() => deleteDialog.open(device)}
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
      <Dialog open={deleteDialog.isOpen} onClose={deleteDialog.close}>
        <DialogTitle>{t('devices.unregisterDialog.title')}</DialogTitle>
        <DialogContent>
          <DialogContentText>
            {t('devices.unregisterDialog.message')}
            {deleteDialog.data && (
              <Box sx={{ mt: 2, p: 2, bgcolor: 'grey.100', borderRadius: 1 }}>
                <Typography variant="body2" fontWeight="medium">
                  {t('devices.unregisterDialog.deviceId', { deviceId: deleteDialog.data.device_id })}
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  {t('devices.unregisterDialog.platform', { platform: deleteDialog.data.platform?.toUpperCase() })}
                </Typography>
              </Box>
            )}
          </DialogContentText>
        </DialogContent>
        <DialogActions>
          <Button onClick={deleteDialog.close} disabled={deleting}>
            {t('actions.cancel', { ns: 'common' })}
          </Button>
          <Button onClick={handleDeleteConfirm} color="error" disabled={deleting}>
            {deleting ? t('devices.unregisterDialog.unregistering') : t('devices.unregisterDialog.confirm')}
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
};

export default DeviceManagementPage;

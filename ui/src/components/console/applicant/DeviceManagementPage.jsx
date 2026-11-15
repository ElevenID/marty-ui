/** View the authenticated user's registrations and deactivate an owned device. */

import { useCallback, useEffect, useLayoutEffect, useRef, useState } from 'react';
import {
  Alert, Box, Button, Chip, Dialog, DialogActions, DialogContent, DialogContentText,
  DialogTitle, IconButton, LinearProgress, Paper, Table, TableBody, TableCell,
  TableContainer, TableHead, TableRow, Tooltip, Typography,
} from '@mui/material';
import DeleteIcon from '@mui/icons-material/Delete';
import RefreshIcon from '@mui/icons-material/Refresh';
import { useTranslation } from 'react-i18next';
import { useAuth } from '../../../hooks/useAuth';
import { listDevices, unregisterDevice } from '../../../services/devicesApi';

function DeviceManagementContent({ principalId }) {
  const { t } = useTranslation('applicant');
  const [devices, setDevices] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [selectedDevice, setSelectedDevice] = useState(null);
  const [deleting, setDeleting] = useState(false);
  const [deleteError, setDeleteError] = useState(null);
  const active = useRef(false);
  const request = useRef(0);
  const pendingDelete = useRef(false);

  useLayoutEffect(() => {
    active.current = true;
    return () => { active.current = false; request.current += 1; };
  }, []);

  const loadDevices = useCallback(async () => {
    const generation = ++request.current;
    const isCurrent = () => active.current && request.current === generation;
    setLoading(true);
    setError(null);
    try {
      const data = await listDevices(null, { userId: principalId, isCurrent });
      if (isCurrent()) setDevices(data);
    } catch (err) {
      if (isCurrent()) setError(err);
    } finally {
      if (isCurrent()) setLoading(false);
    }
  }, [principalId]);

  useEffect(() => { loadDevices(); }, [loadDevices]);

  const closeDialog = () => {
    if (pendingDelete.current) return;
    setSelectedDevice(null);
    setDeleteError(null);
  };

  const handleDeleteConfirm = async () => {
    if (!active.current || pendingDelete.current || !selectedDevice) return;
    const device = devices.find(item => item.id === selectedDevice.id && item.is_active);
    if (!device) return;
    pendingDelete.current = true;
    setDeleting(true);
    setDeleteError(null);
    // A pending refresh must not restore the former active state after deactivation.
    request.current += 1;
    setLoading(false);
    try {
      await unregisterDevice(device.id);
      if (!active.current) return;
      setDevices(current => current.map(item => item.id === device.id ? { ...item, is_active: false } : item));
      setSelectedDevice(null);
    } catch (err) {
      if (active.current) setDeleteError(err);
    } finally {
      if (active.current) {
        pendingDelete.current = false;
        setDeleting(false);
      }
    }
  };

  const formatDate = (value) => {
    const parsed = value ? new Date(value) : null;
    return parsed && !Number.isNaN(parsed.getTime()) ? parsed.toLocaleString() : t('devices.notReported');
  };

  return (
    <Box sx={{ minWidth: 0, maxWidth: '100%' }}>
      <Box sx={{ mb: 3, display: 'flex', flexWrap: 'wrap', gap: 2, justifyContent: 'space-between', alignItems: 'center' }}>
        <Typography variant="h4" component="h1">{t('devices.title')}</Typography>
        <Button startIcon={<RefreshIcon />} onClick={loadDevices} disabled={loading || deleting}>
          {t('devices.refresh')}
        </Button>
      </Box>
      <Alert severity="info" sx={{ mb: 3 }}>{t('devices.info')}</Alert>
      {loading ? <LinearProgress aria-label={t('devices.loading')} /> : error ? (
        <Alert severity="error" action={<Button color="inherit" onClick={loadDevices}>{t('actions.retry', { ns: 'common' })}</Button>}>
          {error?.message?.trim() || t('devices.errorLoading')}
        </Alert>
      ) : devices.length === 0 ? (
        <Paper sx={{ p: 4, textAlign: 'center' }}>
          <Typography variant="h6" gutterBottom>{t('devices.empty.title')}</Typography>
          <Typography variant="body2" color="text.secondary">{t('devices.empty.description')}</Typography>
        </Paper>
      ) : (
        <TableContainer component={Paper} role="region" aria-label={t('devices.tableLabel')} tabIndex={0} sx={{ maxWidth: '100%' }}>
          <Table sx={{ minWidth: 720 }}>
            <TableHead>
              <TableRow>
                {['device', 'platform', 'appVersion', 'registered', 'lastSeen', 'status'].map(field => (
                  <TableCell key={field}>{t(`devices.tableHeaders.${field}`)}</TableCell>
                ))}
                <TableCell align="right">{t('devices.tableHeaders.actions')}</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {devices.map(device => (
                <TableRow key={device.id}>
                  <TableCell sx={{ overflowWrap: 'anywhere', maxWidth: 280 }}>
                    {device.device_model && <Typography variant="body2" sx={{ fontWeight: 500 }}>{device.device_model}</Typography>}
                    <Typography variant="body2">{device.device_id}</Typography>
                  </TableCell>
                  <TableCell>{device.platform.toUpperCase()}</TableCell>
                  <TableCell>{device.app_version || t('devices.notReported')}</TableCell>
                  <TableCell>{formatDate(device.created_at)}</TableCell>
                  <TableCell>{formatDate(device.last_seen_at)}</TableCell>
                  <TableCell><Chip label={t(device.is_active ? 'devices.status.active' : 'devices.status.inactive')} size="small" /></TableCell>
                  <TableCell align="right">
                    {device.is_active && (
                      <Tooltip title={t('devices.actions.unregister')}>
                        <IconButton
                          aria-label={t('devices.actions.unregisterNamed', { deviceId: device.device_id })}
                          size="small"
                          color="error"
                          onClick={() => { setSelectedDevice(device); setDeleteError(null); }}
                        >
                          <DeleteIcon />
                        </IconButton>
                      </Tooltip>
                    )}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>
      )}
      <Dialog open={Boolean(selectedDevice)} onClose={closeDialog} aria-labelledby="unregister-device-title" aria-describedby="unregister-device-description">
        <DialogTitle id="unregister-device-title">{t('devices.unregisterDialog.title')}</DialogTitle>
        <DialogContent>
          <DialogContentText id="unregister-device-description">{t('devices.unregisterDialog.message')}</DialogContentText>
          {selectedDevice && (
            <Box sx={{ mt: 2, p: 2, bgcolor: 'action.hover', borderRadius: 1, overflowWrap: 'anywhere' }}>
              <Typography variant="body2" sx={{ fontWeight: 500 }}>{t('devices.unregisterDialog.deviceId', { deviceId: selectedDevice.device_id })}</Typography>
              <Typography variant="body2" color="text.secondary">{t('devices.unregisterDialog.platform', { platform: selectedDevice.platform.toUpperCase() })}</Typography>
            </Box>
          )}
          {deleteError && <Alert severity="error" sx={{ mt: 2 }}>{deleteError?.message?.trim() || t('devices.errorUnregisteringFallback')}</Alert>}
        </DialogContent>
        <DialogActions>
          <Button onClick={closeDialog} disabled={deleting}>{t('actions.cancel', { ns: 'common' })}</Button>
          <Button onClick={handleDeleteConfirm} color="error" disabled={deleting}>
            {deleting ? t('devices.unregisterDialog.unregistering') : deleteError ? t('actions.retry', { ns: 'common' }) : t('devices.unregisterDialog.confirm')}
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
}

function DeviceManagementPage() {
  const { t } = useTranslation('applicant');
  const { user, isAuthenticated, isLoading } = useAuth();
  const principalId = user?.user_id || user?.sub || user?.id || null;
  if (isLoading) return <LinearProgress aria-label={t('devices.loading')} />;
  if (!isAuthenticated || !principalId) return <Alert severity="info">{t('devices.signInRequired')}</Alert>;
  return <DeviceManagementContent key={principalId} principalId={principalId} />;
}

export default DeviceManagementPage;

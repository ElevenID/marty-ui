/**
 * Flow Disable Dialog
 * 
 * Confirms disabling a flow to prevent new applications.
 */

import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import {
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Button,
  TextField,
  Alert,
  CircularProgress,
  IconButton,
  Typography,
} from '@mui/material';
import BlockIcon from '@mui/icons-material/Block';
import CloseIcon from '@mui/icons-material/Close';
import PropTypes from 'prop-types';
import flowsApi from '../../services/flowsApi';

function FlowDisableDialog({ open, onClose, flow, onDisabled }) {
  const { t } = useTranslation('vendor');
  const [reason, setReason] = useState('');
  const [disabling, setDisabling] = useState(false);
  const [error, setError] = useState(null);

  const handleDisable = async () => {
    if (!reason.trim()) {
      setError(t('flowDisableDialog.reasonError'));
      return;
    }

    setDisabling(true);
    setError(null);

    try {
      const result = await flowsApi.disableFlow(flow.id, { reason });
      
      if (onDisabled) {
        onDisabled(result);
      }
      
      handleClose();
    } catch (err) {
      setError(err.message || t('flowDisableDialog.failedToDisable'));
    } finally {
      setDisabling(false);
    }
  };

  const handleClose = () => {
    setReason('');
    setError(null);
    onClose();
  };

  return (
    <Dialog open={open} onClose={handleClose} maxWidth="sm" fullWidth>
      <DialogTitle>
        {t('flowDisableDialog.title')}
        <IconButton
          onClick={handleClose}
          sx={{ position: 'absolute', right: 8, top: 8 }}
        >
          <CloseIcon />
        </IconButton>
      </DialogTitle>
      
      <DialogContent>
        {error && (
          <Alert severity="error" sx={{ mb: 2 }}>
            {error}
          </Alert>
        )}

        <Alert severity="warning" sx={{ mb: 3 }}>
          {t('flowDisableDialog.warningMessage')}
        </Alert>

        <Typography variant="body2" color="text.secondary" gutterBottom>
          <strong>{t('flowDisableDialog.flowNameLabel')}:</strong> {flow?.name || t('flowDisableDialog.unknown')}
        </Typography>
        
        <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
          <strong>{t('flowDisableDialog.statusLabel')}:</strong> {flow?.status || t('flowDisableDialog.unknown')}
        </Typography>

        <TextField
          fullWidth
          required
          multiline
          rows={3}
          label={t('flowDisableDialog.reasonLabel')}
          placeholder={t('flowDisableDialog.reasonPlaceholder')}
          value={reason}
          onChange={(e) => setReason(e.target.value)}
          error={!reason && error}
          helperText={!reason && error ? t('flowDisableDialog.reasonRequired') : ''}
        />
      </DialogContent>

      <DialogActions>
        <Button onClick={handleClose}>
          {t('flowDisableDialog.cancel')}
        </Button>
        <Button
          variant="contained"
          color="error"
          onClick={handleDisable}
          disabled={disabling}
          startIcon={disabling ? <CircularProgress size={16} /> : <BlockIcon />}
        >
          {disabling ? t('flowDisableDialog.disabling') : t('flowDisableDialog.disableButton')}
        </Button>
      </DialogActions>
    </Dialog>
  );
}

FlowDisableDialog.propTypes = {
  open: PropTypes.bool.isRequired,
  onClose: PropTypes.func.isRequired,
  flow: PropTypes.object,
  onDisabled: PropTypes.func,
};

export default FlowDisableDialog;

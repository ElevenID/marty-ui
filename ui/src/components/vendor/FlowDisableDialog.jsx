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
import {
  disableFlowDefinition,
  getFlowDisableFailureState,
  getFlowDisableInitialState,
  resetFlowDisableState,
  validateFlowDisableReason,
} from '../../application/flows';

function FlowDisableDialog({ open, onClose, flow, onDisabled }) {
  const { t } = useTranslation('vendor');
  const [state, setState] = useState(getFlowDisableInitialState());
  const { reason, disabling, error } = state;

  const handleDisable = async () => {
    const validation = validateFlowDisableReason({
      reason,
      reasonErrorMessage: t('flowDisableDialog.reasonError'),
    });

    if (!validation.valid) {
      setState((currentState) => ({
        ...currentState,
        error: validation.error,
      }));
      return;
    }

    setState((currentState) => ({
      ...currentState,
      disabling: true,
      error: null,
    }));

    try {
      const { result } = await disableFlowDefinition({
        disableFlow: flowsApi.disableFlow,
        flow,
        reason,
      });
      
      if (onDisabled) {
        onDisabled(result);
      }
      
      handleClose();
    } catch (err) {
      setState((currentState) => ({
        ...currentState,
        ...getFlowDisableFailureState({
          error: err,
          fallbackMessage: t('flowDisableDialog.failedToDisable'),
        }),
      }));
    }
  };

  const handleClose = () => {
    setState(resetFlowDisableState());
    onClose();
  };

  return (
    <Dialog open={open} onClose={handleClose} maxWidth="sm" fullWidth>
      <DialogTitle>
        {t('flowDisableDialog.title')}
        <IconButton
          onClick={handleClose}
          aria-label="close"
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
          onChange={(e) => setState((currentState) => ({
            ...currentState,
            reason: e.target.value,
          }))}
          error={Boolean(!reason && error)}
          helperText={!reason && error ? t('flowDisableDialog.reasonRequired') : ''}
          slotProps={{
            htmlInput: {
              'aria-label': t('flowDisableDialog.reasonLabel'),
            }
          }}
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

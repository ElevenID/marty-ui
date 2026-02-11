/**
 * Flow Disable Dialog
 * 
 * Confirms disabling a flow to prevent new applications.
 */

import { useState } from 'react';
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
  const [reason, setReason] = useState('');
  const [disabling, setDisabling] = useState(false);
  const [error, setError] = useState(null);

  const handleDisable = async () => {
    if (!reason.trim()) {
      setError('Please provide a reason for disabling this flow');
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
      setError(err.message || 'Failed to disable flow');
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
        Disable Flow
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
          Disabling this flow will prevent new applications. Existing applications will continue processing.
        </Alert>

        <Typography variant="body2" color="text.secondary" gutterBottom>
          <strong>Flow Name:</strong> {flow?.name || 'Unknown'}
        </Typography>
        
        <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
          <strong>Status:</strong> {flow?.status || 'Unknown'}
        </Typography>

        <TextField
          fullWidth
          required
          multiline
          rows={3}
          label="Reason for Disabling"
          placeholder="Explain why this flow is being disabled..."
          value={reason}
          onChange={(e) => setReason(e.target.value)}
          error={!reason && error}
          helperText={!reason && error ? 'Reason is required' : ''}
        />
      </DialogContent>

      <DialogActions>
        <Button onClick={handleClose}>
          Cancel
        </Button>
        <Button
          variant="contained"
          color="error"
          onClick={handleDisable}
          disabled={disabling}
          startIcon={disabling ? <CircularProgress size={16} /> : <BlockIcon />}
        >
          {disabling ? 'Disabling...' : 'Disable Flow'}
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

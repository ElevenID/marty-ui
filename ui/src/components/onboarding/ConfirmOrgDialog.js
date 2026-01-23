/**
 * Confirm Organization Selection Dialog
 * 
 * Dialog to confirm organization selection before joining
 */

import React from 'react';
import {
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Box,
  Typography,
  Paper,
  Button,
  Alert,
} from '@mui/material';
import WarningAmberIcon from '@mui/icons-material/WarningAmber';
import MembershipModeChip from './MembershipModeChip';

const ConfirmOrgDialog = ({
  open,
  onClose,
  organization,
  submitting,
  onConfirm,
}) => {
  return (
    <Dialog open={open} onClose={onClose} maxWidth="sm" fullWidth>
      <DialogTitle>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          <WarningAmberIcon color="warning" />
          Confirm Organization Selection
        </Box>
      </DialogTitle>
      <DialogContent>
        {organization && (
          <>
            <Alert severity="warning" sx={{ mb: 3 }}>
              Please verify that you want to join the following organization:
            </Alert>
            <Paper variant="outlined" sx={{ p: 2, bgcolor: 'grey.50' }}>
              <Typography variant="h6">{organization.name}</Typography>
              {organization.description && (
                <Typography variant="body2" color="text.secondary">
                  {organization.description}
                </Typography>
              )}
              <Box sx={{ mt: 1 }}>
                <MembershipModeChip mode={organization.membership_mode} />
              </Box>
            </Paper>
            {organization.membership_mode === 'approval' && (
              <Alert severity="info" sx={{ mt: 2 }}>
                This organization requires approval. Your request will be reviewed by an administrator.
              </Alert>
            )}
          </>
        )}
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose}>Cancel</Button>
        <Button
          variant="contained"
          onClick={onConfirm}
          disabled={submitting}
        >
          {submitting ? 'Processing...' : 'Confirm & Join'}
        </Button>
      </DialogActions>
    </Dialog>
  );
};

export default ConfirmOrgDialog;

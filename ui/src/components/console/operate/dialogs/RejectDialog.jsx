/**
 * RejectDialog
 *
 * Confirmation sheet for rejecting a credential application.
 * Requires a reason selection; optionally notifies the applicant.
 */

import { useState } from 'react';
import {
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Button,
  TextField,
  Typography,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  FormControlLabel,
  Checkbox,
  Box,
  CircularProgress,
} from '@mui/material';
import CancelIcon from '@mui/icons-material/Cancel';

const REJECTION_REASONS = [
  { value: 'missing_document', label: 'Missing document' },
  { value: 'data_mismatch', label: 'Data mismatch' },
  { value: 'identity_not_verified', label: 'Identity could not be verified' },
  { value: 'suspicious_activity', label: 'Suspicious activity' },
  { value: 'duplicate_application', label: 'Duplicate application' },
  { value: 'ineligible', label: 'Applicant ineligible per policy' },
  { value: 'other', label: 'Other' },
];

export default function RejectDialog({ open, application, loading, onConfirm, onClose }) {
  const [reason, setReason] = useState('');
  const [notes, setNotes] = useState('');
  const [notify, setNotify] = useState(true);

  if (!application) return null;

  const credentialDisplay = application.credential_display_name || application.credential_template_id;

  const handleConfirm = () => {
    if (!reason) return;
    const reasonLabel = REJECTION_REASONS.find(r => r.value === reason)?.label || reason;
    onConfirm({ reason: reasonLabel, notes, notifyApplicant: notify });
  };

  return (
    <Dialog open={open} onClose={onClose} maxWidth="sm" fullWidth>
      <DialogTitle sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
        <CancelIcon color="error" />
        Reject Application
      </DialogTitle>
      <DialogContent dividers>
        <Typography variant="body2" color="text.secondary" gutterBottom>
          Rejecting this application will prevent credential issuance for <strong>{credentialDisplay}</strong>.
          The application data will be retained for audit purposes.
        </Typography>

        <Box sx={{ mt: 2 }}>
          <FormControl fullWidth size="small" required sx={{ mb: 2 }}>
            <InputLabel>Rejection Reason *</InputLabel>
            <Select
              value={reason}
              label="Rejection Reason *"
              onChange={e => setReason(e.target.value)}
            >
              {REJECTION_REASONS.map(r => (
                <MenuItem key={r.value} value={r.value}>{r.label}</MenuItem>
              ))}
            </Select>
          </FormControl>

          <TextField
            label="Additional notes (optional)"
            multiline
            rows={3}
            fullWidth
            size="small"
            value={notes}
            onChange={e => setNotes(e.target.value)}
            placeholder="Provide any additional context for the rejection…"
            sx={{ mb: 2 }}
          />

          <FormControlLabel
            control={<Checkbox checked={notify} onChange={e => setNotify(e.target.checked)} />}
            label="Notify applicant of rejection"
          />
        </Box>
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose} disabled={loading}>Cancel</Button>
        <Button
          variant="contained"
          color="error"
          onClick={handleConfirm}
          disabled={loading || !reason}
          startIcon={loading ? <CircularProgress size={16} color="inherit" /> : <CancelIcon />}
        >
          Confirm Rejection
        </Button>
      </DialogActions>
    </Dialog>
  );
}

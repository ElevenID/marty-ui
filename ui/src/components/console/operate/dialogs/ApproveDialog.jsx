/**
 * ApproveDialog
 *
 * Confirmation sheet for approving an application.
 * Shows credential preview, claims to be issued, expiry, and lets
 * the reviewer add an optional note before confirming.
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
  Box,
  Chip,
  Divider,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  CircularProgress,
} from '@mui/material';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import VerifiedIcon from '@mui/icons-material/Verified';
import { CHECK_STATUS_COLORS, CHECK_STATUS_LABELS } from '../../../../config/checkConstants';

export default function ApproveDialog({ open, application, checks, initialNote, loading, onConfirm, onClose }) {
  const [note, setNote] = useState(initialNote || '');

  if (!application) return null;

  const credentialDisplay = application.credential_display_name || application.credential_template_id;
  const applicantName = [application.applicant_given_name, application.applicant_family_name].filter(Boolean).join(' ')
    || application.applicant_email || application.applicant_id;

  const failedChecks = checks.filter(c => ['failed', 'completed_failed'].includes(c.status));
  const pendingChecks = checks.filter(c => ['not_started', 'pending', 'in_progress'].includes(c.status));

  const handleConfirm = () => {
    onConfirm({ notes: note });
  };

  return (
    <Dialog open={open} onClose={onClose} maxWidth="sm" fullWidth>
      <DialogTitle sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
        <VerifiedIcon color="success" />
        Approve Application
      </DialogTitle>
      <DialogContent dividers>
        <Typography variant="body2" color="text.secondary" gutterBottom>
          You are about to approve this application and trigger credential issuance.
        </Typography>

        {/* Credential summary */}
        <Box sx={{ bgcolor: 'success.50', border: '1px solid', borderColor: 'success.light', borderRadius: 1, p: 2, my: 2 }}>
          <Typography variant="subtitle2" fontWeight="bold">{credentialDisplay}</Typography>
          <Typography variant="body2" color="text.secondary">Applicant: {applicantName}</Typography>
          {application.requested_validity_years && (
            <Chip label={`Valid for ${application.requested_validity_years} year(s)`} size="small" sx={{ mt: 0.5 }} />
          )}
        </Box>

        {/* Warn about outstanding issues */}
        {failedChecks.length > 0 && (
          <Box sx={{ bgcolor: 'error.50', border: '1px solid', borderColor: 'error.light', borderRadius: 1, p: 1.5, mb: 2 }}>
            <Typography variant="caption" color="error.main" fontWeight="medium">
              ⚠ {failedChecks.length} check(s) failed. Approving overrides these failures.
            </Typography>
          </Box>
        )}
        {pendingChecks.length > 0 && (
          <Box sx={{ bgcolor: 'warning.50', border: '1px solid', borderColor: 'warning.light', borderRadius: 1, p: 1.5, mb: 2 }}>
            <Typography variant="caption" color="warning.dark" fontWeight="medium">
              {pendingChecks.length} check(s) still pending. Approving will proceed without them.
            </Typography>
          </Box>
        )}

        <Divider sx={{ my: 2 }} />

        <Typography variant="subtitle2" gutterBottom>Check Summary</Typography>
        {checks.length === 0 ? (
          <Typography variant="body2" color="text.secondary">No checks defined.</Typography>
        ) : (
          <List dense disablePadding>
            {checks.map(c => (
              <ListItem key={c.id} disableGutters>
                <ListItemIcon sx={{ minWidth: 32 }}>
                  <CheckCircleIcon
                    fontSize="small"
                    color={['passed', 'completed_passed'].includes(c.status) ? 'success' : 'disabled'}
                  />
                </ListItemIcon>
                <ListItemText
                  primary={c.custom_name || c.check_type.replace(/_/g, ' ')}
                  secondary={CHECK_STATUS_LABELS[c.status] || c.status}
                  primaryTypographyProps={{ variant: 'body2' }}
                  secondaryTypographyProps={{ variant: 'caption' }}
                />
                <Chip label={CHECK_STATUS_LABELS[c.status] || c.status} size="small" color={CHECK_STATUS_COLORS[c.status] || 'default'} />
              </ListItem>
            ))}
          </List>
        )}

        <Divider sx={{ my: 2 }} />

        <TextField
          label="Approval note (optional)"
          multiline
          rows={2}
          fullWidth
          size="small"
          value={note}
          onChange={e => setNote(e.target.value)}
          placeholder="E.g. All documents verified, fast-track approved."
        />
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose} disabled={loading}>Cancel</Button>
        <Button
          variant="contained"
          color="success"
          onClick={handleConfirm}
          disabled={loading}
          startIcon={loading ? <CircularProgress size={16} color="inherit" /> : <VerifiedIcon />}
        >
          Confirm Approval
        </Button>
      </DialogActions>
    </Dialog>
  );
}

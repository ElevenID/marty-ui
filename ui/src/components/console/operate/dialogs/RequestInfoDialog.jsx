/**
 * RequestInfoDialog
 *
 * Allows a reviewer to request additional information from the applicant.
 * Shows a checklist of possible missing items (from checks + template),
 * a free-text message, and an optional deadline.
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
  CircularProgress,
  Chip,
  Stack,
} from '@mui/material';
import HelpOutlineIcon from '@mui/icons-material/HelpOutlined';
import { CHECK_TYPE_LABELS } from '../../../../config/checkConstants';

const QUICK_ITEMS = [
  'Government-issued photo ID',
  'Proof of address',
  'Proof of employment',
  'Educational certificates',
  'Biometric data',
  'Signature',
  'Notarised documents',
];

export default function RequestInfoDialog({ open, application, checks, loading, onConfirm, onClose }) {
  const [selected, setSelected] = useState([]);
  const [message, setMessage] = useState('');
  const [deadline, setDeadline] = useState('');

  if (!application) return null;

  // Build checklist: quick items + any failed/pending checks
  const checkItems = checks
    .filter(c => ['not_started', 'pending', 'failed', 'completed_failed'].includes(c.status))
    .map(c => c.custom_name || CHECK_TYPE_LABELS[c.check_type] || c.check_type);

  const allItems = [...new Set([...QUICK_ITEMS, ...checkItems])];

  const toggleItem = (item) => {
    setSelected(prev =>
      prev.includes(item) ? prev.filter(i => i !== item) : [...prev, item]
    );
  };

  const handleChipClick = (item) => toggleItem(item);

  const handleConfirm = () => {
    onConfirm({
      missingItems: selected,
      message,
      deadline: deadline || null,
    });
  };

  return (
    <Dialog open={open} onClose={onClose} maxWidth="sm" fullWidth>
      <DialogTitle sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
        <HelpOutlineIcon color="info" />
        Request Additional Information
      </DialogTitle>
      <DialogContent dividers>
        <Typography variant="body2" color="text.secondary" gutterBottom>
          The application will move to <strong>Needs Info</strong> status and
          the applicant will be notified to provide the selected items.
        </Typography>

        <Typography variant="subtitle2" sx={{ mt: 2, mb: 1 }}>
          Missing items (select all that apply)
        </Typography>
        <Stack direction="row" flexWrap="wrap" gap={1} sx={{ mb: 2 }}>
          {allItems.map(item => (
            <Chip
              key={item}
              label={item}
              size="small"
              onClick={() => handleChipClick(item)}
              color={selected.includes(item) ? 'primary' : 'default'}
              variant={selected.includes(item) ? 'filled' : 'outlined'}
              clickable
            />
          ))}
        </Stack>

        <TextField
          label="Message to applicant"
          multiline
          rows={3}
          fullWidth
          size="small"
          value={message}
          onChange={e => setMessage(e.target.value)}
          placeholder="Explain what is needed and why…"
          sx={{ mb: 2 }}
        />

        <TextField
          label="Deadline (optional)"
          type="date"
          fullWidth
          size="small"
          value={deadline}
          onChange={e => setDeadline(e.target.value)}
          slotProps={{
            inputLabel: { shrink: true }
          }}
        />
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose} disabled={loading}>Cancel</Button>
        <Button
          variant="contained"
          color="info"
          onClick={handleConfirm}
          disabled={loading || (selected.length === 0 && !message)}
          startIcon={loading ? <CircularProgress size={16} color="inherit" /> : <HelpOutlineIcon />}
        >
          Send Request
        </Button>
      </DialogActions>
    </Dialog>
  );
}

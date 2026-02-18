/**
 * CheckConfigurationDialog
 *
 * Dialog for configuring the required vetting checks on an Application Template.
 * Each check entry can define: type, required/optional, order, optional webhook URL.
 */

import { useState, useEffect } from 'react';
import {
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Button,
  Typography,
  Box,
  IconButton,
  Tooltip,
  Chip,
  TextField,
  Switch,
  FormControlLabel,
  Divider,
  Alert,
  CircularProgress,
  Select,
  MenuItem,
  FormControl,
  InputLabel,
} from '@mui/material';
import AddIcon from '@mui/icons-material/Add';
import DeleteIcon from '@mui/icons-material/Delete';
import DragIndicatorIcon from '@mui/icons-material/DragIndicator';
import WebhookIcon from '@mui/icons-material/Webhook';
import SaveIcon from '@mui/icons-material/Save';
import { updateTemplateRequiredChecks } from '../../../services/applicationTemplatesApi';
import { CHECK_TYPE_LABELS, CHECK_TYPE_ICONS, ALL_CHECK_TYPES } from '../../../config/checkConstants';

function CheckRow({ check, index, onChange, onRemove }) {
  const [showWebhook, setShowWebhook] = useState(!!(check.webhook_url || check.external_provider));
  const Icon = CHECK_TYPE_ICONS[check.check_type] || CHECK_TYPE_ICONS['custom'];

  return (
    <Box
      sx={{
        display: 'flex',
        flexDirection: 'column',
        gap: 1,
        p: 2,
        border: '1px solid',
        borderColor: 'divider',
        borderRadius: 2,
        bgcolor: 'background.paper',
      }}
    >
      {/* Header row */}
      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
        <Tooltip title="Drag to reorder">
          <DragIndicatorIcon sx={{ color: 'text.disabled', cursor: 'grab' }} />
        </Tooltip>
        <Chip label={index + 1} size="small" sx={{ minWidth: 32 }} />
        <Icon sx={{ color: 'text.secondary', fontSize: 20 }} />
        <FormControl size="small" sx={{ flex: 1 }}>
          <InputLabel>Check Type</InputLabel>
          <Select
            label="Check Type"
            value={check.check_type}
            onChange={(e) => onChange({ ...check, check_type: e.target.value })}
          >
            {ALL_CHECK_TYPES.map((type) => (
              <MenuItem key={type} value={type}>
                {CHECK_TYPE_LABELS[type] || type}
              </MenuItem>
            ))}
          </Select>
        </FormControl>
        <FormControlLabel
          control={
            <Switch
              checked={check.is_required !== false}
              onChange={(e) => onChange({ ...check, is_required: e.target.checked })}
              size="small"
              color="warning"
            />
          }
          label={<Typography variant="caption">{check.is_required !== false ? 'Required' : 'Optional'}</Typography>}
          sx={{ m: 0, whiteSpace: 'nowrap' }}
        />
        <Tooltip title="Configure external webhook">
          <IconButton size="small" onClick={() => setShowWebhook((v) => !v)} color={showWebhook ? 'primary' : 'default'}>
            <WebhookIcon fontSize="small" />
          </IconButton>
        </Tooltip>
        <Tooltip title="Remove check">
          <IconButton size="small" color="error" onClick={onRemove}>
            <DeleteIcon fontSize="small" />
          </IconButton>
        </Tooltip>
      </Box>

      {/* Custom name (only for CUSTOM type) */}
      {check.check_type === 'custom' && (
        <TextField
          size="small"
          label="Custom check name"
          value={check.custom_name || ''}
          onChange={(e) => onChange({ ...check, custom_name: e.target.value })}
          fullWidth
          placeholder="e.g. Background Screening"
        />
      )}

      {/* Webhook section */}
      {showWebhook && (
        <Box sx={{ display: 'flex', gap: 1, flexDirection: 'column', pl: 4 }}>
          <Typography variant="caption" color="text.secondary">
            When defined, the applicant service will call this webhook URL with the check result for external validation.
          </Typography>
          <TextField
            size="small"
            label="External provider name"
            value={check.external_provider || ''}
            onChange={(e) => onChange({ ...check, external_provider: e.target.value })}
            placeholder="e.g. Onfido, Jumio"
          />
          <TextField
            size="small"
            label="Webhook URL"
            value={check.webhook_url || ''}
            onChange={(e) => onChange({ ...check, webhook_url: e.target.value })}
            placeholder="https://api.example.com/webhooks/check"
          />
        </Box>
      )}
    </Box>
  );
}

export default function CheckConfigurationDialog({ open, template, onClose, onSaved }) {
  const [checks, setChecks] = useState([]);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState(null);

  useEffect(() => {
    if (open && template) {
      setChecks((template.required_checks || []).map((c, i) => ({ order: i, ...c })));
      setError(null);
    }
  }, [open, template]);

  const handleAdd = () => {
    setChecks((prev) => [
      ...prev,
      {
        check_type: 'identity_verification',
        is_required: true,
        order: prev.length,
      },
    ]);
  };

  const handleChange = (index, updated) => {
    setChecks((prev) => prev.map((c, i) => (i === index ? { ...c, ...updated } : c)));
  };

  const handleRemove = (index) => {
    setChecks((prev) => prev.filter((_, i) => i !== index).map((c, i) => ({ ...c, order: i })));
  };

  const handleSave = async () => {
    setSaving(true);
    setError(null);
    try {
      const normalised = checks.map((c, i) => ({ ...c, order: i }));
      const saved = await updateTemplateRequiredChecks(template.id, normalised);
      onSaved?.(saved);
      onClose();
    } catch (err) {
      setError(err.message || 'Failed to save checks');
    } finally {
      setSaving(false);
    }
  };

  if (!template) return null;

  return (
    <Dialog open={open} onClose={onClose} fullWidth maxWidth="md">
      <DialogTitle>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          Configure Required Checks
          <Chip label={template.name} size="small" variant="outlined" sx={{ ml: 1 }} />
        </Box>
      </DialogTitle>
      <DialogContent dividers>
        <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
          Define the vetting checks that reviewers must complete before an application can be approved.
          Checks are created automatically when an applicant submits this template's application form.
        </Typography>

        {error && (
          <Alert severity="error" sx={{ mb: 2 }}>
            {error}
          </Alert>
        )}

        <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1.5 }}>
          {checks.length === 0 ? (
            <Alert severity="info">
              No vetting checks configured. A single Identity Verification check will be created by default.
            </Alert>
          ) : (
            checks.map((check, i) => (
              <CheckRow
                key={i}
                check={check}
                index={i}
                onChange={(updated) => handleChange(i, updated)}
                onRemove={() => handleRemove(i)}
              />
            ))
          )}
        </Box>

        <Divider sx={{ my: 2 }} />

        <Button
          startIcon={<AddIcon />}
          variant="outlined"
          size="small"
          onClick={handleAdd}
        >
          Add check
        </Button>
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose} disabled={saving}>
          Cancel
        </Button>
        <Button
          variant="contained"
          startIcon={saving ? <CircularProgress size={16} /> : <SaveIcon />}
          onClick={handleSave}
          disabled={saving}
        >
          {saving ? 'Saving…' : 'Save checks'}
        </Button>
      </DialogActions>
    </Dialog>
  );
}

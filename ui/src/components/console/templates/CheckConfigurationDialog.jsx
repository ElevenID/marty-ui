/**
 * CheckConfigurationDialog
 *
 * Dialog for configuring the required vetting checks on an Application Template.
 * Each check entry can define: type, required/optional, order, optional webhook URL.
 */

import { useState, useLayoutEffect, useRef, useId } from 'react';
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
import WebhookIcon from '@mui/icons-material/Webhook';
import SaveIcon from '@mui/icons-material/Save';
import { useAsyncActionScope } from '../../../hooks/useAsyncActionScope';
import { updateTemplateRequiredChecks } from '../../../services/applicationTemplatesApi';
import { CHECK_TYPE_LABELS, CHECK_TYPE_ICONS, ALL_CHECK_TYPES } from '../../../config/checkConstants';

function CheckRow({ check, index, onChange, onRemove, disabled }) {
  const checkTypeId = useId();
  const checkTypeLabelId = `${checkTypeId}-label`;
  const [showWebhook, setShowWebhook] = useState(!!(check.webhook_url || check.external_provider));
  const Icon = CHECK_TYPE_ICONS[check.check_type] || CHECK_TYPE_ICONS['custom'];

  return (
    <Box
      sx={{
        display: 'flex',
        flexDirection: 'column',
        minWidth: 0,
        gap: 1,
        p: 2,
        border: '1px solid',
        borderColor: 'divider',
        borderRadius: 2,
        bgcolor: 'background.paper',
      }}
    >
      {/* Header row */}
      <Box sx={{ display: 'flex', flexDirection: { xs: 'column', sm: 'row' }, alignItems: { xs: 'stretch', sm: 'center' }, gap: 1 }}>
        <Box sx={{ display: 'flex', alignItems: 'center', flexWrap: { xs: 'wrap', sm: 'nowrap' }, flex: 1, minWidth: 0, gap: 1 }}>
          <Chip label={index + 1} size="small" sx={{ minWidth: 32, flexShrink: 0 }} />
          <Icon sx={{ color: 'text.secondary', fontSize: 20, flexShrink: 0 }} />
          <FormControl size="small" disabled={disabled} sx={{ flex: { xs: '1 1 100%', sm: 1 }, minWidth: 0 }}>
            <InputLabel id={checkTypeLabelId}>Check Type</InputLabel>
            <Select
              id={checkTypeId}
              labelId={checkTypeLabelId}
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
        </Box>
        <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: { xs: 'flex-end', sm: 'flex-start' }, flexWrap: 'wrap', flexShrink: 0, gap: 1 }}>
          <FormControlLabel
            control={
              <Switch
                disabled={disabled}
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
            <IconButton size="small" disabled={disabled} onClick={() => setShowWebhook((v) => !v)} color={showWebhook ? 'primary' : 'default'}>
              <WebhookIcon fontSize="small" />
            </IconButton>
          </Tooltip>
          <Tooltip title="Remove check">
            <IconButton size="small" disabled={disabled} color="error" onClick={onRemove}>
              <DeleteIcon fontSize="small" />
            </IconButton>
          </Tooltip>
        </Box>
      </Box>

      {/* Custom name (only for CUSTOM type) */}
      {check.check_type === 'custom' && (
        <TextField
          disabled={disabled}
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
        <Box sx={{ display: 'flex', gap: 1, flexDirection: 'column', pl: { xs: 0, sm: 4 } }}>
          <Typography variant="caption" color="text.secondary">
            When defined, the applicant service will call this webhook URL with the check result for external validation.
          </Typography>
          <TextField
            disabled={disabled}
            size="small"
            label="External provider name"
            value={check.external_provider || ''}
            onChange={(e) => onChange({ ...check, external_provider: e.target.value })}
            placeholder="e.g. Onfido, Jumio"
          />
          <TextField
            disabled={disabled}
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
  const beginSave = useAsyncActionScope();
  const savingRef = useRef(false);
  const [checks, setChecks] = useState([]);
  const [checksEdited, setChecksEdited] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState(null);

  useLayoutEffect(() => {
    // A close/reopen or template replacement starts a new dialog session.
    // An older request may finish, but cannot update or dismiss that session.
    beginSave();
    savingRef.current = false;
    setSaving(false);
    if (open && template) {
      const existing = template.required_checks || [];
      const validOrder = existing.every((check) => Number.isInteger(check.order) && check.order > 0);
      setChecks(validOrder ? [...existing].sort((left, right) => left.order - right.order)
        : existing.map((check, index) => ({ ...check, order: index + 1 })));
      // Invalid legacy orders can be repaired without changing their array sequence.
      setChecksEdited(!validOrder);
      setError(null);
    }
  }, [open, template, beginSave]);

  const handleAdd = () => {
    if (savingRef.current) return;
    setChecksEdited(true);
    setChecks((prev) => [
      ...prev,
      {
        check_type: 'identity_verification',
        is_required: true,
        order: prev.length + 1,
      },
    ]);
  };

  const handleChange = (index, updated) => {
    if (savingRef.current) return;
    setChecksEdited(true);
    setChecks((prev) => prev.map((c, i) => (i === index ? { ...c, ...updated } : c)));
  };

  const handleRemove = (index) => {
    if (savingRef.current) return;
    setChecksEdited(true);
    setChecks((prev) => prev.filter((_, i) => i !== index).map((c, i) => ({ ...c, order: i + 1 })));
  };

  const handleClose = () => {
    if (!savingRef.current) onClose();
  };

  const handleSave = async () => {
    if (!open || !template || savingRef.current) return;
    const action = beginSave();
    savingRef.current = true;
    setSaving(true);
    setError(null);
    try {
      const normalised = checksEdited ? checks.map((c, i) => ({ ...c, order: i + 1 })) : template.required_checks || [];
      const saved = await action.run(updateTemplateRequiredChecks, template.id, normalised);
      if (!action.isCurrent()) return;
      onSaved?.(saved);
      onClose();
    } catch (err) {
      if (action.isCurrent()) setError(err.message || 'Failed to save checks');
    } finally {
      if (action.isCurrent()) {
        savingRef.current = false;
        setSaving(false);
      }
    }
  };

  if (!template) return null;

  return (
    <Dialog open={open} onClose={handleClose} disableEscapeKeyDown={saving} fullWidth maxWidth="md">
      <DialogTitle>
        <Box sx={{ display: 'flex', flexDirection: { xs: 'column', sm: 'row' }, alignItems: { xs: 'flex-start', sm: 'center' }, flexWrap: 'wrap', minWidth: 0, gap: 1 }}>
          <Typography component="span" variant="inherit">Configure Required Checks</Typography>
          <Chip label={template.name} size="small" variant="outlined" sx={{ maxWidth: '100%' }} />
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
                disabled={saving}
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
          disabled={saving}
        >
          Add check
        </Button>
      </DialogContent>
      <DialogActions>
        <Button onClick={handleClose} disabled={saving}>
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

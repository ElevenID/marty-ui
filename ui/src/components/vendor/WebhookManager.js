/**
 * Webhook Manager Component
 * 
 * Allows vendors to configure webhook endpoints for receiving event notifications:
 * - Credential issuance events
 * - Verification events
 * - Application status changes
 * - Trust framework updates
 */

import React, { useState, useEffect } from 'react';
import {
  Box,
  Paper,
  Typography,
  Button,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  IconButton,
  Chip,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  TextField,
  FormControl,
  FormLabel,
  FormGroup,
  FormControlLabel,
  Checkbox,
  Alert,
  CircularProgress,
  Tooltip,
  Snackbar,
} from '@mui/material';
import AddIcon from '@mui/icons-material/Add';
import DeleteIcon from '@mui/icons-material/Delete';
import EditIcon from '@mui/icons-material/Edit';
import WebhookIcon from '@mui/icons-material/Webhook';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import ErrorIcon from '@mui/icons-material/Error';
import RefreshIcon from '@mui/icons-material/Refresh';
import ContentCopyIcon from '@mui/icons-material/ContentCopy';
import { useAuth } from '../../hooks/useAuth';
import {
  listWebhooks,
  createWebhook,
  updateWebhook,
  deleteWebhook,
  testWebhook,
  getErrorMessage,
} from '../../services/webhooksApi';

/**
 * Available webhook event types
 */
const EVENT_TYPES = [
  { 
    id: '*', 
    label: 'All Events', 
    description: 'Subscribe to all current and future events',
    category: 'all'
  },
  // Credential Events
  { 
    id: 'credential.issued', 
    label: 'Credential Issued', 
    description: 'Triggered when a credential is issued',
    category: 'credential'
  },
  { 
    id: 'credential.revoked', 
    label: 'Credential Revoked', 
    description: 'Triggered when a credential is revoked',
    category: 'credential'
  },
  { 
    id: 'credential.suspended', 
    label: 'Credential Suspended', 
    description: 'Triggered when a credential is temporarily suspended',
    category: 'credential'
  },
  { 
    id: 'credential.reactivated', 
    label: 'Credential Reactivated', 
    description: 'Triggered when a suspended credential is reactivated',
    category: 'credential'
  },
  // Verification Events
  { 
    id: 'verification.completed', 
    label: 'Verification Completed', 
    description: 'Triggered when a verification is completed successfully',
    category: 'verification'
  },
  { 
    id: 'verification.failed', 
    label: 'Verification Failed', 
    description: 'Triggered when a verification fails',
    category: 'verification'
  },
  { 
    id: 'verification.initiated', 
    label: 'Verification Initiated', 
    description: 'Triggered when a verification request is received',
    category: 'verification'
  },
  // Application Events
  { 
    id: 'application.created', 
    label: 'Application Created', 
    description: 'Triggered when a new application is created',
    category: 'application'
  },
  { 
    id: 'application.submitted', 
    label: 'Application Submitted', 
    description: 'Triggered when an applicant submits an application',
    category: 'application'
  },
  { 
    id: 'application.updated', 
    label: 'Application Updated', 
    description: 'Triggered when application information is updated',
    category: 'application'
  },
  { 
    id: 'application.approved', 
    label: 'Application Approved', 
    description: 'Triggered when an application is approved',
    category: 'application'
  },
  { 
    id: 'application.rejected', 
    label: 'Application Rejected', 
    description: 'Triggered when an application is rejected',
    category: 'application'
  },
  { 
    id: 'application.under_review', 
    label: 'Application Under Review', 
    description: 'Triggered when an application enters review status',
    category: 'application'
  },
  { 
    id: 'application.additional_info_requested', 
    label: 'Additional Info Requested', 
    description: 'Triggered when reviewer requests more information',
    category: 'application'
  },
  { 
    id: 'application.withdrawn', 
    label: 'Application Withdrawn', 
    description: 'Triggered when applicant withdraws their application',
    category: 'application'
  },
  // Audit Events
  { 
    id: 'audit.access_logged', 
    label: 'Access Logged', 
    description: 'Triggered when a user access event is logged',
    category: 'audit'
  },
  { 
    id: 'audit.configuration_changed', 
    label: 'Configuration Changed', 
    description: 'Triggered when system configuration is modified',
    category: 'audit'
  },
  { 
    id: 'audit.credential_accessed', 
    label: 'Credential Accessed', 
    description: 'Triggered when credential data is accessed',
    category: 'audit'
  },
  { 
    id: 'audit.export_performed', 
    label: 'Export Performed', 
    description: 'Triggered when data is exported from the system',
    category: 'audit'
  },
  { 
    id: 'audit.security_event', 
    label: 'Security Event', 
    description: 'Triggered on security-related events (failed logins, etc.)',
    category: 'audit'
  },
  { 
    id: 'audit.compliance_check', 
    label: 'Compliance Check', 
    description: 'Triggered when compliance verification occurs',
    category: 'audit'
  },
  // Trust Events
  { 
    id: 'trust.updated', 
    label: 'Trust Framework Updated', 
    description: 'Triggered when trust settings change',
    category: 'trust'
  },
  { 
    id: 'trust.certificate_expiring', 
    label: 'Certificate Expiring', 
    description: 'Triggered when a certificate is nearing expiration',
    category: 'trust'
  },
  { 
    id: 'trust.chain_validation_failed', 
    label: 'Chain Validation Failed', 
    description: 'Triggered when certificate chain validation fails',
    category: 'trust'
  },
];

/**
 * Webhook Manager Component
 */
export default function WebhookManager() {
  const { organizationId } = useAuth();
  const [webhooks, setWebhooks] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [dialogOpen, setDialogOpen] = useState(false);
  const [editingWebhook, setEditingWebhook] = useState(null);
  const [successMessage, setSuccessMessage] = useState('');
  const [newWebhookSecret, setNewWebhookSecret] = useState('');
  
  // Form state
  const [url, setUrl] = useState('');
  const [description, setDescription] = useState('');
  const [selectedEvents, setSelectedEvents] = useState([]);
  const [saving, setSaving] = useState(false);

  // Load webhooks on mount
  useEffect(() => {
    if (organizationId) {
      loadWebhooks();
    }
  }, [organizationId]);

  const loadWebhooks = async () => {
    setLoading(true);
    setError(null);
    
    try {
      const webhookList = await listWebhooks(organizationId);
      setWebhooks(webhookList);
    } catch (err) {
      setError(getErrorMessage(err));
    } finally {
      setLoading(false);
    }
  };

  const handleOpenDialog = (webhook = null) => {
    if (webhook) {
      setEditingWebhook(webhook);
      setUrl(webhook.url);
      setDescription(webhook.description || '');
      setSelectedEvents(webhook.event_types || []);
    } else {
      setEditingWebhook(null);
      setUrl('');
      setDescription('');
      setSelectedEvents([]);
    }
    setNewWebhookSecret('');
    setDialogOpen(true);
  };

  const handleCloseDialog = () => {
    setDialogOpen(false);
    setEditingWebhook(null);
  };

  const handleEventToggle = (eventId) => {
    setSelectedEvents((prev) => {
      // If "All Events" is selected/deselected
      if (eventId === '*') {
        return prev.includes('*') ? [] : ['*'];
      }
      
      // If selecting a specific event while "All Events" is selected, deselect "All Events"
      if (prev.includes('*')) {
        return [eventId];
      }
      
      // Normal toggle
      return prev.includes(eventId)
        ? prev.filter((id) => id !== eventId)
        : [...prev, eventId];
    });
  };

  const handleSave = async () => {
    if (!url.trim()) {
      setError('URL is required');
      return;
    }
    
    if (selectedEvents.length === 0) {
      setError('Select at least one event type');
      return;
    }

    setSaving(true);
    setError(null);

    try {
      const webhookData = {
        url: url.trim(),
        eventTypes: selectedEvents,
        description: description.trim(),
      };

      if (editingWebhook) {
        await updateWebhook(editingWebhook.id, webhookData);
        setSuccessMessage('Webhook updated successfully');
      } else {
        const result = await createWebhook(organizationId, webhookData);
        // Show the secret only on creation
        if (result.secret) {
          setNewWebhookSecret(result.secret);
          setSuccessMessage('Webhook created successfully! Save the secret below - it won\'t be shown again.');
        } else {
          setSuccessMessage('Webhook created successfully');
        }
      }

      await loadWebhooks();
      
      // Only close dialog if it's an edit or if user has seen the secret
      if (editingWebhook) {
        handleCloseDialog();
      }
    } catch (err) {
      setError(getErrorMessage(err));
    } finally {
      setSaving(false);
    }
  };

  const handleDelete = async (webhookId) => {
    if (!window.confirm('Are you sure you want to delete this webhook?')) {
      return;
    }

    try {
      await deleteWebhook(webhookId);
      setSuccessMessage('Webhook deleted successfully');
      await loadWebhooks();
    } catch (err) {
      setError(getErrorMessage(err));
    }
  };

  const handleTest = async (webhookId) => {
    try {
      await testWebhook(webhookId);
      setSuccessMessage('Test event sent successfully!');
    } catch (err) {
      setError(getErrorMessage(err));
    }
  };

  if (loading) {
    return (
      <Box sx={{ display: 'flex', justifyContent: 'center', p: 4 }}>
        <CircularProgress />
      </Box>
    );
  }

  return (
    <Box data-testid="webhook-manager">
      {/* Header */}
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
        <Box>
          <Typography variant="h6" gutterBottom>
            Webhook Endpoints
          </Typography>
          <Typography variant="body2" color="text.secondary">
            Configure endpoints to receive real-time event notifications from Marty
          </Typography>
        </Box>
        <Button
          variant="contained"
          startIcon={<AddIcon />}
          onClick={() => handleOpenDialog()}
        >
          Add Webhook
        </Button>
      </Box>

      {/* Error Alert */}
      {error && (
        <Alert severity="error" onClose={() => setError(null)} sx={{ mb: 3 }}>
          {error}
        </Alert>
      )}

      {/* Info Alert */}
      <Alert severity="info" sx={{ mb: 3 }}>
        <Typography variant="body2">
          Webhooks allow your application to receive real-time notifications about events in Marty.
          Each webhook will receive a POST request with event data and a signature for verification.
        </Typography>
      </Alert>

      {/* Webhooks Table */}
      {webhooks.length === 0 ? (
        <Paper sx={{ p: 4, textAlign: 'center', bgcolor: 'grey.50' }}>
          <WebhookIcon sx={{ fontSize: 60, color: 'text.secondary', mb: 2 }} />
          <Typography variant="h6" gutterBottom>
            No Webhooks Configured
          </Typography>
          <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
            Add a webhook endpoint to start receiving event notifications
          </Typography>
          <Button variant="contained" startIcon={<AddIcon />} onClick={() => handleOpenDialog()}>
            Add Your First Webhook
          </Button>
        </Paper>
      ) : (
        <TableContainer component={Paper}>
          <Table>
            <TableHead>
              <TableRow>
                <TableCell>URL</TableCell>
                <TableCell>Description</TableCell>
                <TableCell>Events</TableCell>
                <TableCell>Status</TableCell>
                <TableCell>Last Triggered</TableCell>
                <TableCell align="right">Actions</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {webhooks.map((webhook) => (
                <TableRow key={webhook.id}>
                  <TableCell>
                    <Typography variant="body2" sx={{ fontFamily: 'monospace' }}>
                      {webhook.url}
                    </Typography>
                  </TableCell>
                  <TableCell>{webhook.description || '-'}</TableCell>
                  <TableCell>
                    <Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>
                      {webhook.event_types?.includes('*') ? (
                        <Chip 
                          label="All Events" 
                          size="small" 
                          color="primary"
                          sx={{ fontWeight: 'bold' }}
                        />
                      ) : (
                        <>
                          {webhook.event_types?.slice(0, 2).map((event) => (
                            <Chip key={event} label={event} size="small" />
                          ))}
                          {webhook.event_types?.length > 2 && (
                            <Chip label={`+${webhook.event_types.length - 2}`} size="small" variant="outlined" />
                          )}
                        </>
                      )}
                    </Box>
                  </TableCell>
                  <TableCell>
                    {webhook.enabled ? (
                      <Chip
                        icon={<CheckCircleIcon />}
                        label="Active"
                        color="success"
                        size="small"
                      />
                    ) : (
                      <Chip
                        icon={<ErrorIcon />}
                        label="Inactive"
                        color="error"
                        size="small"
                      />
                    )}
                  </TableCell>
                  <TableCell>
                    {webhook.last_triggered_at
                      ? new Date(webhook.last_triggered_at).toLocaleString()
                      : 'Never'}
                  </TableCell>
                  <TableCell align="right">
                    <Tooltip title="Test webhook">
                      <IconButton size="small" onClick={() => handleTest(webhook.id)}>
                        <RefreshIcon />
                      </IconButton>
                    </Tooltip>
                    <Tooltip title="Edit webhook">
                      <IconButton size="small" onClick={() => handleOpenDialog(webhook)}>
                        <EditIcon />
                      </IconButton>
                    </Tooltip>
                    <Tooltip title="Delete webhook">
                      <IconButton size="small" onClick={() => handleDelete(webhook.id)}>
                        <DeleteIcon />
                      </IconButton>
                    </Tooltip>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>
      )}

      {/* Add/Edit Dialog */}
      <Dialog open={dialogOpen} onClose={handleCloseDialog} maxWidth="md" fullWidth>
        <DialogTitle>
          {editingWebhook ? 'Edit Webhook' : 'Add Webhook'}
        </DialogTitle>
        <DialogContent>
          <Box sx={{ pt: 2 }}>
            <TextField
              label="Webhook URL"
              fullWidth
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="https://your-domain.com/webhooks/marty"
              helperText="The endpoint that will receive POST requests with event data"
              sx={{ mb: 3 }}
              required
            />

            <TextField
              label="Description"
              fullWidth
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="Production webhook endpoint"
              helperText="Optional description to help identify this webhook"
              sx={{ mb: 3 }}
            />

            <FormControl component="fieldset" sx={{ mb: 3, width: '100%' }}>
              <FormLabel component="legend">Event Types *</FormLabel>
              <Typography variant="caption" color="text.secondary" sx={{ mb: 2, display: 'block' }}>
                Select which events should trigger this webhook
              </Typography>
              
              {/* All Events Option */}
              <Box sx={{ mb: 2, pb: 2, borderBottom: 1, borderColor: 'divider' }}>
                <FormControlLabel
                  control={
                    <Checkbox
                      checked={selectedEvents.includes('*')}
                      onChange={() => handleEventToggle('*')}
                      color="primary"
                    />
                  }
                  label={
                    <Box>
                      <Typography variant="body2" fontWeight="bold">
                        All Events
                      </Typography>
                      <Typography variant="caption" color="text.secondary">
                        Subscribe to all current and future events (recommended for comprehensive monitoring)
                      </Typography>
                    </Box>
                  }
                />
              </Box>

              {/* Grouped Events */}
              <FormGroup>
                {/* Credential Events */}
                <Typography variant="subtitle2" color="primary" sx={{ mt: 2, mb: 1, fontWeight: 'bold' }}>
                  Credential Events
                </Typography>
                {EVENT_TYPES.filter(e => e.category === 'credential').map((eventType) => (
                  <FormControlLabel
                    key={eventType.id}
                    disabled={selectedEvents.includes('*')}
                    control={
                      <Checkbox
                        checked={selectedEvents.includes('*') || selectedEvents.includes(eventType.id)}
                        onChange={() => handleEventToggle(eventType.id)}
                      />
                    }
                    label={
                      <Box>
                        <Typography variant="body2">{eventType.label}</Typography>
                        <Typography variant="caption" color="text.secondary">
                          {eventType.description}
                        </Typography>
                      </Box>
                    }
                  />
                ))}

                {/* Verification Events */}
                <Typography variant="subtitle2" color="primary" sx={{ mt: 2, mb: 1, fontWeight: 'bold' }}>
                  Verification Events
                </Typography>
                {EVENT_TYPES.filter(e => e.category === 'verification').map((eventType) => (
                  <FormControlLabel
                    key={eventType.id}
                    disabled={selectedEvents.includes('*')}
                    control={
                      <Checkbox
                        checked={selectedEvents.includes('*') || selectedEvents.includes(eventType.id)}
                        onChange={() => handleEventToggle(eventType.id)}
                      />
                    }
                    label={
                      <Box>
                        <Typography variant="body2">{eventType.label}</Typography>
                        <Typography variant="caption" color="text.secondary">
                          {eventType.description}
                        </Typography>
                      </Box>
                    }
                  />
                ))}

                {/* Application Events */}
                <Typography variant="subtitle2" color="primary" sx={{ mt: 2, mb: 1, fontWeight: 'bold' }}>
                  Application Events
                </Typography>
                {EVENT_TYPES.filter(e => e.category === 'application').map((eventType) => (
                  <FormControlLabel
                    key={eventType.id}
                    disabled={selectedEvents.includes('*')}
                    control={
                      <Checkbox
                        checked={selectedEvents.includes('*') || selectedEvents.includes(eventType.id)}
                        onChange={() => handleEventToggle(eventType.id)}
                      />
                    }
                    label={
                      <Box>
                        <Typography variant="body2">{eventType.label}</Typography>
                        <Typography variant="caption" color="text.secondary">
                          {eventType.description}
                        </Typography>
                      </Box>
                    }
                  />
                ))}

                {/* Audit Events */}
                <Typography variant="subtitle2" color="primary" sx={{ mt: 2, mb: 1, fontWeight: 'bold' }}>
                  Audit Events
                </Typography>
                {EVENT_TYPES.filter(e => e.category === 'audit').map((eventType) => (
                  <FormControlLabel
                    key={eventType.id}
                    disabled={selectedEvents.includes('*')}
                    control={
                      <Checkbox
                        checked={selectedEvents.includes('*') || selectedEvents.includes(eventType.id)}
                        onChange={() => handleEventToggle(eventType.id)}
                      />
                    }
                    label={
                      <Box>
                        <Typography variant="body2">{eventType.label}</Typography>
                        <Typography variant="caption" color="text.secondary">
                          {eventType.description}
                        </Typography>
                      </Box>
                    }
                  />
                ))}

                {/* Trust Events */}
                <Typography variant="subtitle2" color="primary" sx={{ mt: 2, mb: 1, fontWeight: 'bold' }}>
                  Trust Events
                </Typography>
                {EVENT_TYPES.filter(e => e.category === 'trust').map((eventType) => (
                  <FormControlLabel
                    key={eventType.id}
                    disabled={selectedEvents.includes('*')}
                    control={
                      <Checkbox
                        checked={selectedEvents.includes('*') || selectedEvents.includes(eventType.id)}
                        onChange={() => handleEventToggle(eventType.id)}
                      />
                    }
                    label={
                      <Box>
                        <Typography variant="body2">{eventType.label}</Typography>
                        <Typography variant="caption" color="text.secondary">
                          {eventType.description}
                        </Typography>
                      </Box>
                    }
                  />
                ))}
              </FormGroup>
            </FormControl>

            {/* Show secret after creation */}
            {newWebhookSecret && (
              <Alert severity="success" sx={{ mt: 3 }}>
                <Typography variant="subtitle2" gutterBottom>
                  Webhook Secret (Save this now - it won't be shown again!)
                </Typography>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mt: 1 }}>
                  <TextField
                    fullWidth
                    value={newWebhookSecret}
                    InputProps={{
                      readOnly: true,
                      sx: { fontFamily: 'monospace', fontSize: '0.875rem' },
                    }}
                    size="small"
                  />
                  <Tooltip title="Copy to clipboard">
                    <IconButton
                      size="small"
                      onClick={() => {
                        navigator.clipboard.writeText(newWebhookSecret);
                        setSuccessMessage('Secret copied to clipboard');
                      }}
                    >
                      <ContentCopyIcon fontSize="small" />
                    </IconButton>
                  </Tooltip>
                </Box>
              </Alert>
            )}
          </Box>
        </DialogContent>
        <DialogActions>
          <Button onClick={handleCloseDialog}>
            {newWebhookSecret ? 'Close' : 'Cancel'}
          </Button>
          {!newWebhookSecret && (
            <Button
              onClick={handleSave}
              variant="contained"
              disabled={saving || !url.trim() || selectedEvents.length === 0}
            >
              {saving ? 'Saving...' : editingWebhook ? 'Update' : 'Create'}
            </Button>
          )}
        </DialogActions>
      </Dialog>

      {/* Success Snackbar */}
      <Snackbar
        open={!!successMessage}
        autoHideDuration={6000}
        onClose={() => setSuccessMessage('')}
        anchorOrigin={{ vertical: 'bottom', horizontal: 'center' }}
      >
        <Alert onClose={() => setSuccessMessage('')} severity="success" sx={{ width: '100%' }}>
          {successMessage}
        </Alert>
      </Snackbar>
    </Box>
  );
}

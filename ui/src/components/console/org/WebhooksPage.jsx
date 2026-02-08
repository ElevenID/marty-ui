/**
 * Webhooks Page
 * 
 * Manage webhook endpoints for event notifications.
 */

import { useState, useEffect } from 'react';
import {
  Box,
  Paper,
  Typography,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Chip,
  IconButton,
  Tooltip,
  Alert,
  LinearProgress,
  Button,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  TextField,
  FormGroup,
  FormControlLabel,
  Checkbox,
} from '@mui/material';
import AddIcon from '@mui/icons-material/Add';
import EditIcon from '@mui/icons-material/Edit';
import DeleteIcon from '@mui/icons-material/Delete';
import PlayArrowIcon from '@mui/icons-material/PlayArrow';
import HistoryIcon from '@mui/icons-material/History';
import { Link } from 'react-router-dom';

import { ResourcePage } from '../../common';

const DEPLOY_TABS = [
  { label: 'Deployment Profiles', path: '/console/deploy/profiles' },
  { label: 'API Keys', path: '/console/deploy/api-keys' },
  { label: 'Lanes & Devices', path: '/console/deploy/lanes' },
  { label: 'Webhooks', path: '/console/deploy/webhooks' },
];

const BREADCRUMBS = [
  { label: 'Console', path: '/console' },
  { label: 'Deploy', path: '/console/deploy' },
  { label: 'Webhooks', path: '/console/deploy/webhooks' },
];

const EVENT_TYPES = [
  { value: 'flow.completed', label: 'Flow Completed' },
  { value: 'flow.failed', label: 'Flow Failed' },
  { value: 'credential.issued', label: 'Credential Issued' },
  { value: 'credential.revoked', label: 'Credential Revoked' },
  { value: 'application.submitted', label: 'Application Submitted' },
  { value: 'application.approved', label: 'Application Approved' },
  { value: 'application.rejected', label: 'Application Rejected' },
];

function WebhooksPage() {
  const [webhooks, setWebhooks] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [createDialogOpen, setCreateDialogOpen] = useState(false);
  const [newWebhook, setNewWebhook] = useState({
    url: '',
    events: [],
  });

  useEffect(() => {
    // TODO: Fetch webhooks from API
    const loadWebhooks = async () => {
      try {
        await new Promise((resolve) => setTimeout(resolve, 500));
        setWebhooks([
          {
            id: 'wh-1',
            url: 'https://api.example.com/webhooks/identity',
            events: ['flow.completed', 'flow.failed', 'credential.issued'],
            status: 'active',
            lastDelivery: '2026-02-07T09:00:00Z',
            successRate: 99.5,
          },
          {
            id: 'wh-2',
            url: 'https://crm.example.com/hooks/applications',
            events: ['application.submitted', 'application.approved'],
            status: 'active',
            lastDelivery: '2026-02-07T08:45:00Z',
            successRate: 100,
          },
        ]);
      } catch (err) {
        setError('Failed to load webhooks');
      } finally {
        setLoading(false);
      }
    };
    loadWebhooks();
  }, []);

  const handleCreate = async () => {
    // TODO: Create webhook via API
    setCreateDialogOpen(false);
    setNewWebhook({ url: '', events: [] });
  };

  const handleEventToggle = (eventValue) => {
    setNewWebhook((prev) => ({
      ...prev,
      events: prev.events.includes(eventValue)
        ? prev.events.filter((e) => e !== eventValue)
        : [...prev.events, eventValue],
    }));
  };

  return (
    <ResourcePage
      title="Webhooks"
      description="Configure webhook endpoints to receive real-time event notifications."
      tabs={DEPLOY_TABS}
      breadcrumbs={BREADCRUMBS}
      actions={
        <Button
          variant="contained"
          startIcon={<AddIcon />}
          onClick={() => setCreateDialogOpen(true)}
        >
          Add Webhook
        </Button>
      }
    >
      {error && (
        <Alert severity="error" sx={{ mb: 3 }}>
          {error}
        </Alert>
      )}

      {loading ? (
        <LinearProgress />
      ) : (
        <TableContainer component={Paper}>
          <Table>
            <TableHead>
              <TableRow>
                <TableCell>Endpoint URL</TableCell>
                <TableCell>Events</TableCell>
                <TableCell>Last Delivery</TableCell>
                <TableCell>Success Rate</TableCell>
                <TableCell>Status</TableCell>
                <TableCell align="right">Actions</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {webhooks.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={6} align="center">
                    <Typography color="text.secondary" sx={{ py: 4 }}>
                      No webhooks configured. Add a webhook to receive event notifications.
                    </Typography>
                  </TableCell>
                </TableRow>
              ) : (
                webhooks.map((webhook) => (
                  <TableRow key={webhook.id} hover>
                    <TableCell>
                      <Typography 
                        variant="body2" 
                        sx={{ 
                          fontFamily: 'monospace',
                          maxWidth: 300,
                          overflow: 'hidden',
                          textOverflow: 'ellipsis',
                        }}
                      >
                        {webhook.url}
                      </Typography>
                    </TableCell>
                    <TableCell>
                      <Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>
                        {webhook.events.slice(0, 2).map((event) => (
                          <Chip key={event} label={event} size="small" variant="outlined" />
                        ))}
                        {webhook.events.length > 2 && (
                          <Chip label={`+${webhook.events.length - 2}`} size="small" />
                        )}
                      </Box>
                    </TableCell>
                    <TableCell>
                      {new Date(webhook.lastDelivery).toLocaleString()}
                    </TableCell>
                    <TableCell>
                      <Chip 
                        label={`${webhook.successRate}%`} 
                        size="small" 
                        color={webhook.successRate >= 99 ? 'success' : webhook.successRate >= 90 ? 'warning' : 'error'}
                      />
                    </TableCell>
                    <TableCell>
                      <Chip 
                        label={webhook.status === 'active' ? 'Active' : 'Disabled'} 
                        color={webhook.status === 'active' ? 'success' : 'default'}
                        size="small" 
                      />
                    </TableCell>
                    <TableCell align="right">
                      <Tooltip title="Test Webhook">
                        <IconButton size="small" color="primary">
                          <PlayArrowIcon fontSize="small" />
                        </IconButton>
                      </Tooltip>
                      <Tooltip title="Delivery History">
                        <IconButton
                          component={Link}
                          to={`/console/org/webhooks/${webhook.id}/history`}
                          size="small"
                        >
                          <HistoryIcon fontSize="small" />
                        </IconButton>
                      </Tooltip>
                      <Tooltip title="Edit">
                        <IconButton size="small">
                          <EditIcon fontSize="small" />
                        </IconButton>
                      </Tooltip>
                      <Tooltip title="Delete">
                        <IconButton size="small" color="error">
                          <DeleteIcon fontSize="small" />
                        </IconButton>
                      </Tooltip>
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </TableContainer>
      )}

      {/* Create Webhook Dialog */}
      <Dialog 
        open={createDialogOpen} 
        onClose={() => setCreateDialogOpen(false)}
        maxWidth="sm"
        fullWidth
      >
        <DialogTitle>Add Webhook</DialogTitle>
        <DialogContent>
          <Box sx={{ pt: 1 }}>
            <TextField
              autoFocus
              fullWidth
              label="Endpoint URL"
              placeholder="https://api.example.com/webhook"
              value={newWebhook.url}
              onChange={(e) => setNewWebhook((prev) => ({ ...prev, url: e.target.value }))}
              sx={{ mb: 3 }}
            />
            <Typography variant="subtitle2" gutterBottom>
              Events to subscribe
            </Typography>
            <FormGroup>
              {EVENT_TYPES.map((event) => (
                <FormControlLabel
                  key={event.value}
                  control={
                    <Checkbox
                      checked={newWebhook.events.includes(event.value)}
                      onChange={() => handleEventToggle(event.value)}
                    />
                  }
                  label={event.label}
                />
              ))}
            </FormGroup>
          </Box>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setCreateDialogOpen(false)}>Cancel</Button>
          <Button 
            variant="contained" 
            onClick={handleCreate}
            disabled={!newWebhook.url.trim() || newWebhook.events.length === 0}
          >
            Add Webhook
          </Button>
        </DialogActions>
      </Dialog>
    </ResourcePage>
  );
}

export default WebhooksPage;

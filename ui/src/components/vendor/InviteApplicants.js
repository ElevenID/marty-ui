/**
 * Invite Applicants
 *
 * Vendor component for inviting applicants via Keycloak Organizations.
 * Uses Keycloak's native invitation feature to send email invitations.
 */

import React, { useState, useEffect } from 'react';
import {
  Box,
  Paper,
  Typography,
  Button,
  TextField,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Chip,
  IconButton,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Alert,
  Snackbar,
  CircularProgress,
  Tooltip,
  Divider,
  InputAdornment,
} from '@mui/material';
import SendIcon from '@mui/icons-material/Send';
import PersonAddIcon from '@mui/icons-material/PersonAdd';
import RefreshIcon from '@mui/icons-material/Refresh';
import DeleteIcon from '@mui/icons-material/Delete';
import ContentCopyIcon from '@mui/icons-material/ContentCopy';
import EmailIcon from '@mui/icons-material/Email';
import AccessTimeIcon from '@mui/icons-material/AccessTime';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import CancelIcon from '@mui/icons-material/Cancel';
import { useAuth } from '../../hooks/useAuth';

// Invitation status mapping
const STATUS_CONFIG = {
  pending: { label: 'Pending', color: 'warning', icon: <AccessTimeIcon fontSize="small" /> },
  accepted: { label: 'Accepted', color: 'success', icon: <CheckCircleIcon fontSize="small" /> },
  expired: { label: 'Expired', color: 'default', icon: <CancelIcon fontSize="small" /> },
  cancelled: { label: 'Cancelled', color: 'error', icon: <CancelIcon fontSize="small" /> },
};

/**
 * Format date for display
 */
function formatDate(dateString) {
  if (!dateString) return 'N/A';
  return new Date(dateString).toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });
}

/**
 * Calculate time remaining until expiry
 */
function getTimeRemaining(expiresAt) {
  if (!expiresAt) return null;
  const now = new Date();
  const expiry = new Date(expiresAt);
  const diff = expiry - now;
  
  if (diff <= 0) return 'Expired';
  
  const days = Math.floor(diff / (1000 * 60 * 60 * 24));
  const hours = Math.floor((diff % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60));
  
  if (days > 0) return `${days}d ${hours}h remaining`;
  return `${hours}h remaining`;
}

export default function InviteApplicants() {
  const { organizationId, organizationName } = useAuth();
  const [invitations, setInvitations] = useState([]);
  const [loading, setLoading] = useState(true);
  const [sending, setSending] = useState(false);
  const [inviteDialogOpen, setInviteDialogOpen] = useState(false);
  const [emailInput, setEmailInput] = useState('');
  const [bulkEmails, setBulkEmails] = useState('');
  const [snackbar, setSnackbar] = useState({ open: false, message: '', severity: 'success' });

  // Fetch existing invitations
  useEffect(() => {
    fetchInvitations();
  }, [organizationId]);

  const fetchInvitations = async () => {
    setLoading(true);
    try {
      // TODO: Replace with Keycloak Admin API call
      // GET /admin/realms/{realm}/organizations/{orgId}/members/invite
      
      // Mock data for development
      setInvitations([
        {
          id: '1',
          email: 'alice@example.com',
          status: 'pending',
          invited_at: '2024-12-14T10:00:00Z',
          expires_at: '2024-12-21T10:00:00Z',
          accepted_at: null,
        },
        {
          id: '2',
          email: 'bob@example.com',
          status: 'accepted',
          invited_at: '2024-12-10T14:00:00Z',
          expires_at: '2024-12-17T14:00:00Z',
          accepted_at: '2024-12-11T09:30:00Z',
        },
        {
          id: '3',
          email: 'charlie@example.com',
          status: 'expired',
          invited_at: '2024-12-01T09:00:00Z',
          expires_at: '2024-12-08T09:00:00Z',
          accepted_at: null,
        },
      ]);
    } catch (error) {
      console.error('Failed to fetch invitations:', error);
      setSnackbar({ open: true, message: 'Failed to load invitations', severity: 'error' });
    } finally {
      setLoading(false);
    }
  };

  const handleSendInvitation = async (emails) => {
    if (!emails || emails.length === 0) {
      setSnackbar({ open: true, message: 'Please enter at least one email address', severity: 'warning' });
      return;
    }

    setSending(true);
    try {
      // TODO: Replace with Keycloak Admin API call
      // POST /admin/realms/{realm}/organizations/{orgId}/members/invite-user
      // Body: { email: "user@example.com" }
      
      // For each email, send invitation via Keycloak
      const results = await Promise.allSettled(
        emails.map(async (email) => {
          // Simulate API call
          await new Promise((resolve) => setTimeout(resolve, 500));
          
          // Mock: 90% success rate
          if (Math.random() < 0.1) {
            throw new Error(`Failed to send to ${email}`);
          }
          
          return {
            id: String(Date.now() + Math.random()),
            email: email.trim(),
            status: 'pending',
            invited_at: new Date().toISOString(),
            expires_at: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString(), // 7 days
            accepted_at: null,
          };
        })
      );

      // Process results
      const successful = results.filter((r) => r.status === 'fulfilled').map((r) => r.value);
      const failed = results.filter((r) => r.status === 'rejected');

      if (successful.length > 0) {
        setInvitations([...successful, ...invitations]);
        setSnackbar({
          open: true,
          message: `Sent ${successful.length} invitation(s) successfully`,
          severity: 'success',
        });
      }

      if (failed.length > 0) {
        setSnackbar({
          open: true,
          message: `${failed.length} invitation(s) failed to send`,
          severity: 'error',
        });
      }

      setInviteDialogOpen(false);
      setEmailInput('');
      setBulkEmails('');
    } catch (error) {
      console.error('Failed to send invitations:', error);
      setSnackbar({ open: true, message: 'Failed to send invitations', severity: 'error' });
    } finally {
      setSending(false);
    }
  };

  const handleResendInvitation = async (invitation) => {
    try {
      // TODO: Resend via Keycloak API
      setSnackbar({ open: true, message: `Resent invitation to ${invitation.email}`, severity: 'success' });
      
      // Update expiry
      setInvitations(
        invitations.map((inv) =>
          inv.id === invitation.id
            ? {
                ...inv,
                status: 'pending',
                invited_at: new Date().toISOString(),
                expires_at: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString(),
              }
            : inv
        )
      );
    } catch (error) {
      setSnackbar({ open: true, message: 'Failed to resend invitation', severity: 'error' });
    }
  };

  const handleCancelInvitation = async (invitation) => {
    try {
      // TODO: Cancel via Keycloak API
      setInvitations(
        invitations.map((inv) =>
          inv.id === invitation.id ? { ...inv, status: 'cancelled' } : inv
        )
      );
      setSnackbar({ open: true, message: 'Invitation cancelled', severity: 'success' });
    } catch (error) {
      setSnackbar({ open: true, message: 'Failed to cancel invitation', severity: 'error' });
    }
  };

  const parseEmails = () => {
    // Parse bulk emails (comma, semicolon, or newline separated)
    const allEmails = bulkEmails
      .split(/[,;\n]/)
      .map((e) => e.trim().toLowerCase())
      .filter((e) => e && e.includes('@'));

    // Add single email if provided
    if (emailInput.trim() && emailInput.includes('@')) {
      allEmails.unshift(emailInput.trim().toLowerCase());
    }

    // Remove duplicates
    return [...new Set(allEmails)];
  };

  const pendingCount = invitations.filter((i) => i.status === 'pending').length;
  const acceptedCount = invitations.filter((i) => i.status === 'accepted').length;

  return (
    <Box sx={{ p: 3 }}>
      {/* Header */}
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
        <Box>
          <Typography variant="h5" component="h1" gutterBottom>
            Invite Applicants
          </Typography>
          <Typography variant="body2" color="textSecondary">
            Send email invitations to join {organizationName || 'your organization'} as applicants.
          </Typography>
        </Box>
        <Box sx={{ display: 'flex', gap: 1 }}>
          <Button startIcon={<RefreshIcon />} onClick={fetchInvitations} disabled={loading}>
            Refresh
          </Button>
          <Button
            variant="contained"
            startIcon={<PersonAddIcon />}
            onClick={() => setInviteDialogOpen(true)}
          >
            Send Invitations
          </Button>
        </Box>
      </Box>

      {/* Stats */}
      <Box sx={{ display: 'flex', gap: 2, mb: 3 }}>
        <Chip
          icon={<AccessTimeIcon />}
          label={`${pendingCount} Pending`}
          color="warning"
          variant="outlined"
        />
        <Chip
          icon={<CheckCircleIcon />}
          label={`${acceptedCount} Accepted`}
          color="success"
          variant="outlined"
        />
      </Box>

      {/* Info Alert */}
      <Alert severity="info" sx={{ mb: 3 }}>
        <Typography variant="body2">
          Invitations are sent via email and expire after 7 days. Applicants will receive a link to
          create their account and join your organization. View sent emails at{' '}
          <a href="http://localhost:8025" target="_blank" rel="noopener noreferrer">
            MailHog (dev only)
          </a>
          .
        </Typography>
      </Alert>

      {/* Invitations Table */}
      <TableContainer component={Paper}>
        <Table>
          <TableHead>
            <TableRow>
              <TableCell>Email</TableCell>
              <TableCell>Status</TableCell>
              <TableCell>Invited</TableCell>
              <TableCell>Expires</TableCell>
              <TableCell>Accepted</TableCell>
              <TableCell align="right">Actions</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {invitations.map((invitation) => {
              const statusConfig = STATUS_CONFIG[invitation.status] || STATUS_CONFIG.pending;
              const timeRemaining = invitation.status === 'pending' ? getTimeRemaining(invitation.expires_at) : null;

              return (
                <TableRow key={invitation.id} hover>
                  <TableCell>
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                      <EmailIcon fontSize="small" color="action" />
                      <Typography variant="body2">{invitation.email}</Typography>
                    </Box>
                  </TableCell>
                  <TableCell>
                    <Chip
                      icon={statusConfig.icon}
                      label={statusConfig.label}
                      color={statusConfig.color}
                      size="small"
                    />
                  </TableCell>
                  <TableCell>
                    <Typography variant="body2" color="textSecondary">
                      {formatDate(invitation.invited_at)}
                    </Typography>
                  </TableCell>
                  <TableCell>
                    <Typography
                      variant="body2"
                      color={invitation.status === 'pending' ? 'warning.main' : 'textSecondary'}
                    >
                      {timeRemaining || formatDate(invitation.expires_at)}
                    </Typography>
                  </TableCell>
                  <TableCell>
                    <Typography variant="body2" color="textSecondary">
                      {formatDate(invitation.accepted_at)}
                    </Typography>
                  </TableCell>
                  <TableCell align="right">
                    {invitation.status === 'pending' && (
                      <>
                        <Tooltip title="Resend Invitation">
                          <IconButton
                            size="small"
                            onClick={() => handleResendInvitation(invitation)}
                          >
                            <RefreshIcon fontSize="small" />
                          </IconButton>
                        </Tooltip>
                        <Tooltip title="Cancel Invitation">
                          <IconButton
                            size="small"
                            onClick={() => handleCancelInvitation(invitation)}
                            color="error"
                          >
                            <DeleteIcon fontSize="small" />
                          </IconButton>
                        </Tooltip>
                      </>
                    )}
                    {(invitation.status === 'expired' || invitation.status === 'cancelled') && (
                      <Tooltip title="Resend Invitation">
                        <IconButton
                          size="small"
                          onClick={() => handleResendInvitation(invitation)}
                        >
                          <RefreshIcon fontSize="small" />
                        </IconButton>
                      </Tooltip>
                    )}
                  </TableCell>
                </TableRow>
              );
            })}
            {invitations.length === 0 && !loading && (
              <TableRow>
                <TableCell colSpan={6} align="center" sx={{ py: 4 }}>
                  <Typography color="textSecondary">
                    No invitations sent yet. Click &quot;Send Invitations&quot; to get started.
                  </Typography>
                </TableCell>
              </TableRow>
            )}
          </TableBody>
        </Table>
      </TableContainer>

      {/* Send Invitation Dialog */}
      <Dialog
        open={inviteDialogOpen}
        onClose={() => setInviteDialogOpen(false)}
        maxWidth="sm"
        fullWidth
      >
        <DialogTitle>Send Invitations</DialogTitle>
        <DialogContent>
          <Typography variant="body2" color="textSecondary" sx={{ mb: 2 }}>
            Invite applicants to join your organization. They will receive an email with a link to
            create their account.
          </Typography>

          <TextField
            autoFocus
            margin="dense"
            label="Email Address"
            type="email"
            fullWidth
            variant="outlined"
            value={emailInput}
            onChange={(e) => setEmailInput(e.target.value)}
            placeholder="applicant@example.com"
            InputProps={{
              startAdornment: (
                <InputAdornment position="start">
                  <EmailIcon color="action" />
                </InputAdornment>
              ),
            }}
            sx={{ mb: 2 }}
          />

          <Divider sx={{ my: 2 }}>
            <Typography variant="caption" color="textSecondary">
              OR bulk invite
            </Typography>
          </Divider>

          <TextField
            margin="dense"
            label="Bulk Email Addresses"
            multiline
            rows={4}
            fullWidth
            variant="outlined"
            value={bulkEmails}
            onChange={(e) => setBulkEmails(e.target.value)}
            placeholder="Enter multiple emails separated by commas, semicolons, or new lines..."
            helperText={`${parseEmails().length} valid email(s) detected`}
          />
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setInviteDialogOpen(false)} disabled={sending}>
            Cancel
          </Button>
          <Button
            onClick={() => handleSendInvitation(parseEmails())}
            variant="contained"
            startIcon={sending ? <CircularProgress size={20} /> : <SendIcon />}
            disabled={sending || parseEmails().length === 0}
          >
            {sending ? 'Sending...' : `Send ${parseEmails().length} Invitation(s)`}
          </Button>
        </DialogActions>
      </Dialog>

      {/* Snackbar */}
      <Snackbar
        open={snackbar.open}
        autoHideDuration={4000}
        onClose={() => setSnackbar({ ...snackbar, open: false })}
      >
        <Alert severity={snackbar.severity} onClose={() => setSnackbar({ ...snackbar, open: false })}>
          {snackbar.message}
        </Alert>
      </Snackbar>
    </Box>
  );
}

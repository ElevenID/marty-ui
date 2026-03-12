/**
 * Invite Applicants
 *
 * Vendor component for inviting applicants via Keycloak Organizations.
 * Uses Keycloak's native invitation feature to send email invitations.
 */

import { useState, useEffect } from 'react';
import { useTranslation } from 'react-i18next';
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
  CircularProgress,
  Tooltip,
  Divider,
  InputAdornment,
} from '@mui/material';
import SendIcon from '@mui/icons-material/Send';
import PersonAddIcon from '@mui/icons-material/PersonAdd';
import RefreshIcon from '@mui/icons-material/Refresh';
import DeleteIcon from '@mui/icons-material/Delete';
import EmailIcon from '@mui/icons-material/Email';
import AccessTimeIcon from '@mui/icons-material/AccessTime';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import CancelIcon from '@mui/icons-material/Cancel';
import { useAuth } from '../../hooks/useAuth';
import { useNotifications } from '../../hooks/useNotifications';

export default function InviteApplicants() {
  const { t } = useTranslation('vendor');
  const { organizationId, organizationName } = useAuth();
  const { showSuccess, showError, showWarning } = useNotifications();
  // Invitation status mapping
  const STATUS_CONFIG = {
    pending: { label: t('inviteApplicants.status.pending'), color: 'warning', icon: <AccessTimeIcon fontSize="small" /> },
    accepted: { label: t('inviteApplicants.status.accepted'), color: 'success', icon: <CheckCircleIcon fontSize="small" /> },
    expired: { label: t('inviteApplicants.status.expired'), color: 'default', icon: <CancelIcon fontSize="small" /> },
    cancelled: { label: t('inviteApplicants.status.cancelled'), color: 'error', icon: <CancelIcon fontSize="small" /> },
  };
  const [invitations, setInvitations] = useState([]);
  const [loading, setLoading] = useState(true);
  const [sending, setSending] = useState(false);
  const [inviteDialogOpen, setInviteDialogOpen] = useState(false);
  const [emailInput, setEmailInput] = useState('');
  const [bulkEmails, setBulkEmails] = useState('');

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
      showError(t('inviteApplicants.loadFailed'));
    } finally {
      setLoading(false);
    }
  };

  const handleSendInvitation = async (emails) => {
    if (!emails || emails.length === 0) {
      showWarning(t('inviteApplicants.enterEmail'));
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
        showSuccess(t('inviteApplicants.sentSuccess', { count: successful.length }));
      }

      if (failed.length > 0) {
        showError(t('inviteApplicants.sentFailed', { count: failed.length }));
      }

      setInviteDialogOpen(false);
      setEmailInput('');
      setBulkEmails('');
    } catch (error) {
      console.error('Failed to send invitations:', error);
      showError(t('inviteApplicants.sendFailed'));
    } finally {
      setSending(false);
    }
  };

  const handleResendInvitation = async (invitation) => {
    try {
      // TODO: Resend via Keycloak API
      showSuccess(t('inviteApplicants.resentSuccess', { email: invitation.email }));
      
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
      showError(t('inviteApplicants.resendFailed'));
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
      showSuccess(t('inviteApplicants.cancelSuccess'));
    } catch (error) {
      showError(t('inviteApplicants.cancelFailed'));
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

  const formatDate = (dateString) => {
    if (!dateString) return t('inviteApplicants.notAvailable');
    return new Date(dateString).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    });
  };

  const getTimeRemaining = (expiresAt) => {
    if (!expiresAt) return null;
    const now = new Date();
    const expiry = new Date(expiresAt);
    const diff = expiry - now;
    
    if (diff <= 0) return t('inviteApplicants.expired');
    
    const days = Math.floor(diff / (1000 * 60 * 60 * 24));
    const hours = Math.floor((diff % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60));
    
    if (days > 0) return t('inviteApplicants.timeRemaining.days', { days, hours });
    return t('inviteApplicants.timeRemaining.hours', { hours });
  };

  return (
    <Box sx={{ p: 3 }}>
      {/* Header */}
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
        <Box>
          <Typography variant="h5" component="h1" gutterBottom>
            {t('inviteApplicants.title')}
          </Typography>
          <Typography variant="body2" color="textSecondary">
            {t('inviteApplicants.description', { organization: organizationName || t('inviteApplicants.yourOrganization') })}
          </Typography>
        </Box>
        <Box sx={{ display: 'flex', gap: 1 }}>
          <Button startIcon={<RefreshIcon />} onClick={fetchInvitations} disabled={loading}>
            {t('inviteApplicants.refreshButton')}
          </Button>
          <Button
            variant="contained"
            startIcon={<PersonAddIcon />}
            onClick={() => setInviteDialogOpen(true)}
          >
            {t('inviteApplicants.sendButton')}
          </Button>
        </Box>
      </Box>

      {/* Stats */}
      <Box sx={{ display: 'flex', gap: 2, mb: 3 }}>
        <Chip
          icon={<AccessTimeIcon />}
          label={t('inviteApplicants.stats.pending', { count: pendingCount })}
          color="warning"
          variant="outlined"
        />
        <Chip
          icon={<CheckCircleIcon />}
          label={t('inviteApplicants.stats.accepted', { count: acceptedCount })}
          color="success"
          variant="outlined"
        />
      </Box>

      {/* Info Alert */}
      <Alert severity="info" sx={{ mb: 3 }}>
        <Typography variant="body2">
          {t('inviteApplicants.infoAlert')}{' '}
          <a href="http://localhost:8025" target="_blank" rel="noopener noreferrer">
            {t('inviteApplicants.mailhogLink')}
          </a>
          .
        </Typography>
      </Alert>

      {/* Invitations Table */}
      <TableContainer component={Paper}>
        <Table>
          <TableHead>
            <TableRow>
              <TableCell>{t('inviteApplicants.table.email')}</TableCell>
              <TableCell>{t('inviteApplicants.table.status')}</TableCell>
              <TableCell>{t('inviteApplicants.table.invited')}</TableCell>
              <TableCell>{t('inviteApplicants.table.expires')}</TableCell>
              <TableCell>{t('inviteApplicants.table.accepted')}</TableCell>
              <TableCell align="right">{t('inviteApplicants.table.actions')}</TableCell>
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
                        <Tooltip title={t('inviteApplicants.table.resend')}>
                          <IconButton
                            size="small"
                            onClick={() => handleResendInvitation(invitation)}
                          >
                            <RefreshIcon fontSize="small" />
                          </IconButton>
                        </Tooltip>
                        <Tooltip title={t('inviteApplicants.table.cancel')}>
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
                      <Tooltip title={t('inviteApplicants.table.resend')}>
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
                    {t('inviteApplicants.table.empty')}
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
        <DialogTitle>{t('inviteApplicants.dialog.title')}</DialogTitle>
        <DialogContent>
          <Typography variant="body2" color="textSecondary" sx={{ mb: 2 }}>
            {t('inviteApplicants.dialog.description')}
          </Typography>

          <TextField
            autoFocus
            margin="dense"
            label={t('inviteApplicants.dialog.emailLabel')}
            type="email"
            fullWidth
            variant="outlined"
            value={emailInput}
            onChange={(e) => setEmailInput(e.target.value)}
            placeholder={t('inviteApplicants.dialog.emailPlaceholder')}
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
              {t('inviteApplicants.dialog.bulkOr')}
            </Typography>
          </Divider>

          <TextField
            margin="dense"
            label={t('inviteApplicants.dialog.bulkLabel')}
            multiline
            rows={4}
            fullWidth
            variant="outlined"
            value={bulkEmails}
            onChange={(e) => setBulkEmails(e.target.value)}
            placeholder={t('inviteApplicants.dialog.bulkPlaceholder')}
            helperText={t('inviteApplicants.dialog.bulkHelper', { count: parseEmails().length })}
          />
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setInviteDialogOpen(false)} disabled={sending}>
            {t('inviteApplicants.dialog.cancelButton')}
          </Button>
          <Button
            onClick={() => handleSendInvitation(parseEmails())}
            variant="contained"
            startIcon={sending ? <CircularProgress size={20} /> : <SendIcon />}
            disabled={sending || parseEmails().length === 0}
          >
            {sending ? t('inviteApplicants.dialog.sending') : t('inviteApplicants.dialog.sendButton', { count: parseEmails().length })}
          </Button>
        </DialogActions>
      </Dialog>

    </Box>
  );
}

import { useEffect, useRef, useState } from 'react';
import {
  Box,
  Paper,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Button,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  TextField,
  Chip,
  Typography,
  IconButton,
  Alert,
} from '@mui/material';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import CancelIcon from '@mui/icons-material/Cancel';
import { useTranslation } from 'react-i18next';
import ResourcePage from '../../common/ResourcePage';
import { useDialog } from '../../../hooks/useDialog';
import { useAsyncData } from '../../../hooks/useAsyncData';
import { useAuth } from '../../../hooks/useAuth';
import { useConsole } from '../../../contexts/ConsoleContext';
import { getPendingRoleRequests, approveRoleRequest, rejectRoleRequest } from '../../../services/rolesApi';

function requestErrorMessage(error, fallback) {
  const message = typeof error?.message === 'string' ? error.message.trim() : '';
  return message || fallback;
}

/**
 * Role Escalation Requests Page
 * 
 * Admin interface for reviewing and approving/rejecting role escalation requests.
 */
export default function RoleEscalationRequestsPage() {
  const { activeOrgId } = useConsole();
  const { user, isAuthenticated } = useAuth();
  const principalId = isAuthenticated ? user?.user_id || user?.sub || user?.id || 'unknown-user' : 'signed-out';
  return <RoleEscalationRequestsContent key={`${activeOrgId || 'no-organization'}:${principalId}`} organizationId={activeOrgId} isAuthenticated={isAuthenticated} />;
}

function RoleEscalationRequestsContent({ organizationId, isAuthenticated }) {
  const { t } = useTranslation('console');
  const active = useRef(true);
  const actionPending = useRef(false);
  const { data, loading, error: loadError, reload } = useAsyncData(async () => {
    if (!organizationId) throw new Error('Select an organization before loading role requests.');
    if (!isAuthenticated) throw new Error('Sign in before loading role requests.');
    const response = await getPendingRoleRequests();
    if (!Array.isArray(response?.requests)) throw new Error('Role requests returned an invalid response.');
    return response.requests;
  }, []);
  const requests = data || [];
  const loaded = Array.isArray(data) && !loading && !loadError;
  const [actionError, setActionError] = useState(null);
  const rejectDialog = useDialog();
  const [rejectionReason, setRejectionReason] = useState('');
  const [actionLoading, setActionLoading] = useState(false);

  useEffect(() => {
    active.current = true;
    return () => { active.current = false; };
  }, []);

  const loadRequests = async () => {
    setActionError(null);
    await reload();
  };

  const handleApprove = async (request) => {
    if (!loaded || actionPending.current) return;
    actionPending.current = true;
    try {
      setActionLoading(true);
      setActionError(null);
      await approveRoleRequest(request.id);
      if (!active.current) return;
      await loadRequests(); // Refresh list
    } catch (err) {
      if (active.current) setActionError(requestErrorMessage(err, 'Failed to approve role request'));
    } finally {
      if (active.current) {
        actionPending.current = false;
        setActionLoading(false);
      }
    }
  };

  const handleRejectConfirm = async () => {
    if (!rejectDialog.data || !loaded || actionPending.current) return;
    actionPending.current = true;
    try {
      setActionLoading(true);
      setActionError(null);
      await rejectRoleRequest(rejectDialog.data.id, rejectionReason);
      if (!active.current) return;
      rejectDialog.close();
      setRejectionReason('');
      await loadRequests();
    } catch (err) {
      if (active.current) setActionError(requestErrorMessage(err, 'Failed to reject role request'));
    } finally {
      if (active.current) {
        actionPending.current = false;
        setActionLoading(false);
      }
    }
  };

  const handleRejectCancel = () => {
    if (actionPending.current) return;
    rejectDialog.close();
    setActionError(null);
    setRejectionReason('');
  };

  const getRoleChipColor = (role) => {
    switch (role) {
      case 'admin':
        return 'error';
      case 'operator':
        return 'warning';
      case 'member':
        return 'primary';
      default:
        return 'default';
    }
  };

  const formatRole = (role) => {
    return role.charAt(0).toUpperCase() + role.slice(1);
  };

  const formatDate = (dateString) => {
    return new Date(dateString).toLocaleString();
  };

  return (
    <ResourcePage
      title={t('org.roleEscalation.title')}
      description={t('org.roleEscalation.subtitle')}
    >
      {loadError && (
        <Alert severity="error" sx={{ mb: 2 }} action={
          <Button color="inherit" size="small" onClick={loadRequests}>{t('actions.retry', { ns: 'common' })}</Button>
        }>
          {requestErrorMessage(loadError, 'Failed to load role escalation requests')}
        </Alert>
      )}
      {actionError && !rejectDialog.isOpen && (
        <Alert severity="error" sx={{ mb: 2 }} onClose={() => setActionError(null)}>
          {actionError}
        </Alert>
      )}

      <Box sx={{ display: 'flex', justifyContent: 'flex-end', mb: 2 }}>
        <Button onClick={loadRequests} disabled={loading || actionLoading}>{t('org.membership.refresh')}</Button>
      </Box>

      {(loading || loaded) && <TableContainer component={Paper}>
        <Table>
          <TableHead>
            <TableRow>
              <TableCell>{t('org.roleEscalation.tableHeaders.user')}</TableCell>
              <TableCell>{t('org.roleEscalation.tableHeaders.currentRole')}</TableCell>
              <TableCell>{t('org.roleEscalation.tableHeaders.requestedRole')}</TableCell>
              <TableCell>{t('org.roleEscalation.tableHeaders.message')}</TableCell>
              <TableCell>{t('org.roleEscalation.tableHeaders.requestedAt')}</TableCell>
              <TableCell align="right">{t('org.roleEscalation.tableHeaders.actions')}</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {loading ? (
              <TableRow>
                <TableCell colSpan={6} align="center">
                  <Typography variant="body2" color="text.secondary">
                    {t('org.roleEscalation.loading')}
                  </Typography>
                </TableCell>
              </TableRow>
            ) : requests.length === 0 ? (
              <TableRow>
                <TableCell colSpan={6} align="center">
                  <Typography variant="body2" color="text.secondary">
                    {t('org.roleEscalation.empty')}
                  </Typography>
                </TableCell>
              </TableRow>
            ) : (
              requests.map((request) => (
                <TableRow key={request.id}>
                  <TableCell>
                    <Box>
                      <Typography variant="body2" sx={{ fontWeight: 'medium' }}>
                        {request.user_email}
                      </Typography>
                      <Typography variant="caption" color="text.secondary">
                        {t('org.roleEscalation.userId', { id: request.user_id })}
                      </Typography>
                    </Box>
                  </TableCell>
                  <TableCell>
                    <Chip
                      label={formatRole(request.current_role)}
                      color={getRoleChipColor(request.current_role)}
                      size="small"
                    />
                  </TableCell>
                  <TableCell>
                    <Chip
                      label={formatRole(request.requested_role)}
                      color={getRoleChipColor(request.requested_role)}
                      size="small"
                      variant="outlined"
                    />
                  </TableCell>
                  <TableCell>
                    <Typography
                      variant="body2"
                      sx={{
                        maxWidth: 300,
                        overflow: 'hidden',
                        textOverflow: 'ellipsis',
                        whiteSpace: 'nowrap',
                      }}
                    >
                      {request.message || '—'}
                    </Typography>
                  </TableCell>
                  <TableCell>
                    <Typography variant="body2" color="text.secondary">
                      {formatDate(request.created_at)}
                    </Typography>
                  </TableCell>
                  <TableCell align="right">
                    <Box sx={{ display: 'flex', gap: 1, justifyContent: 'flex-end' }}>
                      <IconButton
                        color="success"
                        size="small"
                        onClick={() => handleApprove(request)}
                        disabled={actionLoading}
                        aria-label={t('org.roleEscalation.actions.approve')}
                        title={t('org.roleEscalation.actions.approve')}
                      >
                        <CheckCircleIcon />
                      </IconButton>
                      <IconButton
                        color="error"
                        size="small"
                        onClick={() => { setActionError(null); setRejectionReason(''); rejectDialog.open(request); }}
                        disabled={actionLoading}
                        aria-label={t('org.roleEscalation.actions.reject')}
                        title={t('org.roleEscalation.actions.reject')}
                      >
                        <CancelIcon />
                      </IconButton>
                    </Box>
                  </TableCell>
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
      </TableContainer>}

      {/* Reject Dialog */}
      <Dialog
        open={rejectDialog.isOpen}
        onClose={handleRejectCancel}
        maxWidth="sm"
        fullWidth
      >
        <DialogTitle>{t('org.roleEscalation.dialog.title')}</DialogTitle>
        <DialogContent>
          {actionError && <Alert severity="error" sx={{ mb: 2 }}>{actionError}</Alert>}
          <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
            {t('org.roleEscalation.dialog.message')}{' '}
            <strong>{rejectDialog.data?.user_email}</strong> {t('org.roleEscalation.dialog.messageToBecome')}{' '}
            <strong>{rejectDialog.data ? formatRole(rejectDialog.data.requested_role) : ''}</strong>.
          </Typography>
          <TextField
            label={t('org.roleEscalation.dialog.reasonLabel')}
            multiline
            rows={3}
            fullWidth
            disabled={actionLoading}
            value={rejectionReason}
            onChange={(e) => setRejectionReason(e.target.value)}
            placeholder={t('org.roleEscalation.dialog.reasonPlaceholder')}
          />
        </DialogContent>
        <DialogActions>
          <Button onClick={handleRejectCancel} disabled={actionLoading}>
            {t('actions.cancel', { ns: 'common' })}
          </Button>
          <Button
            onClick={handleRejectConfirm}
            variant="contained"
            color="error"
            disabled={actionLoading}
          >
            {actionLoading ? t('org.roleEscalation.dialog.rejecting') : t('org.roleEscalation.dialog.reject')}
          </Button>
        </DialogActions>
      </Dialog>
    </ResourcePage>
  );
}

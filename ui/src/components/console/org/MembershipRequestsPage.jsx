/**
 * Membership Requests Page
 * 
 * Allows organization administrators to review and approve/reject
 * pending membership requests from users who want to join the organization.
 */

import { useEffect, useRef, useState } from 'react';
import { useAsyncData } from '../../../hooks/useAsyncData';
import { useAuth } from '../../../hooks/useAuth';
import { useConsole } from '../../../contexts/ConsoleContext';
import { useDialog } from '../../../hooks/useDialog';
import { useNotifications } from '../../../hooks/useNotifications';
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
  Button,
  Chip,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  TextField,
  Alert,
  CircularProgress,
  IconButton,
  Tooltip,
} from '@mui/material';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import CancelIcon from '@mui/icons-material/Cancel';
import RefreshIcon from '@mui/icons-material/Refresh';
import PersonAddIcon from '@mui/icons-material/PersonAdd';
import EmailIcon from '@mui/icons-material/Email';
import { useTranslation } from 'react-i18next';

import { ResourcePage } from '../../common';
import { getPendingRequests, approveMembershipRequest, rejectMembershipRequest } from '../../../services/membershipApi';

const getOrgTabs = (t) => [
  { label: t('org.tabs.organization'), path: '/console/org/settings' },
  { label: t('org.tabs.team'), path: '/console/org/team' },
  { label: t('org.tabs.membershipRequests'), path: '/console/org/membership-requests' },
  { label: t('org.tabs.webhooks'), path: '/console/org/webhooks' },
];

const getBreadcrumbs = (t) => [
  { label: t('org.breadcrumbs.console'), path: '/console' },
  { label: t('org.breadcrumbs.org'), path: '/console/org' },
  { label: t('org.breadcrumbs.membershipRequests'), path: '/console/org/membership-requests' },
];

function requestErrorMessage(error, fallback) {
  const message = typeof error?.message === 'string' ? error.message.trim() : '';
  return message || fallback;
}

function MembershipRequestsPage() {
  const { activeOrgId } = useConsole();
  const { user, isAuthenticated } = useAuth();
  const principalId = isAuthenticated ? user?.user_id || user?.sub || user?.id || 'unknown-user' : 'signed-out';
  return <MembershipRequestsContent key={`${activeOrgId || 'no-organization'}:${principalId}`} organizationId={activeOrgId} isAuthenticated={isAuthenticated} />;
}

function MembershipRequestsContent({ organizationId, isAuthenticated }) {
  const { t } = useTranslation('console');
  const { showSuccess } = useNotifications();
  const rejectDialog = useDialog();
  const active = useRef(true);
  const actionPending = useRef(false);
  useEffect(() => {
    active.current = true;
    return () => { active.current = false; };
  }, []);
  const { data, loading, error: loadError, reload } = useAsyncData(
    async () => {
      if (!organizationId) throw new Error('Select an organization before loading membership requests.');
      if (!isAuthenticated) throw new Error('Sign in before loading membership requests.');
      const response = await getPendingRequests();
      if (!Array.isArray(response?.requests)) throw new Error('Membership requests returned an invalid response.');
      return response.requests;
    },
    [],
  );
  const requests = data || [];
  const loaded = Array.isArray(data) && !loading && !loadError;
  const [actionError, setActionError] = useState(null);
  const [rejectionReason, setRejectionReason] = useState('');
  const [actionLoading, setActionLoading] = useState(false);
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
      const result = await approveMembershipRequest(request.id);
      if (!active.current) return;
      showSuccess(result.message || t('org.membership.success.approved', { email: request.user_email }));
      await loadRequests();
    } catch (err) {
      if (active.current) setActionError(requestErrorMessage(err, 'Failed to approve membership request'));
    } finally {
      if (active.current) {
        actionPending.current = false;
        setActionLoading(false);
      }
    }
  };

  const handleRejectClick = (request) => {
    if (!loaded || actionPending.current) return;
    setActionError(null);
    setRejectionReason('');
    rejectDialog.open(request);
  };

  const handleRejectConfirm = async () => {
    if (!rejectDialog.data || !loaded || actionPending.current) return;
    actionPending.current = true;

    try {
      setActionLoading(true);
      setActionError(null);
      
      const result = await rejectMembershipRequest(
        rejectDialog.data.id,
        rejectionReason.trim() || null
      );
      if (!active.current) return;
      showSuccess(result.message || t('org.membership.success.rejected', { email: rejectDialog.data.user_email }));
      
      rejectDialog.close();
      setRejectionReason('');
      
      // Refresh the list
      await loadRequests();
    } catch (err) {
      if (active.current) setActionError(requestErrorMessage(err, 'Failed to reject membership request'));
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

  const formatDate = (dateString) => {
    try {
      return new Date(dateString).toLocaleDateString('en-US', {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
      });
    } catch {
      return dateString;
    }
  };

  return (
    <ResourcePage
      title={t('org.membership.title')}
      description={t('org.membership.description')}
      tabs={getOrgTabs(t)}
      breadcrumbs={getBreadcrumbs(t)}
    >
      <Box sx={{ mb: 3 }}>
        {loadError && (
          <Alert severity="error" sx={{ mb: 2 }} action={
            <Button color="inherit" size="small" onClick={loadRequests}>{t('actions.retry', { ns: 'common' })}</Button>
          }>
            {requestErrorMessage(loadError, 'Failed to load membership requests')}
          </Alert>
        )}
        {actionError && !rejectDialog.isOpen && (
          <Alert severity="error" sx={{ mb: 2 }} onClose={() => setActionError(null)}>
            {actionError}
          </Alert>
        )}

        <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
          <Typography variant="h6">
            {loaded ? t('org.membership.pendingRequests', { count: requests.length }) : t('org.membership.title')}
          </Typography>
          <Tooltip title={t('org.membership.refresh')}>
            <span>
              <IconButton aria-label={t('org.membership.refresh')} onClick={loadRequests} disabled={loading || actionLoading}>
                <RefreshIcon />
              </IconButton>
            </span>
          </Tooltip>
        </Box>

        {loading ? (
          <Box sx={{ display: 'flex', justifyContent: 'center', py: 4 }}>
            <CircularProgress aria-label={t('common.loading', { ns: 'common' })} />
          </Box>
        ) : !loaded ? null : requests.length === 0 ? (
          <Paper sx={{ p: 6, textAlign: 'center', bgcolor: 'grey.50' }}>
            <PersonAddIcon sx={{ fontSize: 60, color: 'text.secondary', mb: 2 }} />
            <Typography variant="h6" gutterBottom>
              {t('org.membership.empty.title')}
            </Typography>
            <Typography variant="body2" color="text.secondary">
              {t('org.membership.empty.description')}
            </Typography>
          </Paper>
        ) : (
          <TableContainer component={Paper}>
            <Table>
              <TableHead>
                <TableRow>
                  <TableCell>{t('org.membership.tableHeaders.userEmail')}</TableCell>
                  <TableCell>{t('org.membership.tableHeaders.message')}</TableCell>
                  <TableCell>{t('org.membership.tableHeaders.requested')}</TableCell>
                  <TableCell>{t('org.membership.tableHeaders.status')}</TableCell>
                  <TableCell align="right">{t('org.membership.tableHeaders.actions')}</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {requests.map((request) => (
                  <TableRow key={request.id} hover>
                    <TableCell>
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                        <EmailIcon fontSize="small" color="action" />
                        {request.user_email}
                      </Box>
                    </TableCell>
                    <TableCell>
                      {request.message ? (
                        <Typography variant="body2" sx={{ maxWidth: 300 }}>
                          {request.message}
                        </Typography>
                      ) : (
                        <Typography variant="body2" color="text.secondary" sx={{ fontStyle: 'italic' }}>
                          {t('org.membership.noMessage')}
                        </Typography>
                      )}
                    </TableCell>
                    <TableCell>
                      <Typography variant="body2">
                        {formatDate(request.created_at)}
                      </Typography>
                    </TableCell>
                    <TableCell>
                      <Chip
                        label={request.status}
                        size="small"
                        color="warning"
                        variant="outlined"
                      />
                    </TableCell>
                    <TableCell align="right">
                      <Box sx={{ display: 'flex', gap: 1, justifyContent: 'flex-end' }}>
                        <Button
                          variant="contained"
                          color="success"
                          size="small"
                          startIcon={<CheckCircleIcon />}
                          onClick={() => handleApprove(request)}
                          disabled={actionLoading}
                        >
                          {t('org.membership.actions.approve')}
                        </Button>
                        <Button
                          variant="outlined"
                          color="error"
                          size="small"
                          startIcon={<CancelIcon />}
                          onClick={() => handleRejectClick(request)}
                          disabled={actionLoading}
                        >
                          {t('org.membership.actions.reject')}
                        </Button>
                      </Box>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        )}
      </Box>

      {/* Reject Dialog */}
      <Dialog open={rejectDialog.isOpen} onClose={handleRejectCancel} maxWidth="sm" fullWidth>
        <DialogTitle>{t('org.membership.dialog.title')}</DialogTitle>
        <DialogContent>
          {actionError && <Alert severity="error" sx={{ mb: 2 }}>{actionError}</Alert>}
          <Typography variant="body2" sx={{ mb: 2 }}>
            {t('org.membership.dialog.message')}{' '}
            <strong>{rejectDialog.data?.user_email}</strong>?
          </Typography>
          <TextField
            label={t('org.membership.dialog.reasonLabel')}
            multiline
            rows={3}
            fullWidth
            disabled={actionLoading}
            value={rejectionReason}
            onChange={(e) => setRejectionReason(e.target.value)}
            placeholder={t('org.membership.dialog.reasonPlaceholder')}
          />
        </DialogContent>
        <DialogActions>
          <Button onClick={handleRejectCancel} disabled={actionLoading}>
            {t('actions.cancel', { ns: 'common' })}
          </Button>
          <Button
            onClick={handleRejectConfirm}
            color="error"
            variant="contained"
            disabled={actionLoading}
          >
            {actionLoading ? t('org.membership.dialog.rejecting') : t('org.membership.dialog.reject')}
          </Button>
        </DialogActions>
      </Dialog>
    </ResourcePage>
  );
}

export default MembershipRequestsPage;

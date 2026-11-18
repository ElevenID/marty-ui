/** Review native pending memberships without invoking unsupported legacy writes. */
import { useLayoutEffect, useRef, useState } from 'react';
import { useAsyncData } from '../../../hooks/useAsyncData';
import { useAuth } from '../../../hooks/useAuth';
import { useConsole } from '../../../contexts/ConsoleContext';
import { usePermissions } from '../../../hooks/usePermissions';
import { useNotifications } from '../../../hooks/useNotifications';
import {
  Alert, Box, Button, Chip, CircularProgress, IconButton, Paper,
  Table, TableBody, TableCell, TableContainer, TableHead, TableRow, Tooltip, Typography,
} from '@mui/material';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import RefreshIcon from '@mui/icons-material/Refresh';
import PersonAddIcon from '@mui/icons-material/PersonAdd';
import { useTranslation } from 'react-i18next';
import { ResourcePage } from '../../common';
import ErrorState from '../../common/ErrorState';
import { getPendingRequests, approveMembershipRequest } from '../../../services/membershipApi';

function requestErrorMessage(error, fallback) {
  const message = typeof error?.message === 'string' ? error.message.trim() : '';
  return message || fallback;
}

export default function MembershipRequestsPage() {
  const { activeOrgId } = useConsole();
  const { user, isAuthenticated } = useAuth();
  const { can, isLoading, error: permissionError, refresh: refreshPermissions } = usePermissions();
  const { t } = useTranslation('console');
  const principalId = user?.user_id || user?.sub || user?.id || null;
  const canView = !isLoading && can('team', 'view');
  const canApprove = !isLoading && can('team', 'manage');
  const tabs = [
    { label: t('org.tabs.organization'), path: '/console/org/settings', allowed: !isLoading && can('organization', 'view') },
    { label: t('org.tabs.team'), path: '/console/org/team', allowed: canView },
    { label: t('org.tabs.membershipRequests'), path: '/console/org/membership-requests', allowed: canView },
    { label: t('org.tabs.webhooks'), path: '/console/org/webhooks', allowed: !isLoading && can('webhook', 'view') },
  ].filter(tab => tab.allowed);
  let content;
  if (!isAuthenticated) content = <Alert severity="info">{t('membershipReview.signIn')}</Alert>;
  else if (!activeOrgId) content = <Alert severity="info">{t('membershipReview.selectOrganization')}</Alert>;
  else if (isLoading) content = <CircularProgress aria-label={t('membershipReview.permissionsLoading')} />;
  else if (permissionError) content = <ErrorState error={permissionError} onRetry={refreshPermissions} variant="compact" />;
  else if (!canView) content = <Alert severity="info">{t('membershipReview.readDenied')}</Alert>;
  else {
    content = (
      <MembershipRequestsContent
        key={JSON.stringify([activeOrgId, principalId, canApprove])}
        organizationId={activeOrgId}
        canApprove={canApprove}
      />
    );
  }
  return (
    <ResourcePage
      title={t('org.membership.title')}
      description={t('membershipReview.description')}
      tabs={tabs}
      breadcrumbs={[
        { label: t('org.breadcrumbs.console'), path: '/console' },
        { label: t('org.breadcrumbs.org'), path: '/console/org' },
        { label: t('org.breadcrumbs.membershipRequests'), path: '/console/org/membership-requests' },
      ]}
    >
      {content}
    </ResourcePage>
  );
}

function MembershipRequestsContent({ organizationId, canApprove }) {
  const { t } = useTranslation('console');
  const { showSuccess } = useNotifications();
  const active = useRef(true);
  const actionPending = useRef(false);
  const [actionError, setActionError] = useState(null);
  const [actionLoading, setActionLoading] = useState(false);
  useLayoutEffect(() => {
    active.current = true;
    return () => { active.current = false; };
  }, []);
  const { data, loading, error: loadError, reload } = useAsyncData(async () => {
    const response = await getPendingRequests(organizationId, { isCurrent: () => active.current });
    if (!Array.isArray(response?.requests)) throw new Error('Membership requests returned an invalid response.');
    return response.requests;
  }, []);
  const requests = data || [];
  const loaded = Array.isArray(data) && !loading && !loadError;
  const loadRequests = async () => {
    setActionError(null);
    await reload();
  };
  const handleApprove = async request => {
    if (!loaded || !canApprove || actionPending.current) return;
    actionPending.current = true;
    setActionLoading(true);
    setActionError(null);
    try {
      await approveMembershipRequest(organizationId, request.id);
      if (!active.current) return;
      showSuccess(t('org.membership.success.approved', { email: request.email?.trim() || request.user_id }));
      await loadRequests();
    } catch (error) {
      if (active.current) setActionError(requestErrorMessage(error, t('membershipReview.approvalFailed')));
    } finally {
      if (active.current) {
        actionPending.current = false;
        setActionLoading(false);
      }
    }
  };

  return (
    <Box sx={{ mb: 3 }}>
      <Alert severity="info" sx={{ mb: 2 }}>
        {t(canApprove ? 'membershipReview.approvalOnly' : 'membershipReview.viewOnly')}
      </Alert>
      {loadError && (
        <Alert severity="error" sx={{ mb: 2 }} action={
          <Button color="inherit" size="small" onClick={loadRequests}>{t('actions.retry', { ns: 'common' })}</Button>
        }>
          {requestErrorMessage(loadError, t('membershipReview.loadFailed'))}
        </Alert>
      )}
      {actionError && (
        <Alert severity="error" sx={{ mb: 2 }} onClose={() => setActionError(null)}>{actionError}</Alert>
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
          <Typography variant="h6" gutterBottom>{t('org.membership.empty.title')}</Typography>
          <Typography variant="body2" color="text.secondary">{t('org.membership.empty.description')}</Typography>
        </Paper>
      ) : (
        <TableContainer component={Paper}>
          <Table>
            <TableHead>
              <TableRow>
                <TableCell>{t('membershipReview.applicant')}</TableCell>
                <TableCell>{t('membershipReview.roles')}</TableCell>
                <TableCell>{t('org.membership.tableHeaders.status')}</TableCell>
                {canApprove && <TableCell align="right">{t('org.membership.tableHeaders.actions')}</TableCell>}
              </TableRow>
            </TableHead>
            <TableBody>
              {requests.map(request => (
                <TableRow key={request.id} hover>
                  <TableCell>{request.email?.trim() || t('membershipReview.account', { id: request.user_id })}</TableCell>
                  <TableCell>{request.roles.length
                    ? request.roles.map(role => role.display_name || role.name).join(', ')
                    : t('membershipReview.noRoles')}</TableCell>
                  <TableCell><Chip label={t('membershipReview.pending')} size="small" color="warning" variant="outlined" /></TableCell>
                  {canApprove && (
                    <TableCell align="right">
                      <Button variant="contained" color="success" size="small" startIcon={<CheckCircleIcon />}
                        onClick={() => handleApprove(request)} disabled={actionLoading}>
                        {t('org.membership.actions.approve')}
                      </Button>
                    </TableCell>
                  )}
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>
      )}
    </Box>
  );
}

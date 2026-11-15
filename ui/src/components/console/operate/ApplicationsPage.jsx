/**
 * Applications Page
 * 
 * Manage credential applications from applicants.
 */

import { useLayoutEffect, useRef, useState } from 'react';
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
  TextField,
  InputAdornment,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Button,
} from '@mui/material';
import SearchIcon from '@mui/icons-material/Search';
import VisibilityIcon from '@mui/icons-material/Visibility';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import CancelIcon from '@mui/icons-material/Cancel';
import RefreshIcon from '@mui/icons-material/Refresh';
import ReplayIcon from '@mui/icons-material/Replay';
import SendIcon from '@mui/icons-material/Send';
import { Link, useNavigate } from 'react-router';
import { useTranslation } from 'react-i18next';
import { useConsole } from '../../../contexts/ConsoleContext';
import { useAuth } from '../../../hooks/useAuth';
import { useAsyncData } from '../../../hooks/useAsyncData';
import { useNotifications } from '../../../hooks/useNotifications';
import { usePermissions } from '../../../hooks/usePermissions';
import {
  issueOrganizationApplication,
  reviewOrganizationApplication,
} from '../../../services/applicantApi';
import { loadOrganizationApplications } from '../../../application/applications';
import { pickOfficialReference } from '../../../utils/officialReferences';

import { ResourcePage, EmptyState, EmptyStates, StatusChip } from '../../common';
import { getOperateTabs } from '../../../config/operateTabs';

const getBreadcrumbs = (t) => [
  { label: t('operate.breadcrumbs.console'), path: '/console' },
  { label: t('operate.breadcrumbs.operate'), path: '/console/org/operate' },
  { label: t('operate.breadcrumbs.applications'), path: '/console/org/operate/applications' },
];

// Statuses that belong to the "pending" (in-progress / awaiting review) group
const PENDING_STATUSES = new Set([
  'submitted', 'under_review', 'vetting_in_progress', 'pending_review',
  'documents_pending', 'pending', 'draft', 'pending_information', 'needs_info',
]);
const REVIEWABLE_STATUSES = new Set(['submitted', 'under_review', 'pending_information']);
const REISSUABLE_STATUSES = new Set(['offered', 'credentialed', 'credential_issued', 'wallet_invite_ready']);

function errorMessage(error, fallback) {
  return (typeof error?.message === 'string' && error.message.trim()) || fallback;
}

function ApplicationsPage() {
  const { t } = useTranslation('console');
  const { activeOrgId: organizationId } = useConsole();
  const { user, isAuthenticated } = useAuth();
  const { can, isLoading } = usePermissions();
  const principalId = user?.user_id || user?.sub || user?.id || null;
  const canApprove = !isLoading && can('application', 'approve');
  const canReject = !isLoading && can('application', 'reject');
  const canIssue = !isLoading && can('issuance', 'initiate');
  let unavailable;
  if (!isAuthenticated) unavailable = <Alert severity="info">{t('operate.applications.signIn', 'Sign in to view applications.')}</Alert>;
  else if (!organizationId) unavailable = <Alert severity="info">{t('operate.applications.selectOrganization', 'Select an organization to view applications.')}</Alert>;
  else if (isLoading) unavailable = <LinearProgress aria-label={t('operate.applications.permissionsLoading', 'Checking application permissions')} />;
  else if (!can('application', 'view')) unavailable = <Alert severity="info">{t('operate.applications.readDenied', 'You do not have permission to view applications for this organization.')}</Alert>;

  if (unavailable) {
    return <ResourcePage title={t('operate.applications.title')} description={t('operate.applications.description')}
      tabs={getOperateTabs(t)} breadcrumbs={getBreadcrumbs(t)}>{unavailable}</ResourcePage>;
  }
  return <ApplicationsContent
    key={JSON.stringify([organizationId, principalId, canApprove, canReject, canIssue])}
    organizationId={organizationId} canApprove={canApprove} canReject={canReject} canIssue={canIssue}
  />;
}

function ApplicationsContent({ organizationId, canApprove, canReject, canIssue }) {
  const { t } = useTranslation('console');
  const navigate = useNavigate();
  const { showSuccess } = useNotifications();
  const active = useRef(true);
  const actionPending = useRef(false);
  const [busy, setBusy] = useState(false);
  const [actionError, setActionError] = useState(null);
  useLayoutEffect(() => {
    active.current = true;
    return () => { active.current = false; };
  }, []);
  const { data: _applicationsData, loading, error, reload } = useAsyncData(async () => {
    const result = await loadOrganizationApplications({ organizationId });
    if (!Array.isArray(result)) throw new Error('Applications returned an invalid response.');
    return result;
  }, [organizationId]);
  const applications = _applicationsData ?? [];
  const loaded = Array.isArray(_applicationsData) && !loading && !error;
  const [searchQuery, setSearchQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState('all');

  const handleAction = async (app, action) => {
    const allowed = action === 'approve' ? canApprove && REVIEWABLE_STATUSES.has(app.rawStatus)
      : action === 'reject' ? canReject && REVIEWABLE_STATUSES.has(app.rawStatus)
        : canIssue && (app.rawStatus === 'approved' || REISSUABLE_STATUSES.has(app.rawStatus));
    if (!active.current || !loaded || !allowed || actionPending.current || !applications.includes(app)) return;
    actionPending.current = true;
    setBusy(true);
    setActionError(null);
    try {
      // Native review endpoints own a transient lock. A separate client lock
      // incorrectly requires application:review and can survive a failed write.
      if (action === 'approve') await reviewOrganizationApplication(organizationId, app.id, 'approve');
      else if (action === 'reject') await reviewOrganizationApplication(organizationId, app.id, 'reject', {
        reason: 'Rejected by organization reviewer',
      });
      else await issueOrganizationApplication(organizationId, app.id);
      if (!active.current) return;
      if (action === 'reissue') showSuccess(t('operate.applications.reissueSucceeded', 'New wallet invite generated — the applicant can now re-claim their credential.'));
      await reload();
    } catch (err) {
      if (active.current) setActionError(errorMessage(err, t('operate.applications.actionFailed', 'Unable to update the application. Please try again.')));
    } finally {
      if (active.current) {
        actionPending.current = false;
        setBusy(false);
      }
    }
  };

  const filteredApplications = applications.filter((app) => {
    const q = searchQuery.trim().toLowerCase();
    const applicationReference = pickOfficialReference({
      reference: app.reference,
      rawId: app.id,
      kind: 'application',
    });
    const matchesSearch = [app.id, applicationReference, app.applicant, app.credentialType]
      .some(value => String(value ?? '').toLowerCase().includes(q));
    const matchesStatus = statusFilter === 'all'
      || (statusFilter === 'pending' ? PENDING_STATUSES.has(app.status)
        : statusFilter === 'under_review' ? ['under_review', 'pending_review', 'vetting_in_progress'].includes(app.status)
          : statusFilter === 'pending_information' ? ['pending_information', 'needs_info', 'documents_pending'].includes(app.status)
            : app.status === statusFilter);
    return matchesSearch && matchesStatus;
  });

  return (
    <ResourcePage
      title={t('operate.applications.title')}
      description={t('operate.applications.description')}
      tabs={getOperateTabs(t)}
      breadcrumbs={getBreadcrumbs(t)}
      actions={
        <Button
          variant="outlined"
          startIcon={<RefreshIcon />}
          onClick={reload}
          disabled={loading || busy}
        >
          {t('operate.applications.refresh')}
        </Button>
      }
    >
      {error && (
        <Alert severity="error" sx={{ mb: 3 }} action={
          <Button color="inherit" size="small" onClick={reload}>{t('actions.retry', { ns: 'common' })}</Button>
        }>
          {errorMessage(error, t('operate.applications.errorLoading'))}
        </Alert>
      )}
      {actionError && <Alert severity="error" sx={{ mb: 3 }} onClose={() => setActionError(null)}>{actionError}</Alert>}
      {/* Filters */}
      <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 2, mb: 3 }}>
        <TextField
          label={t('operate.applications.searchPlaceholder')}
          placeholder={t('operate.applications.searchPlaceholder')}
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          size="small"
          sx={{ width: { xs: '100%', sm: 300 } }}
          slotProps={{
            input: {
              startAdornment: (
                <InputAdornment position="start">
                  <SearchIcon color="action" />
                </InputAdornment>
              ),
            }
          }}
        />
        <FormControl size="small" sx={{ minWidth: 180, width: { xs: '100%', sm: 'auto' } }}>
          <InputLabel id="applications-status-label">{t('operate.applications.filters.status')}</InputLabel>
          <Select
            labelId="applications-status-label"
            id="applications-status"
            value={statusFilter}
            label={t('operate.applications.filters.status')}
            onChange={(e) => setStatusFilter(e.target.value)}
          >
            <MenuItem value="all">{t('operate.applications.filters.all')}</MenuItem>
            <MenuItem value="pending">{t('operate.applications.filters.pending')}</MenuItem>
            <MenuItem value="under_review">{t('operate.applications.filters.underReview', 'Under Review')}</MenuItem>
            <MenuItem value="pending_information">{t('operate.applications.filters.pendingInformation', 'Awaiting Information')}</MenuItem>
            <MenuItem value="approved">{t('operate.applications.filters.approved')}</MenuItem>
            <MenuItem value="rejected">{t('operate.applications.filters.rejected')}</MenuItem>
          </Select>
        </FormControl>
      </Box>
      {loading ? (
        <LinearProgress />
      ) : !loaded ? null : applications.length === 0 ? (
        <EmptyState {...EmptyStates.applications} />
      ) : (
        <TableContainer component={Paper}>
          <Table>
            <TableHead>
              <TableRow>
                <TableCell>{t('operate.applications.tableHeaders.applicationReference', 'Application Reference')}</TableCell>
                <TableCell>{t('operate.applications.tableHeaders.applicant')}</TableCell>
                <TableCell>{t('operate.applications.tableHeaders.credentialType')}</TableCell>
                <TableCell>{t('operate.applications.tableHeaders.submitted')}</TableCell>
                <TableCell>{t('operate.applications.tableHeaders.documents')}</TableCell>
                <TableCell>{t('operate.applications.tableHeaders.verification')}</TableCell>
                <TableCell>{t('operate.applications.tableHeaders.status')}</TableCell>
                <TableCell align="right">{t('operate.applications.tableHeaders.actions')}</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {filteredApplications.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={8} align="center">
                    <Typography color="text.secondary" sx={{ py: 4 }}>
                      {t('operate.applications.noMatchingApplications')}
                    </Typography>
                    <Button onClick={() => { setSearchQuery(''); setStatusFilter('all'); }}>
                      {t('operate.applications.clearFilters', 'Clear filters')}
                    </Button>
                  </TableCell>
                </TableRow>
              ) : (
                filteredApplications.map((app) => (
                  <TableRow
                    key={app.id}
                    hover
                    onClick={(event) => {
                      if (event.target.closest('button, a')) return;
                      navigate(`/console/org/operate/applications/${app.id}`);
                    }}
                    sx={{ cursor: 'pointer' }}
                  >
                    <TableCell>
                      <Typography variant="body2" sx={{ fontFamily: 'monospace' }}>
                        {pickOfficialReference({
                          reference: app.reference,
                          rawId: app.id,
                          kind: 'application',
                        })}
                      </Typography>
                    </TableCell>
                    <TableCell>{app.applicant || '—'}</TableCell>
                    <TableCell>{app.credentialType || '—'}</TableCell>
                    <TableCell>
                      {new Date(app.submittedAt).toLocaleDateString()}
                    </TableCell>
                    <TableCell>
                      {app.documentsUploaded === null ? (
                        <Chip label={t('operate.applications.notReported', 'Not reported')} size="small" variant="outlined" />
                      ) : <Chip
                        label={app.documentsUploaded ? t('operate.applications.documents.uploaded') : t('operate.applications.documents.pending')}
                        color={app.documentsUploaded ? 'success' : 'warning'}
                        size="small"
                        variant="outlined"
                      />}
                    </TableCell>
                    <TableCell>
                      {app.verificationPassed === null ? (
                        <Chip label={t('operate.applications.notReported', 'Not reported')} size="small" variant="outlined" />
                      ) : (
                        <Chip 
                          label={app.verificationPassed ? t('operate.applications.verification.passed') : t('operate.applications.verification.failed')} 
                          color={app.verificationPassed ? 'success' : 'error'}
                          size="small" 
                          variant="outlined"
                        />
                      )}
                    </TableCell>
                    <TableCell>
                      <StatusChip status={app.status === 'pending_information' ? 'needs_info' : app.status} />
                    </TableCell>
                    <TableCell align="right">
                      <Tooltip title={t('operate.applications.actions.viewDetails')}>
                        <IconButton
                          component={Link}
                          to={`/console/org/operate/applications/${app.id}`}
                          size="small"
                          aria-label={t('operate.applications.actions.viewDetails')}
                        >
                          <VisibilityIcon fontSize="small" />
                        </IconButton>
                      </Tooltip>
                      {REVIEWABLE_STATUSES.has(app.rawStatus) && canApprove && (
                          <Tooltip title={t('operate.applications.actions.approve')}>
                            <span><IconButton size="small" color="success" disabled={busy}
                              aria-label={t('operate.applications.actions.approve')} onClick={() => handleAction(app, 'approve')}>
                              <CheckCircleIcon fontSize="small" />
                            </IconButton></span>
                          </Tooltip>
                      )}
                      {REVIEWABLE_STATUSES.has(app.rawStatus) && canReject && (
                          <Tooltip title={t('operate.applications.actions.reject')}>
                            <span><IconButton size="small" color="error" disabled={busy}
                              aria-label={t('operate.applications.actions.reject')} onClick={() => handleAction(app, 'reject')}>
                              <CancelIcon fontSize="small" />
                            </IconButton></span>
                          </Tooltip>
                      )}
                      {app.rawStatus === 'approved' && canIssue && (
                        <Tooltip title={t('operate.applications.actions.issue', 'Generate wallet invite')}>
                          <span><IconButton size="small" color="primary" disabled={busy}
                            aria-label={t('operate.applications.actions.issue', 'Generate wallet invite')} onClick={() => handleAction(app, 'issue')}>
                            <SendIcon fontSize="small" />
                          </IconButton></span>
                        </Tooltip>
                      )}
                      {REISSUABLE_STATUSES.has(app.rawStatus) && canIssue && (
                        <Tooltip title={t('operate.applications.actions.reissue', 'Resend wallet invite')}>
                          <span><IconButton size="small" color="secondary" disabled={busy}
                            aria-label={t('operate.applications.actions.reissue', 'Resend wallet invite')} onClick={() => handleAction(app, 'reissue')}>
                            <ReplayIcon fontSize="small" />
                          </IconButton></span>
                        </Tooltip>
                      )}
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </TableContainer>
      )}
    </ResourcePage>
  );
}

export default ApplicationsPage;

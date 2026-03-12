/**
 * Applications Page
 * 
 * Manage credential applications from applicants.
 */

import { useState } from 'react';
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
import SendIcon from '@mui/icons-material/Send';
import { Link, useNavigate } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { useAuth } from '../../../hooks/useAuth';
import { useAsyncData } from '../../../hooks/useAsyncData';
import { useNotifications } from '../../../hooks/useNotifications';
import {
  issueOrganizationApplication,
  listOrganizationApplications,
  reviewOrganizationApplication,
} from '../../../services/applicantApi';

import { ResourcePage, EmptyState, EmptyStates, StatusChip } from '../../common';

const getOperateTabs = (t) => [
  { label: t('operate.tabs.issuance'), path: '/console/org/operate/issuance' },
  { label: t('operate.tabs.applications'), path: '/console/org/operate/applications' },
];

const getBreadcrumbs = (t) => [
  { label: t('operate.breadcrumbs.console'), path: '/console' },
  { label: t('operate.breadcrumbs.operate'), path: '/console/org/operate' },
  { label: t('operate.breadcrumbs.applications'), path: '/console/org/operate/applications' },
];

// Statuses that belong to the "pending" (in-progress / awaiting review) group
const PENDING_STATUSES = new Set([
  'submitted', 'under_review', 'vetting_in_progress', 'pending_review',
  'documents_pending', 'pending', 'draft',
]);

function ApplicationsPage() {
  const { t } = useTranslation('console');
  const { organizationId } = useAuth();
  const navigate = useNavigate();
  const { showError } = useNotifications();
  const { data: _applicationsData, loading, error, reload } = useAsyncData(async () => {
    if (!organizationId) return [];
    const [appsResult, applicantsResponse] = await Promise.all([
      listOrganizationApplications(organizationId),
      fetch(`/v1/applicants?organization_id=${encodeURIComponent(organizationId)}`, {
        credentials: 'include',
      }),
    ]);
    const rawApplicants = applicantsResponse.ok ? await applicantsResponse.json() : [];
    const applicants = Array.isArray(rawApplicants) ? rawApplicants : [];
    const applicantById = new Map(applicants.map((a) => [a.id, a]));
    return (appsResult.applications || []).map((app) => {
      const applicant = applicantById.get(app.applicant_id);
      const status = (app.status || '').toLowerCase();
      const metadata = app.metadata || {};
      return {
        id: app.id,
        applicant: applicant?.email || app.applicant_id,
        credentialType: app.credential_display_name || metadata.credential_display_name || app.credential_configuration_id,
        submittedAt: app.submitted_at || app.created_at,
        documentsUploaded: true,
        verificationPassed: true,
        status,
        rawStatus: status,
        issuanceTransactionId: metadata.issuance_transaction_id || null,
      };
    });
  }, [organizationId]);
  const applications = _applicationsData ?? [];
  const [searchQuery, setSearchQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState('pending');

  const handleApprove = async (applicationId) => {
    try {
      await reviewOrganizationApplication(applicationId, 'approve');
      await reload();
    } catch (err) {
      showError(err.message || 'Failed to approve application');
    }
  };

  const handleReject = async (applicationId) => {
    try {
      await reviewOrganizationApplication(applicationId, 'reject', {
        reason: 'Rejected by organization reviewer',
      });
      await reload();
    } catch (err) {
      showError(err.message || 'Failed to reject application');
    }
  };

  const handleIssue = async (applicationId) => {
    try {
      await issueOrganizationApplication(applicationId);
      await reload();
    } catch (err) {
      showError(err.message || 'Failed to issue credential');
    }
  };

  const filteredApplications = applications.filter((app) => {
    const q = searchQuery.toLowerCase();
    const matchesSearch = app.id.toLowerCase().includes(q) ||
      app.applicant.toLowerCase().includes(q) ||
      app.credentialType.toLowerCase().includes(q);
    const matchesStatus = statusFilter === 'all' ||
      (statusFilter === 'pending' ? PENDING_STATUSES.has(app.status) : app.status === statusFilter);
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
          disabled={loading}
        >
          {t('operate.applications.refresh')}
        </Button>
      }
    >
      {error && (
        <Alert severity="error" sx={{ mb: 3 }}>
          {error?.message || String(error)}
        </Alert>
      )}

      {/* Filters */}
      <Box sx={{ display: 'flex', gap: 2, mb: 3 }}>
        <TextField
          placeholder={t('operate.applications.searchPlaceholder')}
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          size="small"
          sx={{ width: 300 }}
          InputProps={{
            startAdornment: (
              <InputAdornment position="start">
                <SearchIcon color="action" />
              </InputAdornment>
            ),
          }}
        />
        <FormControl size="small" sx={{ minWidth: 180 }}>
          <InputLabel>{t('operate.applications.filters.status')}</InputLabel>
          <Select
            value={statusFilter}
            label={t('operate.applications.filters.status')}
            onChange={(e) => setStatusFilter(e.target.value)}
          >
            <MenuItem value="all">{t('operate.applications.filters.all')}</MenuItem>
            <MenuItem value="pending">{t('operate.applications.filters.pending')}</MenuItem>
            <MenuItem value="pending_review">{t('operate.applications.filters.pendingReview')}</MenuItem>
            <MenuItem value="documents_pending">{t('operate.applications.filters.documentsPending')}</MenuItem>
            <MenuItem value="approved">{t('operate.applications.filters.approved')}</MenuItem>
            <MenuItem value="rejected">{t('operate.applications.filters.rejected')}</MenuItem>
          </Select>
        </FormControl>
      </Box>

      {loading ? (
        <LinearProgress />
      ) : applications.length === 0 ? (
        <EmptyState {...EmptyStates.applications} />
      ) : (
        <TableContainer component={Paper}>
          <Table>
            <TableHead>
              <TableRow>
                <TableCell>{t('operate.applications.tableHeaders.applicationId')}</TableCell>
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
                        {app.id}
                      </Typography>
                    </TableCell>
                    <TableCell>{app.applicant}</TableCell>
                    <TableCell>{app.credentialType}</TableCell>
                    <TableCell>
                      {new Date(app.submittedAt).toLocaleDateString()}
                    </TableCell>
                    <TableCell>
                      <Chip
                        label={app.documentsUploaded ? t('operate.applications.documents.uploaded') : t('operate.applications.documents.pending')}
                        color={app.documentsUploaded ? 'success' : 'warning'}
                        size="small"
                        variant="outlined"
                      />
                    </TableCell>
                    <TableCell>
                      {app.verificationPassed === null ? (
                        <Chip label={t('operate.applications.verification.na')} size="small" variant="outlined" />
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
                      <StatusChip status={app.status} />
                    </TableCell>
                    <TableCell align="right">
                      <Tooltip title={t('operate.applications.actions.viewDetails')}>
                        <IconButton
                          component={Link}
                          to={`/console/org/operate/applications/${app.id}`}
                          size="small"
                        >
                          <VisibilityIcon fontSize="small" />
                        </IconButton>
                      </Tooltip>
                      {app.rawStatus === 'submitted' && (
                        <>
                          <Tooltip title={t('operate.applications.actions.approve')}>
                            <IconButton size="small" color="success" onClick={() => handleApprove(app.id)}>
                              <CheckCircleIcon fontSize="small" />
                            </IconButton>
                          </Tooltip>
                          <Tooltip title={t('operate.applications.actions.reject')}>
                            <IconButton size="small" color="error" onClick={() => handleReject(app.id)}>
                              <CancelIcon fontSize="small" />
                            </IconButton>
                          </Tooltip>
                        </>
                      )}
                      {app.rawStatus === 'approved' && (
                        <Tooltip title={t('operate.issuance.title')}>
                          <IconButton size="small" color="primary" onClick={() => handleIssue(app.id)}>
                            <SendIcon fontSize="small" />
                          </IconButton>
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

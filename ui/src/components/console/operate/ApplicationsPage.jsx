/**
 * Applications Page
 * 
 * Manage credential applications from applicants.
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
import { Link } from 'react-router-dom';
import { useTranslation } from 'react-i18next';

import { ResourcePage, EmptyState, EmptyStates, StatusChip } from '../../common';

const getOperateTabs = (t) => [
  { label: t('operate.tabs.issuance'), path: '/console/operate/issuance' },
  { label: t('operate.tabs.applications'), path: '/console/operate/applications' },
];

const getBreadcrumbs = (t) => [
  { label: t('operate.breadcrumbs.console'), path: '/console' },
  { label: t('operate.breadcrumbs.operate'), path: '/console/operate' },
  { label: t('operate.breadcrumbs.applications'), path: '/console/operate/applications' },
];

function ApplicationsPage() {
  const { t } = useTranslation('console');
  const [applications, setApplications] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState('pending');

  useEffect(() => {
    loadApplications();
  }, []);

  const loadApplications = async () => {
    setLoading(true);
    try {
      await new Promise((resolve) => setTimeout(resolve, 500));
      setApplications([
        {
          id: 'app-2001',
          applicant: 'alice.johnson@example.com',
          credentialType: 'EU Digital Identity Credential',
          submittedAt: '2026-02-07T08:30:00Z',
          documentsUploaded: true,
          verificationPassed: true,
          status: 'pending_review',
        },
        {
          id: 'app-2002',
          applicant: 'charlie.brown@example.com',
          credentialType: 'Mobile Driving License',
          submittedAt: '2026-02-07T07:45:00Z',
          documentsUploaded: true,
          verificationPassed: false,
          status: 'verification_failed',
        },
        {
          id: 'app-2003',
          applicant: 'diana.prince@example.com',
          credentialType: 'EU Digital Identity Credential',
          submittedAt: '2026-02-06T16:00:00Z',
          documentsUploaded: false,
          verificationPassed: null,
          status: 'documents_pending',
        },
        {
          id: 'app-2004',
          applicant: 'edward.stark@example.com',
          credentialType: 'Employee Badge',
          submittedAt: '2026-02-06T14:30:00Z',
          documentsUploaded: true,
          verificationPassed: true,
          status: 'approved',
        },
      ]);
    } catch (err) {
      setError(t('operate.applications.errorLoading'));
    } finally {
      setLoading(false);
    }
  };

  const filteredApplications = applications.filter((app) => {
    const matchesSearch = app.id.toLowerCase().includes(searchQuery.toLowerCase()) ||
      app.applicant.toLowerCase().includes(searchQuery.toLowerCase()) ||
      app.credentialType.toLowerCase().includes(searchQuery.toLowerCase());
    const matchesStatus = statusFilter === 'all' || 
      (statusFilter === 'pending' && ['pending_review', 'documents_pending'].includes(app.status)) ||
      app.status === statusFilter;
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
          onClick={loadApplications}
          disabled={loading}
        >
          {t('operate.applications.refresh')}
        </Button>
      }
    >
      {error && (
        <Alert severity="error" sx={{ mb: 3 }}>
          {error}
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
                  <TableRow key={app.id} hover>
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
                          to={`/console/operate/applications/${app.id}`}
                          size="small"
                        >
                          <VisibilityIcon fontSize="small" />
                        </IconButton>
                      </Tooltip>
                      {app.status === 'pending_review' && (
                        <>
                          <Tooltip title={t('operate.applications.actions.approve')}>
                            <IconButton size="small" color="success">
                              <CheckCircleIcon fontSize="small" />
                            </IconButton>
                          </Tooltip>
                          <Tooltip title={t('operate.applications.actions.reject')}>
                            <IconButton size="small" color="error">
                              <CancelIcon fontSize="small" />
                            </IconButton>
                          </Tooltip>
                        </>
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

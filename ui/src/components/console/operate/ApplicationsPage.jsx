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

import { ResourcePage, EmptyState, EmptyStates, StatusChip } from '../../common';

const OPERATE_TABS = [
  { label: 'Issuance', path: '/console/operate/issuance' },
  { label: 'Applications', path: '/console/operate/applications' },
];

const BREADCRUMBS = [
  { label: 'Console', path: '/console' },
  { label: 'Operate', path: '/console/operate' },
  { label: 'Applications', path: '/console/operate/applications' },
];

function ApplicationsPage() {
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
      setError('Failed to load applications');
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
      title="Applications"
      description="Review and process credential applications."
      tabs={OPERATE_TABS}
      breadcrumbs={BREADCRUMBS}
      actions={
        <Button
          variant="outlined"
          startIcon={<RefreshIcon />}
          onClick={loadApplications}
          disabled={loading}
        >
          Refresh
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
          placeholder="Search applications..."
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
          <InputLabel>Status</InputLabel>
          <Select
            value={statusFilter}
            label="Status"
            onChange={(e) => setStatusFilter(e.target.value)}
          >
            <MenuItem value="all">All</MenuItem>
            <MenuItem value="pending">Pending</MenuItem>
            <MenuItem value="pending_review">Pending Review</MenuItem>
            <MenuItem value="documents_pending">Documents Pending</MenuItem>
            <MenuItem value="approved">Approved</MenuItem>
            <MenuItem value="rejected">Rejected</MenuItem>
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
                <TableCell>Application ID</TableCell>
                <TableCell>Applicant</TableCell>
                <TableCell>Credential Type</TableCell>
                <TableCell>Submitted</TableCell>
                <TableCell>Documents</TableCell>
                <TableCell>Verification</TableCell>
                <TableCell>Status</TableCell>
                <TableCell align="right">Actions</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {filteredApplications.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={8} align="center">
                    <Typography color="text.secondary" sx={{ py: 4 }}>
                      No applications match your filters. Try adjusting your search.
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
                        label={app.documentsUploaded ? 'Uploaded' : 'Pending'} 
                        color={app.documentsUploaded ? 'success' : 'warning'}
                        size="small" 
                        variant="outlined"
                      />
                    </TableCell>
                    <TableCell>
                      {app.verificationPassed === null ? (
                        <Chip label="N/A" size="small" variant="outlined" />
                      ) : (
                        <Chip 
                          label={app.verificationPassed ? 'Passed' : 'Failed'} 
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
                      <Tooltip title="View Details">
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
                          <Tooltip title="Approve">
                            <IconButton size="small" color="success">
                              <CheckCircleIcon fontSize="small" />
                            </IconButton>
                          </Tooltip>
                          <Tooltip title="Reject">
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

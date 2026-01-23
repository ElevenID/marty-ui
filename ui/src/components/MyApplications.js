/**
 * My Applications Component
 *
 * Applicant view showing their travel document applications and status.
 */

import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Box,
  Card,
  CardContent,
  Typography,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
  Chip,
  Button,
  CircularProgress,
  Alert,
  Tooltip,
} from '@mui/material';
import AddIcon from '@mui/icons-material/Add';
import RefreshIcon from '@mui/icons-material/Refresh';
import EditIcon from '@mui/icons-material/Edit';
import InfoIcon from '@mui/icons-material/Info';
import { useAuth } from '../hooks/useAuth';

// Application status colors
const STATUS_COLORS = {
  pending: 'warning',
  submitted: 'info',
  pending_approval: 'warning',
  under_review: 'info',
  approved: 'success',
  rejected: 'error',
  issued: 'success',
  completed: 'success',
  needs_revision: 'warning',
};

// Application status labels
const STATUS_LABELS = {
  pending: 'Pending',
  submitted: 'Submitted',
  pending_approval: 'Pending Approval',
  under_review: 'Under Review',
  approved: 'Approved',
  rejected: 'Rejected',
  issued: 'Issued',
  completed: 'Completed',
  needs_revision: 'Needs Revision',
};

function MyApplications() {
  const { user } = useAuth();
  const navigate = useNavigate();
  const [applications, setApplications] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const fetchApplications = async () => {
    setLoading(true);
    setError(null);

    try {
      let applicantId = user?.applicant_id;
      if (!applicantId && user?.user_id) {
        const applicantResponse = await fetch(`/api/applicants/by-user/${user.user_id}`, {
          credentials: 'include',
        });
        if (applicantResponse.ok) {
          const applicantData = await applicantResponse.json();
          applicantId = applicantData?.id;
        }
      }

      if (!applicantId) {
        throw new Error('Applicant profile not found');
      }

      const response = await fetch(`/api/applicants/${applicantId}/applications`, {
        credentials: 'include',
      });

      if (!response.ok) {
        throw new Error('Failed to fetch applications');
      }

      const data = await response.json();
      const applications = Array.isArray(data) ? data : (data.applications || []);
      setApplications(applications);
    } catch (err) {
      console.error('Error fetching applications:', err);
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchApplications();
  }, []);

  const formatDate = (dateString) => {
    if (!dateString) return 'N/A';
    return new Date(dateString).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
    });
  };

  return (
    <Box>
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
        <Typography variant="h4" component="h1">
          My Applications
        </Typography>

        <Box sx={{ display: 'flex', gap: 2 }}>
          <Button variant="outlined" startIcon={<RefreshIcon />} onClick={fetchApplications}>
            Refresh
          </Button>
          <Button variant="contained" startIcon={<AddIcon />} onClick={() => navigate('/credentials')}>
            New Application
          </Button>
        </Box>
      </Box>

      {/* Welcome Card */}
      <Card sx={{ mb: 3 }}>
        <CardContent>
          <Typography variant="h6" gutterBottom>
            Welcome, {user?.name || 'Applicant'}
          </Typography>
          <Typography variant="body2" color="textSecondary">
            Track your travel document applications below. You can start a new application or check
            the status of existing ones.
          </Typography>
        </CardContent>
      </Card>

      {/* Error Display */}
      {error && (
        <Alert severity="error" sx={{ mb: 3 }}>
          {error}
        </Alert>
      )}

      {/* Loading State */}
      {loading && (
        <Box display="flex" justifyContent="center" py={4}>
          <CircularProgress />
        </Box>
      )}

      {/* Applications Table */}
      {!loading && !error && (
        <TableContainer component={Paper} data-testid="applications-table">
          <Table>
            <TableHead>
              <TableRow>
                <TableCell>Application ID</TableCell>
                <TableCell>Document Type</TableCell>
                <TableCell>Submitted</TableCell>
                <TableCell>Status</TableCell>
                <TableCell>Last Updated</TableCell>
                <TableCell align="right">Actions</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {applications.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={6} align="center">
                    <Typography color="textSecondary" sx={{ py: 4 }}>
                      No applications found. Start a new application to begin your travel document
                      process.
                    </Typography>
                  </TableCell>
                </TableRow>
              ) : (
                applications.map((app) => (
                  <TableRow key={app.id} hover data-testid={`application-row-${app.id}`}>
                    <TableCell>
                      <Typography variant="body2" fontFamily="monospace">
                        {app.id?.slice(0, 8)}...
                      </Typography>
                      {app.revision_notes && (
                        <Tooltip title={app.revision_notes} arrow>
                          <Box sx={{ display: 'flex', alignItems: 'center', mt: 0.5 }}>
                            <InfoIcon fontSize="small" color="warning" sx={{ mr: 0.5 }} />
                            <Typography variant="caption" color="warning.main">
                              Revision requested
                            </Typography>
                          </Box>
                        </Tooltip>
                      )}
                    </TableCell>
                    <TableCell>{app.credential_display_name || app.document_type || 'Credential'}</TableCell>
                    <TableCell>{formatDate(app.submitted_at)}</TableCell>
                    <TableCell>
                      <Chip
                        label={STATUS_LABELS[`${app.status || ''}`.toLowerCase()] || app.status}
                        color={STATUS_COLORS[`${app.status || ''}`.toLowerCase()] || 'default'}
                        size="small"
                      />
                    </TableCell>
                    <TableCell>{formatDate(app.updated_at)}</TableCell>
                    <TableCell align="right">
                      <Box sx={{ display: 'flex', gap: 1, justifyContent: 'flex-end' }}>
                        {app.status?.toLowerCase() === 'needs_revision' && (
                          <Button
                            size="small"
                            variant="contained"
                            color="warning"
                            startIcon={<EditIcon />}
                            onClick={() => navigate(`/application/${app.credential_configuration_id}`, {
                              state: { applicationId: app.id, revisionData: app }
                            })}
                          >
                            Edit & Resubmit
                          </Button>
                        )}
                        <Button size="small">View Details</Button>
                      </Box>
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </TableContainer>
      )}
    </Box>
  );
}

export default MyApplications;

/**
 * Vendor Application Review Component
 * 
 * Restructured to include two tabs:
 * 1. Application Templates - Define what applicants can apply for
 * 2. Applications - Review and manage submitted applications
 * 
 * Templates encapsulate trust profiles, credential types, required documents,
 * and approval workflows. Applications are instances of templates.
 */

import React, { useState, useEffect, useCallback } from 'react';
import {
  Box,
  Typography,
  Paper,
  Button,
  TextField,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  TablePagination,
  Chip,
  IconButton,
  Alert,
  Snackbar,
  CircularProgress,
  Tabs,
  Tab,
  Tooltip,
  List,
  ListItem,
  ListItemText,
  Divider,
  Grid,
} from '@mui/material';
import {
  Visibility as ViewIcon,
  CheckCircle as ApproveIcon,
  Cancel as RejectIcon,
  Edit as RevisionIcon,
  Refresh as RefreshIcon,
  CheckCircle as PassedIcon,
  Cancel as FailedIcon,
  Schedule as PendingIcon,
  Description as ApplicationsIcon,
  Assignment as TemplatesIcon,
} from '@mui/icons-material';
import { useAuth } from '../../hooks/useAuth';
import {
  listApplications,
  getVettingChecks,
  approveApplication,
  rejectApplication,
} from '../ApplicantVetting';
import ApplicationTemplateManager from './ApplicationTemplateManager';

// Add request revision API function
async function requestRevision(applicationId, data) {
  const response = await fetch(`/api/applicants/applications/${applicationId}/request-revision`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  });
  if (!response.ok) {
    const error = await response.json();
    throw new Error(error.detail || 'Failed to request revision');
  }
  return response.json();
}

// Status configuration
const STATUS_LABELS = {
  draft: 'Draft',
  submitted: 'Submitted',
  identity_proofing: 'Identity Proofing',
  pending_kyc: 'Pending KYC',
  kyc_review: 'KYC Review',
  pending_vetting: 'Pending Vetting',
  vetting_in_progress: 'Vetting In Progress',
  pending_biometrics: 'Pending Biometrics',
  pending_approval: 'Pending Approval',
  needs_revision: 'Needs Revision',
  approved: 'Approved',
  rejected: 'Rejected',
  issued: 'Issued',
  expired: 'Expired',
  cancelled: 'Cancelled',
};

const STATUS_COLORS = {
  draft: 'default',
  submitted: 'info',
  identity_proofing: 'info',
  pending_kyc: 'warning',
  kyc_review: 'warning',
  pending_vetting: 'warning',
  vetting_in_progress: 'info',
  pending_biometrics: 'warning',
  pending_approval: 'warning',
  needs_revision: 'warning',
  approved: 'success',
  rejected: 'error',
  issued: 'success',
  expired: 'default',
  cancelled: 'default',
};

const CHECK_LABELS = {
  criminal_history: 'Criminal History',
  identity_verification: 'Identity Verification',
  document_verification: 'Document Verification',
  biometric_enrollment: 'Biometric Enrollment',
  sanctions_screening: 'Sanctions Screening',
  watchlist_check: 'Watchlist Check',
  reference_check: 'Reference Check',
  address_verification: 'Address Verification',
  employment_verification: 'Employment Verification',
  financial_check: 'Financial Check',
};

const CHECK_STATUS_COLORS = {
  not_started: 'default',
  pending: 'default',
  in_progress: 'info',
  passed: 'success',
  failed: 'error',
  requires_manual_review: 'warning',
  completed_passed: 'success',
  completed_failed: 'error',
};

function VendorApplicationReview() {
  const { organizationId, user } = useAuth();
  
  // State
  const [applications, setApplications] = useState([]);
  const [totalApplications, setTotalApplications] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [success, setSuccess] = useState(null);
  
  // Pagination
  const [page, setPage] = useState(0);
  const [rowsPerPage, setRowsPerPage] = useState(25);
  
  // Filters
  const [statusFilter, setStatusFilter] = useState('pending_approval');
  
  // Dialogs
  const [viewDialogOpen, setViewDialogOpen] = useState(false);
  const [approveDialogOpen, setApproveDialogOpen] = useState(false);
  const [rejectDialogOpen, setRejectDialogOpen] = useState(false);
  const [revisionDialogOpen, setRevisionDialogOpen] = useState(false);
  
  // Selected application
  const [selectedApplication, setSelectedApplication] = useState(null);
  const [vettingChecks, setVettingChecks] = useState([]);
  const [loadingChecks, setLoadingChecks] = useState(false);
  
  // Form data
  const [approvalNotes, setApprovalNotes] = useState('');
  const [rejectionReason, setRejectionReason] = useState('');
  const [revisionNotes, setRevisionNotes] = useState('');
  const [submitting, setSubmitting] = useState(false);

  // Fetch applications
  const fetchApplications = useCallback(async () => {
    if (!organizationId) return;
    
    setLoading(true);
    setError(null);
    
    try {
      const params = {
        organization_id: organizationId,
        limit: rowsPerPage,
        offset: page * rowsPerPage,
      };
      
      if (statusFilter && statusFilter !== 'all') {
        params.status = statusFilter;
      }
      
      const data = await listApplications(params);
      setApplications(data.applications || []);
      setTotalApplications(data.total || 0);
    } catch (err) {
      console.error('Failed to fetch applications:', err);
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }, [organizationId, statusFilter, page, rowsPerPage]);

  useEffect(() => {
    fetchApplications();
  }, [fetchApplications]);

  // Handle view application
  const handleViewApplication = async (application) => {
    setSelectedApplication(application);
    setViewDialogOpen(true);
    setLoadingChecks(true);
    
    try {
      const checks = await getVettingChecks(application.id);
      setVettingChecks(checks.checks || []);
    } catch (err) {
      console.error('Failed to fetch vetting checks:', err);
    } finally {
      setLoadingChecks(false);
    }
  };

  // Handle approve
  const handleApprove = async () => {
    if (!selectedApplication) return;
    
    setSubmitting(true);
    setError(null);
    
    try {
      await approveApplication(selectedApplication.id, {
        approved_by: user?.email || 'vendor',
        notes: approvalNotes,
      });
      
      setSuccess(`Application ${selectedApplication.application_number} approved successfully`);
      setApproveDialogOpen(false);
      setApprovalNotes('');
      fetchApplications();
    } catch (err) {
      setError(err.message);
    } finally {
      setSubmitting(false);
    }
  };

  // Handle reject
  const handleReject = async () => {
    if (!selectedApplication) return;
    
    setSubmitting(true);
    setError(null);
    
    try {
      await rejectApplication(selectedApplication.id, {
        rejected_by: user?.email || 'vendor',
        reason: rejectionReason,
      });
      
      setSuccess(`Application ${selectedApplication.application_number} rejected`);
      setRejectDialogOpen(false);
      setRejectionReason('');
      fetchApplications();
    } catch (err) {
      setError(err.message);
    } finally {
      setSubmitting(false);
    }
  };

  // Handle request revision
  const handleRequestRevision = async () => {
    if (!selectedApplication) return;
    
    setSubmitting(true);
    setError(null);
    
    try {
      await requestRevision(selectedApplication.id, {
        rejected_by: user?.email || 'vendor',  // Reusing field name
        reason: revisionNotes,
      });
      
      setSuccess(`Revision requested for application ${selectedApplication.application_number}`);
      setRevisionDialogOpen(false);
      setRevisionNotes('');
      fetchApplications();
    } catch (err) {
      setError(err.message);
    } finally {
      setSubmitting(false);
    }
  };

  // Handle tab change
  const handleStatusFilterChange = (event, newValue) => {
    setStatusFilter(newValue);
    setPage(0);
  };

  // Main tabs state
  const [mainTab, setMainTab] = useState(0);

  return (
    <Box>
      <Typography variant="h4" gutterBottom>
        Applications
      </Typography>
      
      <Typography variant="body2" color="text.secondary" paragraph>
        Manage application templates (what can be applied for) and review submitted applications.
      </Typography>

      {/* Main Tabs: Templates vs Applications */}
      <Paper sx={{ mb: 3 }}>
        <Tabs value={mainTab} onChange={(e, v) => setMainTab(v)} sx={{ borderBottom: 1, borderColor: 'divider' }}>
          <Tab icon={<TemplatesIcon />} iconPosition="start" label="Application Templates" />
          <Tab icon={<ApplicationsIcon />} iconPosition="start" label="Applications" />
        </Tabs>

        {/* Templates Tab */}
        {mainTab === 0 && (
          <Box sx={{ p: 3 }}>
            <ApplicationTemplateManager />
          </Box>
        )}

        {/* Applications Tab */}
        {mainTab === 1 && (
          <Box sx={{ p: 3 }}>
            {/* Status Tabs */}
            <Paper sx={{ mb: 3 }} elevation={0}>
              <Tabs value={statusFilter} onChange={handleStatusFilterChange} variant="scrollable">
                <Tab label="Pending Review" value="pending_approval" />
                <Tab label="Needs Revision" value="needs_revision" />
                <Tab label="Under Review" value="vetting_in_progress" />
                <Tab label="Approved" value="approved" />
                <Tab label="Rejected" value="rejected" />
                <Tab label="All" value="all" />
              </Tabs>
            </Paper>

      {/* Error/Success Messages */}
      <Snackbar 
        open={!!error} 
        autoHideDuration={6000} 
        onClose={() => setError(null)}
        anchorOrigin={{ vertical: 'top', horizontal: 'center' }}
      >
        <Alert severity="error" onClose={() => setError(null)}>
          {error}
        </Alert>
      </Snackbar>
      
      <Snackbar 
        open={!!success} 
        autoHideDuration={4000} 
        onClose={() => setSuccess(null)}
        anchorOrigin={{ vertical: 'top', horizontal: 'center' }}
      >
        <Alert severity="success" onClose={() => setSuccess(null)}>
          {success}
        </Alert>
      </Snackbar>

      {/* Applications Table */}
      <Paper>
        <Box sx={{ p: 2, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <Typography variant="h6">
            Applications ({totalApplications})
          </Typography>
          <Button
            startIcon={<RefreshIcon />}
            onClick={fetchApplications}
            disabled={loading}
          >
            Refresh
          </Button>
        </Box>
        
        <TableContainer>
          <Table>
            <TableHead>
              <TableRow>
                <TableCell>Reference</TableCell>
                <TableCell>Applicant</TableCell>
                <TableCell>Document Type</TableCell>
                <TableCell>Submitted</TableCell>
                <TableCell>Status</TableCell>
                <TableCell>Actions</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {loading ? (
                <TableRow>
                  <TableCell colSpan={6} align="center">
                    <CircularProgress size={40} />
                  </TableCell>
                </TableRow>
              ) : applications.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={6} align="center">
                    <Typography color="text.secondary">
                      No applications found
                    </Typography>
                  </TableCell>
                </TableRow>
              ) : (
                applications.map((app) => (
                  <TableRow key={app.id} hover>
                    <TableCell>
                      <Typography variant="body2" fontWeight="medium">
                        {app.application_number}
                      </Typography>
                    </TableCell>
                    <TableCell>
                      <Typography variant="body2">
                        {app.holder_name}
                      </Typography>
                    </TableCell>
                    <TableCell>{app.document_type || 'N/A'}</TableCell>
                    <TableCell>
                      {app.submitted_at 
                        ? new Date(app.submitted_at).toLocaleDateString()
                        : 'Not submitted'}
                    </TableCell>
                    <TableCell>
                      <Chip
                        label={STATUS_LABELS[app.status] || app.status}
                        color={STATUS_COLORS[app.status] || 'default'}
                        size="small"
                      />
                    </TableCell>
                    <TableCell>
                      <Tooltip title="View Details">
                        <IconButton
                          size="small"
                          onClick={() => handleViewApplication(app)}
                        >
                          <ViewIcon />
                        </IconButton>
                      </Tooltip>
                      {app.status === 'pending_approval' && (
                        <>
                          <Tooltip title="Approve">
                            <IconButton
                              size="small"
                              color="success"
                              onClick={() => {
                                setSelectedApplication(app);
                                setApproveDialogOpen(true);
                              }}
                            >
                              <ApproveIcon />
                            </IconButton>
                          </Tooltip>
                          <Tooltip title="Request Revision">
                            <IconButton
                              size="small"
                              color="warning"
                              onClick={() => {
                                setSelectedApplication(app);
                                setRevisionDialogOpen(true);
                              }}
                            >
                              <RevisionIcon />
                            </IconButton>
                          </Tooltip>
                          <Tooltip title="Reject">
                            <IconButton
                              size="small"
                              color="error"
                              onClick={() => {
                                setSelectedApplication(app);
                                setRejectDialogOpen(true);
                              }}
                            >
                              <RejectIcon />
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
        
        <TablePagination
          component="div"
          count={totalApplications}
          page={page}
          onPageChange={(e, newPage) => setPage(newPage)}
          rowsPerPage={rowsPerPage}
          onRowsPerPageChange={(e) => {
            setRowsPerPage(parseInt(e.target.value, 10));
            setPage(0);
          }}
        />
      </Paper>

      {/* View Application Dialog */}
      <Dialog
        open={viewDialogOpen}
        onClose={() => setViewDialogOpen(false)}
        maxWidth="md"
        fullWidth
      >
        <DialogTitle>
          Application Details
          {selectedApplication && ` - ${selectedApplication.application_number}`}
        </DialogTitle>
        <DialogContent>
          {selectedApplication && (
            <Box>
              <Grid container spacing={2} sx={{ mb: 3 }}>
                <Grid item xs={6}>
                  <Typography variant="body2" color="text.secondary">
                    Applicant Name
                  </Typography>
                  <Typography variant="body1">
                    {selectedApplication.holder_name}
                  </Typography>
                </Grid>
                <Grid item xs={6}>
                  <Typography variant="body2" color="text.secondary">
                    Status
                  </Typography>
                  <Chip
                    label={STATUS_LABELS[selectedApplication.status]}
                    color={STATUS_COLORS[selectedApplication.status]}
                    size="small"
                  />
                </Grid>
                <Grid item xs={6}>
                  <Typography variant="body2" color="text.secondary">
                    Document Type
                  </Typography>
                  <Typography variant="body1">
                    {selectedApplication.document_type || 'N/A'}
                  </Typography>
                </Grid>
                <Grid item xs={6}>
                  <Typography variant="body2" color="text.secondary">
                    Date of Birth
                  </Typography>
                  <Typography variant="body1">
                    {selectedApplication.holder_dob 
                      ? new Date(selectedApplication.holder_dob).toLocaleDateString()
                      : 'N/A'}
                  </Typography>
                </Grid>
                <Grid item xs={6}>
                  <Typography variant="body2" color="text.secondary">
                    Nationality
                  </Typography>
                  <Typography variant="body1">
                    {selectedApplication.nationality || 'N/A'}
                  </Typography>
                </Grid>
                <Grid item xs={6}>
                  <Typography variant="body2" color="text.secondary">
                    Submitted
                  </Typography>
                  <Typography variant="body1">
                    {selectedApplication.submitted_at
                      ? new Date(selectedApplication.submitted_at).toLocaleString()
                      : 'Not submitted'}
                  </Typography>
                </Grid>
              </Grid>

              <Divider sx={{ my: 2 }} />

              <Typography variant="h6" gutterBottom>
                Vetting Checks
              </Typography>
              
              {loadingChecks ? (
                <Box display="flex" justifyContent="center" p={2}>
                  <CircularProgress size={30} />
                </Box>
              ) : vettingChecks.length === 0 ? (
                <Typography color="text.secondary" variant="body2">
                  No vetting checks configured
                </Typography>
              ) : (
                <List>
                  {vettingChecks.map((check) => (
                    <ListItem key={check.id}>
                      <ListItemText
                        primary={CHECK_LABELS[check.check_type] || check.check_type}
                        secondary={check.notes || 'No notes'}
                      />
                      <Chip
                        label={check.status}
                        color={CHECK_STATUS_COLORS[check.status]}
                        size="small"
                        icon={
                          check.status === 'passed' || check.status === 'completed_passed' ? (
                            <PassedIcon />
                          ) : check.status === 'failed' || check.status === 'completed_failed' ? (
                            <FailedIcon />
                          ) : (
                            <PendingIcon />
                          )
                        }
                      />
                    </ListItem>
                  ))}
                </List>
              )}

              {selectedApplication.revision_notes && (
                <>
                  <Divider sx={{ my: 2 }} />
                  <Alert severity="info">
                    <Typography variant="body2" fontWeight="bold">
                      Revision Notes:
                    </Typography>
                    <Typography variant="body2">
                      {selectedApplication.revision_notes}
                    </Typography>
                  </Alert>
                </>
              )}
            </Box>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setViewDialogOpen(false)}>
            Close
          </Button>
        </DialogActions>
      </Dialog>

      {/* Approve Dialog */}
      <Dialog open={approveDialogOpen} onClose={() => setApproveDialogOpen(false)}>
        <DialogTitle>Approve Application</DialogTitle>
        <DialogContent>
          <Typography variant="body2" color="text.secondary" paragraph>
            Are you sure you want to approve this application? This will trigger credential issuance.
          </Typography>
          <TextField
            label="Approval Notes (Optional)"
            multiline
            rows={3}
            fullWidth
            value={approvalNotes}
            onChange={(e) => setApprovalNotes(e.target.value)}
            sx={{ mt: 2 }}
          />
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setApproveDialogOpen(false)} disabled={submitting}>
            Cancel
          </Button>
          <Button
            onClick={handleApprove}
            variant="contained"
            color="success"
            disabled={submitting}
            startIcon={submitting ? <CircularProgress size={16} /> : <ApproveIcon />}
          >
            Approve
          </Button>
        </DialogActions>
      </Dialog>

      {/* Reject Dialog */}
      <Dialog open={rejectDialogOpen} onClose={() => setRejectDialogOpen(false)}>
        <DialogTitle>Reject Application</DialogTitle>
        <DialogContent>
          <Typography variant="body2" color="text.secondary" paragraph>
            Please provide a reason for rejecting this application.
          </Typography>
          <TextField
            label="Rejection Reason *"
            multiline
            rows={3}
            fullWidth
            required
            value={rejectionReason}
            onChange={(e) => setRejectionReason(e.target.value)}
            sx={{ mt: 2 }}
          />
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setRejectDialogOpen(false)} disabled={submitting}>
            Cancel
          </Button>
          <Button
            onClick={handleReject}
            variant="contained"
            color="error"
            disabled={submitting || !rejectionReason.trim()}
            startIcon={submitting ? <CircularProgress size={16} /> : <RejectIcon />}
          >
            Reject
          </Button>
        </DialogActions>
      </Dialog>

      {/* Request Revision Dialog */}
      <Dialog open={revisionDialogOpen} onClose={() => setRevisionDialogOpen(false)}>
        <DialogTitle>Request Revision</DialogTitle>
        <DialogContent>
          <Typography variant="body2" color="text.secondary" paragraph>
            Request the applicant to revise their application. Provide clear instructions on what needs to be changed.
          </Typography>
          <TextField
            label="Revision Notes *"
            multiline
            rows={4}
            fullWidth
            required
            value={revisionNotes}
            onChange={(e) => setRevisionNotes(e.target.value)}
            placeholder="Please provide more details about your employment history..."
            sx={{ mt: 2 }}
          />
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setRevisionDialogOpen(false)} disabled={submitting}>
            Cancel
          </Button>
          <Button
            onClick={handleRequestRevision}
            variant="contained"
            color="warning"
            disabled={submitting || !revisionNotes.trim()}
            startIcon={submitting ? <CircularProgress size={16} /> : <RevisionIcon />}
          >
            Request Revision
          </Button>
        </DialogActions>
      </Dialog>
          </Box>
        )}
      </Paper>
    </Box>
  );
}

export default VendorApplicationReview;

import { useCallback, useEffect, useState } from 'react';
import {
  Alert,
  Box,
  Button,
  Card,
  CardContent,
  Chip,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  Grid,
  IconButton,
  LinearProgress,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  Paper,
  Snackbar,
  Tab,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Tabs,
  TextField,
  Typography,
} from '@mui/material';
import {
  Cancel as CancelIcon,
  Check as PassedIcon,
  CheckCircle as CheckIcon,
  Close as FailedIcon,
  Refresh as RefreshIcon,
  Security as SecurityIcon,
  Visibility as ViewIcon,
} from '@mui/icons-material';
import {
  approveApplication,
  completeCheck,
  getApplication,
  getPendingChecks,
  listApplications,
  rejectApplication,
} from '../../services/applicantApi';
import {
  approveVettingApplication,
  canRejectApplication,
  completeVettingDashboardCheck,
  filterApplicationsByTab,
  formatStatusLabel,
  getDashboardStats,
  loadVettingApplicationDetails,
  loadVettingDashboard,
  normalizeCheckStatus,
  normalizeEnumValue,
  rejectVettingApplication,
  resolveApprovalNotesInput,
  resolveApproveDialogClose,
  resolveApproveDialogOpen,
  resolveDashboardTabChange,
  resolveDetailDialogClose,
  resolveRejectDialogClose,
  resolveRejectDialogOpen,
  resolveRejectionReasonInput,
} from '../../application/vetting';
import {
  CHECK_STATUS_COLORS,
  CHECK_TYPE_ICONS,
  STATUS_COLORS,
  formatDate,
} from './shared';

/**
 * Dashboard for reviewing and processing vetting checks.
 */
export function VettingDashboard() {
  const [applications, setApplications] = useState([]);
  const [pendingChecks, setPendingChecks] = useState([]);
  const [selectedApplication, setSelectedApplication] = useState(null);
  const [applicationDetails, setApplicationDetails] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [success, setSuccess] = useState(null);
  const [tabValue, setTabValue] = useState(0);
  const [detailDialogOpen, setDetailDialogOpen] = useState(false);
  const [approveDialogOpen, setApproveDialogOpen] = useState(false);
  const [rejectDialogOpen, setRejectDialogOpen] = useState(false);
  const [approvalNotes, setApprovalNotes] = useState('');
  const [rejectionReason, setRejectionReason] = useState('');

  const dashboardStats = getDashboardStats(applications, pendingChecks);
  const filteredApplications = filterApplicationsByTab(applications, tabValue);
  const detailStatus = applicationDetails
    ? normalizeEnumValue(applicationDetails.application.status)
    : '';

  const loadData = useCallback(async () => {
    setLoading(true);
    try {
      const result = await loadVettingDashboard({ listApplications, getPendingChecks, limit: 50 });
      setApplications(result.applications);
      setPendingChecks(result.pendingChecks);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadData();
  }, [loadData]);

  const handleViewDetails = async (application) => {
    try {
      const result = await loadVettingApplicationDetails({ getApplication, application });
      setSelectedApplication(result.selectedApplication);
      setApplicationDetails(result.applicationDetails);
      setDetailDialogOpen(result.detailDialogOpen);
    } catch (err) {
      setError(err.message);
    }
  };

  const handleApprove = async () => {
    if (!selectedApplication) return;
    setLoading(true);
    try {
      const result = await approveVettingApplication({
        approveApplication,
        applicationId: selectedApplication.id,
        approvalNotes,
      });
      setSuccess(result.successMessage);
      setApproveDialogOpen(result.approveDialogOpen);
      setApprovalNotes(result.approvalNotes);
      if (result.shouldReload) {
        loadData();
      }
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleReject = async () => {
    if (!selectedApplication) return;
    setLoading(true);
    try {
      const result = await rejectVettingApplication({
        rejectApplication,
        applicationId: selectedApplication.id,
        rejectionReason,
      });
      setSuccess(result.successMessage);
      setRejectDialogOpen(result.rejectDialogOpen);
      setRejectionReason(result.rejectionReason);
      if (result.shouldReload) {
        loadData();
      }
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleCompleteCheck = async (checkId, passed) => {
    setLoading(true);
    try {
      const result = await completeVettingDashboardCheck({
        completeCheck,
        getApplication,
        checkId,
        passed,
        applicationDetails,
        selectedApplication,
      });
      setSuccess(result.successMessage);
      if (result.shouldReload) {
        loadData();
      }
      if (result.applicationDetails) {
        setApplicationDetails(result.applicationDetails);
      }
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <Box sx={{ p: 3 }}>
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
        <Typography variant="h4">Vetting Dashboard</Typography>
        <IconButton onClick={loadData} disabled={loading}>
          <RefreshIcon />
        </IconButton>
      </Box>

      <Snackbar open={!!error} autoHideDuration={6000} onClose={() => setError(null)}>
        <Alert severity="error" onClose={() => setError(null)}>{error}</Alert>
      </Snackbar>
      <Snackbar open={!!success} autoHideDuration={3000} onClose={() => setSuccess(null)}>
        <Alert severity="success" onClose={() => setSuccess(null)}>{success}</Alert>
      </Snackbar>

      <Grid container spacing={2} sx={{ mb: 3 }}>
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Typography color="textSecondary" gutterBottom>Pending Review</Typography>
              <Typography variant="h4">{dashboardStats.pendingApprovalCount}</Typography>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Typography color="textSecondary" gutterBottom>Under Review</Typography>
              <Typography variant="h4">{dashboardStats.underReviewCount}</Typography>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Typography color="textSecondary" gutterBottom>Pending Checks</Typography>
              <Typography variant="h4">{dashboardStats.pendingChecksCount}</Typography>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Typography color="textSecondary" gutterBottom>Approved Today</Typography>
              <Typography variant="h4" color="success.main">{dashboardStats.approvedTodayCount}</Typography>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      <Tabs
        value={tabValue}
        onChange={(event, value) => setTabValue(resolveDashboardTabChange(value).tabValue)}
        sx={{ mb: 2 }}
      >
        <Tab label="All Applications" />
        <Tab label="Pending Approval" />
        <Tab label="Pending Checks" />
      </Tabs>

      {loading && <LinearProgress sx={{ mb: 2 }} />}

      <TableContainer component={Paper} data-testid="applications-table">
        <Table>
          <TableHead>
            <TableRow>
              <TableCell>Reference</TableCell>
              <TableCell>Document Type</TableCell>
              <TableCell>Status</TableCell>
              <TableCell>Submitted</TableCell>
              <TableCell>Actions</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {filteredApplications.map((app) => {
              const normalizedStatus = normalizeEnumValue(app.status);
              return (
                <TableRow key={app.id} data-testid={`application-row-${app.id}`}>
                  <TableCell>{app.reference_number}</TableCell>
                  <TableCell>{app.document_type}</TableCell>
                  <TableCell>
                    <Chip
                      label={formatStatusLabel(normalizedStatus)}
                      color={STATUS_COLORS[normalizedStatus] || 'default'}
                      size="small"
                    />
                  </TableCell>
                  <TableCell>{formatDate(app.submitted_at)}</TableCell>
                  <TableCell>
                    <IconButton
                      size="small"
                      onClick={() => handleViewDetails(app)}
                      data-testid="view-application-btn"
                    >
                      <ViewIcon />
                    </IconButton>
                    {normalizedStatus === 'PENDING_APPROVAL' && (
                      <>
                        <IconButton
                          size="small"
                          color="success"
                          onClick={() => {
                            const result = resolveApproveDialogOpen(app);
                            setSelectedApplication(result.selectedApplication);
                            setApproveDialogOpen(result.approveDialogOpen);
                          }}
                          data-testid="approve-application-btn"
                        >
                          <CheckIcon />
                        </IconButton>
                        <IconButton
                          size="small"
                          color="error"
                          onClick={() => {
                            const result = resolveRejectDialogOpen(app);
                            setSelectedApplication(result.selectedApplication);
                            setRejectDialogOpen(result.rejectDialogOpen);
                          }}
                          data-testid="reject-application-btn"
                        >
                          <CancelIcon />
                        </IconButton>
                      </>
                    )}
                  </TableCell>
                </TableRow>
              );
            })}
          </TableBody>
        </Table>
      </TableContainer>

      <Dialog
        open={detailDialogOpen}
        onClose={() => setDetailDialogOpen(resolveDetailDialogClose().detailDialogOpen)}
        maxWidth="md"
        fullWidth
        data-testid="application-detail-view"
      >
        <DialogTitle>Application Details</DialogTitle>
        <DialogContent>
          {applicationDetails && (
            <Box>
              <Grid container spacing={2} sx={{ mb: 3 }}>
                <Grid item xs={6}>
                  <Typography variant="body2" color="textSecondary">Reference</Typography>
                  <Typography>{applicationDetails.application.reference_number}</Typography>
                </Grid>
                <Grid item xs={6}>
                  <Typography variant="body2" color="textSecondary">Status</Typography>
                  <Chip
                    label={formatStatusLabel(detailStatus)}
                    color={STATUS_COLORS[detailStatus] || 'default'}
                    size="small"
                  />
                </Grid>
                <Grid item xs={6}>
                  <Typography variant="body2" color="textSecondary">Applicant</Typography>
                  <Typography>{applicationDetails.applicant?.full_name}</Typography>
                </Grid>
                <Grid item xs={6}>
                  <Typography variant="body2" color="textSecondary">Document Type</Typography>
                  <Typography>{applicationDetails.application.document_type}</Typography>
                </Grid>
              </Grid>

              <Typography variant="h6" gutterBottom>Vetting Checks</Typography>
              <List>
                {applicationDetails.vetting_checks?.map((check) => {
                  const normalizedCheckType = normalizeEnumValue(check.check_type);
                  const normalizedCheckStatus = normalizeCheckStatus(check.status);
                  const IconComponent = CHECK_TYPE_ICONS[normalizedCheckType] || SecurityIcon;
                  return (
                    <ListItem key={check.id} divider>
                      <ListItemIcon>
                        <IconComponent />
                      </ListItemIcon>
                      <ListItemText
                        primary={formatStatusLabel(normalizedCheckType)}
                        secondary={check.notes || ((check.is_required ?? check.is_mandatory) ? 'Required' : 'Optional')}
                      />
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                        <Chip
                          label={formatStatusLabel(normalizedCheckStatus)}
                          color={CHECK_STATUS_COLORS[normalizedCheckStatus]}
                          size="small"
                        />
                        {normalizedCheckStatus === 'PENDING' && (
                          <>
                            <IconButton
                              size="small"
                              color="success"
                              onClick={() => handleCompleteCheck(check.id, true)}
                              data-testid={`check-pass-btn-${check.id}`}
                            >
                              <PassedIcon />
                            </IconButton>
                            <IconButton
                              size="small"
                              color="error"
                              onClick={() => handleCompleteCheck(check.id, false)}
                              data-testid={`check-fail-btn-${check.id}`}
                            >
                              <FailedIcon />
                            </IconButton>
                          </>
                        )}
                      </Box>
                    </ListItem>
                  );
                })}
              </List>
            </Box>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setDetailDialogOpen(resolveDetailDialogClose().detailDialogOpen)}>Close</Button>
        </DialogActions>
      </Dialog>

      <Dialog
        open={approveDialogOpen}
        onClose={() => {
          const result = resolveApproveDialogClose();
          setApproveDialogOpen(result.approveDialogOpen);
          setApprovalNotes(result.approvalNotes);
        }}
        data-testid="approval-dialog"
      >
        <DialogTitle>Approve Application</DialogTitle>
        <DialogContent>
          <Typography sx={{ mb: 2 }}>
            Approve application {selectedApplication?.reference_number}?
          </Typography>
          <TextField
            fullWidth
            multiline
            rows={3}
            label="Notes (optional)"
            value={approvalNotes}
            onChange={(e) => setApprovalNotes(resolveApprovalNotesInput(e.target.value).approvalNotes)}
            data-testid="approval-notes"
          />
        </DialogContent>
        <DialogActions>
          <Button
            onClick={() => {
              const result = resolveApproveDialogClose();
              setApproveDialogOpen(result.approveDialogOpen);
              setApprovalNotes(result.approvalNotes);
            }}
          >
            Cancel
          </Button>
          <Button
            variant="contained"
            color="success"
            onClick={handleApprove}
            disabled={loading}
            data-testid="confirm-approval-btn"
          >
            Approve
          </Button>
        </DialogActions>
      </Dialog>

      <Dialog
        open={rejectDialogOpen}
        onClose={() => {
          const result = resolveRejectDialogClose();
          setRejectDialogOpen(result.rejectDialogOpen);
          setRejectionReason(result.rejectionReason);
        }}
        data-testid="rejection-dialog"
      >
        <DialogTitle>Reject Application</DialogTitle>
        <DialogContent>
          <Typography sx={{ mb: 2 }}>
            Reject application {selectedApplication?.reference_number}?
          </Typography>
          <TextField
            fullWidth
            required
            multiline
            rows={3}
            label="Reason"
            value={rejectionReason}
            onChange={(e) => setRejectionReason(resolveRejectionReasonInput(e.target.value).rejectionReason)}
            data-testid="rejection-reason"
          />
        </DialogContent>
        <DialogActions>
          <Button
            onClick={() => {
              const result = resolveRejectDialogClose();
              setRejectDialogOpen(result.rejectDialogOpen);
              setRejectionReason(result.rejectionReason);
            }}
          >
            Cancel
          </Button>
          <Button
            variant="contained"
            color="error"
            onClick={handleReject}
            disabled={loading || !canRejectApplication(rejectionReason)}
            data-testid="confirm-reject-btn"
          >
            Reject
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
}

export default VettingDashboard;

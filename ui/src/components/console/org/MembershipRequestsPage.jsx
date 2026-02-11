/**
 * Membership Requests Page
 * 
 * Allows organization administrators to review and approve/reject
 * pending membership requests from users who want to join the organization.
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

import { ResourcePage } from '../../common';
import { getPendingRequests, approveMembershipRequest, rejectMembershipRequest } from '../../../services/membershipApi';

const ORG_TABS = [
  { label: 'Organization', path: '/console/org/settings' },
  { label: 'Team', path: '/console/org/team' },
  { label: 'Membership Requests', path: '/console/org/membership-requests' },
  { label: 'Webhooks', path: '/console/org/webhooks' },
];

const BREADCRUMBS = [
  { label: 'Console', path: '/console' },
  { label: 'Org', path: '/console/org' },
  { label: 'Membership Requests', path: '/console/org/membership-requests' },
];

function MembershipRequestsPage() {
  const [requests, setRequests] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [successMessage, setSuccessMessage] = useState(null);
  
  // Dialog state
  const [rejectDialogOpen, setRejectDialogOpen] = useState(false);
  const [selectedRequest, setSelectedRequest] = useState(null);
  const [rejectionReason, setRejectionReason] = useState('');
  const [actionLoading, setActionLoading] = useState(false);

  const loadRequests = async () => {
    try {
      setLoading(true);
      setError(null);
      const data = await getPendingRequests();
      setRequests(data.requests || []);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadRequests();
  }, []);

  const handleApprove = async (request) => {
    try {
      setActionLoading(true);
      setError(null);
      setSuccessMessage(null);
      
      const result = await approveMembershipRequest(request.id);
      setSuccessMessage(result.message || `${request.user_email} has been approved`);
      
      // Refresh the list
      await loadRequests();
    } catch (err) {
      setError(err.message);
    } finally {
      setActionLoading(false);
    }
  };

  const handleRejectClick = (request) => {
    setSelectedRequest(request);
    setRejectionReason('');
    setRejectDialogOpen(true);
  };

  const handleRejectConfirm = async () => {
    if (!selectedRequest) return;

    try {
      setActionLoading(true);
      setError(null);
      setSuccessMessage(null);
      
      const result = await rejectMembershipRequest(
        selectedRequest.id,
        rejectionReason.trim() || null
      );
      setSuccessMessage(result.message || `Request from ${selectedRequest.user_email} has been rejected`);
      
      setRejectDialogOpen(false);
      setSelectedRequest(null);
      setRejectionReason('');
      
      // Refresh the list
      await loadRequests();
    } catch (err) {
      setError(err.message);
    } finally {
      setActionLoading(false);
    }
  };

  const handleRejectCancel = () => {
    setRejectDialogOpen(false);
    setSelectedRequest(null);
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
      title="Membership Requests"
      description="Review and approve membership requests from users wanting to join your organization."
      tabs={ORG_TABS}
      breadcrumbs={BREADCRUMBS}
    >
      <Box sx={{ mb: 3 }}>
        {error && (
          <Alert severity="error" sx={{ mb: 2 }} onClose={() => setError(null)}>
            {error}
          </Alert>
        )}
        
        {successMessage && (
          <Alert severity="success" sx={{ mb: 2 }} onClose={() => setSuccessMessage(null)}>
            {successMessage}
          </Alert>
        )}

        <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
          <Typography variant="h6">
            Pending Requests ({requests.length})
          </Typography>
          <Tooltip title="Refresh">
            <IconButton onClick={loadRequests} disabled={loading}>
              <RefreshIcon />
            </IconButton>
          </Tooltip>
        </Box>

        {loading ? (
          <Box sx={{ display: 'flex', justifyContent: 'center', py: 4 }}>
            <CircularProgress />
          </Box>
        ) : requests.length === 0 ? (
          <Paper sx={{ p: 6, textAlign: 'center', bgcolor: 'grey.50' }}>
            <PersonAddIcon sx={{ fontSize: 60, color: 'text.secondary', mb: 2 }} />
            <Typography variant="h6" gutterBottom>
              No Pending Requests
            </Typography>
            <Typography variant="body2" color="text.secondary">
              When users request to join your organization, they will appear here for review.
            </Typography>
          </Paper>
        ) : (
          <TableContainer component={Paper}>
            <Table>
              <TableHead>
                <TableRow>
                  <TableCell>User Email</TableCell>
                  <TableCell>Message</TableCell>
                  <TableCell>Requested</TableCell>
                  <TableCell>Status</TableCell>
                  <TableCell align="right">Actions</TableCell>
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
                        <Typography variant="body2" color="text.secondary" fontStyle="italic">
                          No message
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
                          Approve
                        </Button>
                        <Button
                          variant="outlined"
                          color="error"
                          size="small"
                          startIcon={<CancelIcon />}
                          onClick={() => handleRejectClick(request)}
                          disabled={actionLoading}
                        >
                          Reject
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
      <Dialog open={rejectDialogOpen} onClose={handleRejectCancel} maxWidth="sm" fullWidth>
        <DialogTitle>Reject Membership Request</DialogTitle>
        <DialogContent>
          <Typography variant="body2" sx={{ mb: 2 }}>
            Are you sure you want to reject the membership request from{' '}
            <strong>{selectedRequest?.user_email}</strong>?
          </Typography>
          <TextField
            label="Reason for rejection (optional)"
            multiline
            rows={3}
            fullWidth
            value={rejectionReason}
            onChange={(e) => setRejectionReason(e.target.value)}
            placeholder="Provide a reason that will be visible to the applicant..."
          />
        </DialogContent>
        <DialogActions>
          <Button onClick={handleRejectCancel} disabled={actionLoading}>
            Cancel
          </Button>
          <Button
            onClick={handleRejectConfirm}
            color="error"
            variant="contained"
            disabled={actionLoading}
          >
            {actionLoading ? <CircularProgress size={20} /> : 'Reject Request'}
          </Button>
        </DialogActions>
      </Dialog>
    </ResourcePage>
  );
}

export default MembershipRequestsPage;

import { useState, useEffect } from 'react';
import {
  Box,
  Paper,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Button,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  TextField,
  Chip,
  Typography,
  IconButton,
  Alert,
} from '@mui/material';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import CancelIcon from '@mui/icons-material/Cancel';
import ResourcePage from '../../common/ResourcePage';
import { getPendingRoleRequests, approveRoleRequest, rejectRoleRequest } from '../../../services/rolesApi';

/**
 * Role Escalation Requests Page
 * 
 * Admin interface for reviewing and approving/rejecting role escalation requests.
 */
export default function RoleEscalationRequestsPage() {
  const [requests, setRequests] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [rejectDialogOpen, setRejectDialogOpen] = useState(false);
  const [selectedRequest, setSelectedRequest] = useState(null);
  const [rejectionReason, setRejectionReason] = useState('');
  const [actionLoading, setActionLoading] = useState(false);

  useEffect(() => {
    loadRequests();
  }, []);

  const loadRequests = async () => {
    try {
      setLoading(true);
      setError(null);
      const response = await getPendingRoleRequests();
      setRequests(response.requests || []);
    } catch (err) {
      console.error('Failed to load role escalation requests:', err);
      setError(err.message || 'Failed to load role escalation requests');
    } finally {
      setLoading(false);
    }
  };

  const handleApprove = async (request) => {
    try {
      setActionLoading(true);
      await approveRoleRequest(request.id);
      await loadRequests(); // Refresh list
    } catch (err) {
      console.error('Failed to approve role request:', err);
      setError(err.message || 'Failed to approve role request');
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
      await rejectRoleRequest(selectedRequest.id, rejectionReason);
      setRejectDialogOpen(false);
      setSelectedRequest(null);
      setRejectionReason('');
      await loadRequests(); // Refresh list
    } catch (err) {
      console.error('Failed to reject role request:', err);
      setError(err.message || 'Failed to reject role request');
    } finally {
      setActionLoading(false);
    }
  };

  const getRoleChipColor = (role) => {
    switch (role) {
      case 'admin':
        return 'error';
      case 'operator':
        return 'warning';
      case 'member':
        return 'primary';
      default:
        return 'default';
    }
  };

  const formatRole = (role) => {
    return role.charAt(0).toUpperCase() + role.slice(1);
  };

  const formatDate = (dateString) => {
    return new Date(dateString).toLocaleString();
  };

  return (
    <ResourcePage
      title="Role Escalation Requests"
      subtitle="Review and manage role change requests from organization members"
    >
      {error && (
        <Alert severity="error" sx={{ mb: 2 }} onClose={() => setError(null)}>
          {error}
        </Alert>
      )}

      <TableContainer component={Paper}>
        <Table>
          <TableHead>
            <TableRow>
              <TableCell>User</TableCell>
              <TableCell>Current Role</TableCell>
              <TableCell>Requested Role</TableCell>
              <TableCell>Message</TableCell>
              <TableCell>Requested At</TableCell>
              <TableCell align="right">Actions</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {loading ? (
              <TableRow>
                <TableCell colSpan={6} align="center">
                  <Typography variant="body2" color="text.secondary">
                    Loading requests...
                  </Typography>
                </TableCell>
              </TableRow>
            ) : requests.length === 0 ? (
              <TableRow>
                <TableCell colSpan={6} align="center">
                  <Typography variant="body2" color="text.secondary">
                    No pending role escalation requests
                  </Typography>
                </TableCell>
              </TableRow>
            ) : (
              requests.map((request) => (
                <TableRow key={request.id}>
                  <TableCell>
                    <Box>
                      <Typography variant="body2" fontWeight="medium">
                        {request.user_email}
                      </Typography>
                      <Typography variant="caption" color="text.secondary">
                        ID: {request.user_id}
                      </Typography>
                    </Box>
                  </TableCell>
                  <TableCell>
                    <Chip
                      label={formatRole(request.current_role)}
                      color={getRoleChipColor(request.current_role)}
                      size="small"
                    />
                  </TableCell>
                  <TableCell>
                    <Chip
                      label={formatRole(request.requested_role)}
                      color={getRoleChipColor(request.requested_role)}
                      size="small"
                      variant="outlined"
                    />
                  </TableCell>
                  <TableCell>
                    <Typography
                      variant="body2"
                      sx={{
                        maxWidth: 300,
                        overflow: 'hidden',
                        textOverflow: 'ellipsis',
                        whiteSpace: 'nowrap',
                      }}
                    >
                      {request.message || '—'}
                    </Typography>
                  </TableCell>
                  <TableCell>
                    <Typography variant="body2" color="text.secondary">
                      {formatDate(request.created_at)}
                    </Typography>
                  </TableCell>
                  <TableCell align="right">
                    <Box sx={{ display: 'flex', gap: 1, justifyContent: 'flex-end' }}>
                      <IconButton
                        color="success"
                        size="small"
                        onClick={() => handleApprove(request)}
                        disabled={actionLoading}
                        title="Approve request"
                      >
                        <CheckCircleIcon />
                      </IconButton>
                      <IconButton
                        color="error"
                        size="small"
                        onClick={() => handleRejectClick(request)}
                        disabled={actionLoading}
                        title="Reject request"
                      >
                        <CancelIcon />
                      </IconButton>
                    </Box>
                  </TableCell>
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
      </TableContainer>

      {/* Reject Dialog */}
      <Dialog
        open={rejectDialogOpen}
        onClose={() => !actionLoading && setRejectDialogOpen(false)}
        maxWidth="sm"
        fullWidth
      >
        <DialogTitle>Reject Role Request</DialogTitle>
        <DialogContent>
          <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
            You are rejecting the role escalation request from{' '}
            <strong>{selectedRequest?.user_email}</strong> to become{' '}
            <strong>{selectedRequest ? formatRole(selectedRequest.requested_role) : ''}</strong>.
          </Typography>
          <TextField
            label="Rejection Reason (Optional)"
            multiline
            rows={3}
            fullWidth
            value={rejectionReason}
            onChange={(e) => setRejectionReason(e.target.value)}
            placeholder="Provide a reason for rejecting this request..."
          />
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setRejectDialogOpen(false)} disabled={actionLoading}>
            Cancel
          </Button>
          <Button
            onClick={handleRejectConfirm}
            variant="contained"
            color="error"
            disabled={actionLoading}
          >
            {actionLoading ? 'Rejecting...' : 'Reject Request'}
          </Button>
        </DialogActions>
      </Dialog>
    </ResourcePage>
  );
}

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
import { useTranslation } from 'react-i18next';
import ResourcePage from '../../common/ResourcePage';
import { useDialog } from '../../../hooks/useDialog';
import { getPendingRoleRequests, approveRoleRequest, rejectRoleRequest } from '../../../services/rolesApi';

/**
 * Role Escalation Requests Page
 * 
 * Admin interface for reviewing and approving/rejecting role escalation requests.
 */
export default function RoleEscalationRequestsPage() {
  const { t } = useTranslation('console');
  const [requests, setRequests] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const rejectDialog = useDialog();
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

  const handleRejectConfirm = async () => {
    try {
      setActionLoading(true);
      await rejectRoleRequest(rejectDialog.data.id, rejectionReason);
      rejectDialog.close();
      setRejectionReason('');
      await loadRequests();
    } catch (err) {
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
      title={t('org.roleEscalation.title')}
      subtitle={t('org.roleEscalation.subtitle')}
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
              <TableCell>{t('org.roleEscalation.tableHeaders.user')}</TableCell>
              <TableCell>{t('org.roleEscalation.tableHeaders.currentRole')}</TableCell>
              <TableCell>{t('org.roleEscalation.tableHeaders.requestedRole')}</TableCell>
              <TableCell>{t('org.roleEscalation.tableHeaders.message')}</TableCell>
              <TableCell>{t('org.roleEscalation.tableHeaders.requestedAt')}</TableCell>
              <TableCell align="right">{t('org.roleEscalation.tableHeaders.actions')}</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {loading ? (
              <TableRow>
                <TableCell colSpan={6} align="center">
                  <Typography variant="body2" color="text.secondary">
                    {t('org.roleEscalation.loading')}
                  </Typography>
                </TableCell>
              </TableRow>
            ) : requests.length === 0 ? (
              <TableRow>
                <TableCell colSpan={6} align="center">
                  <Typography variant="body2" color="text.secondary">
                    {t('org.roleEscalation.empty')}
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
                        {t('org.roleEscalation.userId', { id: request.user_id })}
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
                        title={t('org.roleEscalation.actions.approve')}
                      >
                        <CheckCircleIcon />
                      </IconButton>
                      <IconButton
                        color="error"
                        size="small"
                        onClick={() => { setRejectionReason(''); rejectDialog.open(request); }}
                        disabled={actionLoading}
                        title={t('org.roleEscalation.actions.reject')}
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
        open={rejectDialog.isOpen}
        onClose={() => !actionLoading && rejectDialog.close()}
        maxWidth="sm"
        fullWidth
      >
        <DialogTitle>{t('org.roleEscalation.dialog.title')}</DialogTitle>
        <DialogContent>
          <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
            {t('org.roleEscalation.dialog.message')}{' '}
            <strong>{rejectDialog.data?.user_email}</strong> {t('org.roleEscalation.dialog.messageToBecome')}{' '}
            <strong>{rejectDialog.data ? formatRole(rejectDialog.data.requested_role) : ''}</strong>.
          </Typography>
          <TextField
            label={t('org.roleEscalation.dialog.reasonLabel')}
            multiline
            rows={3}
            fullWidth
            value={rejectionReason}
            onChange={(e) => setRejectionReason(e.target.value)}
            placeholder={t('org.roleEscalation.dialog.reasonPlaceholder')}
          />
        </DialogContent>
        <DialogActions>
          <Button onClick={rejectDialog.close} disabled={actionLoading}>
            {t('actions.cancel', { ns: 'common' })}
          </Button>
          <Button
            onClick={handleRejectConfirm}
            variant="contained"
            color="error"
            disabled={actionLoading}
          >
            {actionLoading ? t('org.roleEscalation.dialog.rejecting') : t('org.roleEscalation.dialog.reject')}
          </Button>
        </DialogActions>
      </Dialog>
    </ResourcePage>
  );
}

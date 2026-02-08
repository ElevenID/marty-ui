/**
 * My Applications Page
 * 
 * View and track credential applications.
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
  Alert,
  LinearProgress,
  Button,
  Stepper,
  Step,
  StepLabel,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
} from '@mui/material';

const APPLICATION_STEPS = ['Submitted', 'Under Review', 'Verification', 'Approved'];

function MyApplicationsPage() {
  const [applications, setApplications] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [selectedApp, setSelectedApp] = useState(null);

  useEffect(() => {
    // TODO: Fetch from API
    const loadApplications = async () => {
      try {
        await new Promise((resolve) => setTimeout(resolve, 500));
        setApplications([
          {
            id: 'app-1',
            credentialType: 'Professional Certification',
            submittedAt: '2026-02-01T10:00:00Z',
            status: 'under_review',
            step: 1,
            estimatedCompletion: '2026-02-10',
          },
          {
            id: 'app-2',
            credentialType: 'Driver License',
            submittedAt: '2025-12-01T10:00:00Z',
            status: 'approved',
            step: 3,
            completedAt: '2025-12-15T10:00:00Z',
          },
        ]);
      } catch (err) {
        setError('Failed to load applications');
      } finally {
        setLoading(false);
      }
    };
    loadApplications();
  }, []);

  const getStatusColor = (status) => {
    switch (status) {
      case 'approved':
        return 'success';
      case 'rejected':
        return 'error';
      case 'under_review':
        return 'warning';
      case 'submitted':
        return 'info';
      default:
        return 'default';
    }
  };

  const getStatusLabel = (status) => {
    switch (status) {
      case 'under_review':
        return 'Under Review';
      case 'approved':
        return 'Approved';
      case 'rejected':
        return 'Rejected';
      case 'submitted':
        return 'Submitted';
      default:
        return status;
    }
  };

  return (
    <Box>
      <Typography variant="h4" gutterBottom>
        My Applications
      </Typography>
      <Typography variant="body1" color="text.secondary" paragraph>
        Track the status of your credential applications.
      </Typography>

      {error && (
        <Alert severity="error" sx={{ mb: 3 }}>
          {error}
        </Alert>
      )}

      {loading ? (
        <LinearProgress />
      ) : (
        <TableContainer component={Paper}>
          <Table>
            <TableHead>
              <TableRow>
                <TableCell>Credential Type</TableCell>
                <TableCell>Submitted</TableCell>
                <TableCell>Progress</TableCell>
                <TableCell>Status</TableCell>
                <TableCell align="right">Actions</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {applications.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={5} align="center">
                    <Typography color="text.secondary" sx={{ py: 4 }}>
                      No applications yet.
                    </Typography>
                    <Button variant="contained" href="/credentials">
                      Apply for a Credential
                    </Button>
                  </TableCell>
                </TableRow>
              ) : (
                applications.map((app) => (
                  <TableRow key={app.id} hover>
                    <TableCell>
                      <Typography fontWeight={500}>{app.credentialType}</Typography>
                    </TableCell>
                    <TableCell>
                      {new Date(app.submittedAt).toLocaleDateString()}
                    </TableCell>
                    <TableCell sx={{ minWidth: 300 }}>
                      <Stepper activeStep={app.step} alternativeLabel size="small">
                        {APPLICATION_STEPS.map((label) => (
                          <Step key={label}>
                            <StepLabel>{label}</StepLabel>
                          </Step>
                        ))}
                      </Stepper>
                    </TableCell>
                    <TableCell>
                      <Chip
                        label={getStatusLabel(app.status)}
                        color={getStatusColor(app.status)}
                        size="small"
                      />
                    </TableCell>
                    <TableCell align="right">
                      <Button size="small" onClick={() => setSelectedApp(app)}>
                        View Details
                      </Button>
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </TableContainer>
      )}

      {/* Application Details Dialog */}
      <Dialog
        open={!!selectedApp}
        onClose={() => setSelectedApp(null)}
        maxWidth="sm"
        fullWidth
      >
        <DialogTitle>Application Details</DialogTitle>
        <DialogContent>
          {selectedApp && (
            <Box sx={{ pt: 1 }}>
              <Typography variant="subtitle2" color="text.secondary">
                Credential Type
              </Typography>
              <Typography paragraph>{selectedApp.credentialType}</Typography>

              <Typography variant="subtitle2" color="text.secondary">
                Submitted
              </Typography>
              <Typography paragraph>
                {new Date(selectedApp.submittedAt).toLocaleString()}
              </Typography>

              <Typography variant="subtitle2" color="text.secondary">
                Status
              </Typography>
              <Chip
                label={getStatusLabel(selectedApp.status)}
                color={getStatusColor(selectedApp.status)}
                size="small"
              />

              {selectedApp.estimatedCompletion && (
                <>
                  <Typography variant="subtitle2" color="text.secondary" sx={{ mt: 2 }}>
                    Estimated Completion
                  </Typography>
                  <Typography>{selectedApp.estimatedCompletion}</Typography>
                </>
              )}
            </Box>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setSelectedApp(null)}>Close</Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
}

export default MyApplicationsPage;

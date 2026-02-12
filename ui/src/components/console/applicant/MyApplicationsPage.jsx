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
import { useTranslation } from 'react-i18next';

import { getMyApplications } from '../../../services/applicantApi';

function MyApplicationsPage() {
  const { t } = useTranslation('applicant');
  
  const APPLICATION_STEPS = [
    t('applications.steps.submitted'),
    t('applications.steps.underReview'),
    t('applications.steps.verification'),
    t('applications.steps.approved'),
  ];
  const [applications, setApplications] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [selectedApp, setSelectedApp] = useState(null);

  useEffect(() => {
    const loadApplications = async () => {
      try {
        const result = await getMyApplications({ limit: 100 });
        const apps = (result.applications || []).map(app => {
          // Map status to step number for progress visualization
          let step = 0;
          const status = app.status?.toLowerCase();
          if (status === 'submitted') step = 0;
          else if (status === 'under_review' || status === 'vetting_in_progress') step = 1;
          else if (status === 'pending_approval') step = 2;
          else if (status === 'approved') step = 3;
          
          return {
            id: app.id,
            reference: app.reference_number,
            credentialType: app.credential_display_name || app.credential_type || app.document_type,
            submittedAt: app.submitted_at,
            status: status || 'submitted',
            step,
            completedAt: app.approved_at || app.issued_at,
          };
        });
        setApplications(apps);
      } catch (err) {
        console.error('Error loading applications:', err);
        setError(t('applications.errorLoading'));
      } finally {
        setLoading(false);
      }
    };
    loadApplications();
  }, [t]);

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
        return t('applications.status.underReview');
      case 'approved':
        return t('applications.status.approved');
      case 'rejected':
        return t('applications.status.rejected');
      case 'submitted':
        return t('applications.status.submitted');
      default:
        return status;
    }
  };

  return (
    <Box>
      <Typography variant="h4" gutterBottom>
        {t('applications.title')}
      </Typography>
      <Typography variant="body1" color="text.secondary" paragraph>
        {t('applications.description')}
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
                <TableCell>{t('applications.tableHeaders.credentialType')}</TableCell>
                <TableCell>{t('applications.tableHeaders.submitted')}</TableCell>
                <TableCell>{t('applications.tableHeaders.progress')}</TableCell>
                <TableCell>{t('applications.tableHeaders.status')}</TableCell>
                <TableCell align="right">{t('applications.tableHeaders.actions')}</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {applications.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={5} align="center">
                    <Typography color="text.secondary" sx={{ py: 4 }}>
                      {t('applications.empty.message')}
                    </Typography>
                    <Button variant="contained" href="/credentials">
                      {t('applications.empty.applyButton')}
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
                        {t('applications.actions.viewDetails')}
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
        <DialogTitle>{t('applications.detailsDialog.title')}</DialogTitle>
        <DialogContent>
          {selectedApp && (
            <Box sx={{ pt: 1 }}>
              <Typography variant="subtitle2" color="text.secondary">
                {t('applications.detailsDialog.credentialType')}
              </Typography>
              <Typography paragraph>{selectedApp.credentialType}</Typography>

              <Typography variant="subtitle2" color="text.secondary">
                {t('applications.detailsDialog.submitted')}
              </Typography>
              <Typography paragraph>
                {new Date(selectedApp.submittedAt).toLocaleString()}
              </Typography>

              <Typography variant="subtitle2" color="text.secondary">
                {t('applications.detailsDialog.status')}
              </Typography>
              <Chip
                label={getStatusLabel(selectedApp.status)}
                color={getStatusColor(selectedApp.status)}
                size="small"
              />

              {selectedApp.estimatedCompletion && (
                <>
                  <Typography variant="subtitle2" color="text.secondary" sx={{ mt: 2 }}>
                    {t('applications.detailsDialog.estimatedCompletion')}
                  </Typography>
                  <Typography>{selectedApp.estimatedCompletion}</Typography>
                </>
              )}
            </Box>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setSelectedApp(null)}>{t('applications.detailsDialog.close')}</Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
}

export default MyApplicationsPage;

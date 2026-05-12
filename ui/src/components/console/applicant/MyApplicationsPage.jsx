/**
 * My Applications Page
 * 
 * View and track credential applications.
 */

import { useState, useEffect, useRef } from 'react';
import { useSearchParams } from 'react-router-dom';
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
import { generateIssuanceOffer } from '../../../services/credentialsApi';
import ClaimCredentialDialog from './ClaimCredentialDialog';

const TERMINAL_STATUSES = new Set(['credentialed', 'issued', 'rejected']);

function getStepFromStatus(status) {
  switch (status) {
    case 'submitted':
      return 0;
    case 'under_review':
    case 'vetting_in_progress':
      return 1;
    case 'pending_approval':
    case 'needs_info':
      return 2;
    case 'approved':
    case 'offered':
      return 3;
    case 'credentialed':
    case 'issued':
      return 4;
    case 'rejected':
      return 4;
    default:
      return 0;
  }
}

function MyApplicationsPage() {
  const { t } = useTranslation('applicant');
  
  const APPLICATION_STEPS = [
    t('applications.steps.submitted'),
    t('applications.steps.underReview'),
    t('applications.steps.verification'),
    t('applications.steps.approved'),
    t('applications.steps.credentialReady', 'Credential Ready'),
  ];
  const [searchParams] = useSearchParams();
  const highlightId = searchParams.get('id');
  const highlightHandled = useRef(false);

  const [applications, setApplications] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [selectedApp, setSelectedApp] = useState(null);
  const [claimApp, setClaimApp] = useState(null);
  const [reissuingId, setReissuingId] = useState(null);
  const [reissueError, setReissueError] = useState(null);

  const handleReclaim = async (app) => {
    setReissuingId(app.id);
    setReissueError(null);
    try {
      const offerData = await generateIssuanceOffer(app.id);
      setClaimApp({
        ...app,
        offerUrl: offerData.offer_url || null,
        offerUris: offerData.credential_offer_uris || {},
        offerLabels: offerData.credential_offer_labels || {},
        offerExpiresAt: offerData.expires_at || null,
      });
    } catch (err) {
      setReissueError(err.message || t('applications.reissue.error', 'Failed to request re-issuance. Please contact your issuer.'));
    } finally {
      setReissuingId(null);
    }
  };

  useEffect(() => {
    const loadApplications = async (showLoading = true) => {
      try {
        if (showLoading) setLoading(true);
        const result = await getMyApplications({ limit: 100 });
        const apps = (result.applications || []).map(app => {
          const status = app.status?.toLowerCase();
          const step = getStepFromStatus(status);
          
          return {
            id: app.id,
            reference: app.reference_number,
            credentialType: app.credential_display_name || app.credential_type || app.document_type,
            submittedAt: app.submitted_at,
            status: status || 'submitted',
            step,
            completedAt: app.issued_at || app.approved_at,
            // Preserve offer data so ClaimCredentialDialog can use it directly
            offerUrl: app.credential_offer_uri || null,
            offerUris: app.credential_offer_uris || {},
            offerLabels: app.credential_offer_labels || {},
            offerExpiresAt: app.offer_expires_at || null,
          };
        });
        setApplications(apps);
      } catch (err) {
        console.error('Error loading applications:', err);
        setError(t('applications.errorLoading'));
      } finally {
        if (showLoading) setLoading(false);
      }
    };

    loadApplications(true);

    // Keep statuses in sync with org review decisions
    const interval = setInterval(() => {
      loadApplications(false);
    }, 15000);

    const onFocus = () => loadApplications(false);
    window.addEventListener('focus', onFocus);

    return () => {
      clearInterval(interval);
      window.removeEventListener('focus', onFocus);
    };
  }, [t]);

  // Auto-open detail dialog when arriving from the application form (?id=...)
  useEffect(() => {
    if (highlightId && applications.length > 0 && !highlightHandled.current) {
      const match = applications.find(a => a.id === highlightId);
      if (match) {
        highlightHandled.current = true;
        setSelectedApp(match);
      }
    }
  }, [highlightId, applications]);

  const getStatusColor = (status) => {
    switch (status) {
      case 'approved':
        return 'success';
      case 'offered':
        return 'primary';
      case 'credentialed':
      case 'issued':
        return 'primary';
      case 'rejected':
        return 'error';
      case 'under_review':
      case 'vetting_in_progress':
      case 'pending_approval':
      case 'needs_info':
        return 'warning';
      case 'submitted':
        return 'info';
      default:
        return 'default';
    }
  };

  const getStatusLabel = (status) => {
    switch (status) {
      case 'draft':
        return t('applications.status.draft', 'Draft');
      case 'submitted':
        return t('applications.status.submitted');
      case 'under_review':
      case 'vetting_in_progress':
        return t('applications.status.underReview');
      case 'pending_approval':
      case 'needs_info':
        return t('applications.status.pendingApproval', 'Pending Approval');
      case 'approved':
        return t('applications.status.approved');
      case 'offered':
        return t('applications.status.walletInviteReady', 'Wallet Invite Ready');
      case 'credentialed':
        return t('applications.status.credentialIssued', 'Credential Issued');
      case 'issued':
        return t('applications.status.credentialIssued', 'Credential Issued');
      case 'rejected':
        return t('applications.status.rejected');
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

      {reissueError && (
        <Alert severity="error" sx={{ mb: 3 }} onClose={() => setReissueError(null)}>
          {reissueError}
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
                    <Button variant="contained" href="/console/applicant/catalog">
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
                            <StepLabel error={app.status === 'rejected' && TERMINAL_STATUSES.has(app.status)}>{label}</StepLabel>
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
                      <Button size="small" onClick={() => setSelectedApp(app)} sx={{ mr: 1 }}>
                        {t('applications.actions.viewDetails')}
                      </Button>
                      {(app.status === 'approved' || app.status === 'offered') && (
                        <Button
                          size="small"
                          variant="contained"
                          color="primary"
                          onClick={() => setClaimApp(app)}
                        >
                          {t('applications.actions.addToWallet', 'Add to Wallet')}
                        </Button>
                      )}
                      {(app.status === 'credentialed' || app.status === 'issued') && (
                        <Button
                          size="small"
                          variant="outlined"
                          color="secondary"
                          disabled={reissuingId === app.id}
                          onClick={() => handleReclaim(app)}
                        >
                          {reissuingId === app.id
                            ? t('applications.actions.requesting', 'Requesting…')
                            : t('applications.actions.reclaim', 'Reclaim')}
                        </Button>
                      )}
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </TableContainer>
      )}

      <ClaimCredentialDialog
        open={!!claimApp}
        onClose={() => setClaimApp(null)}
        applicationId={claimApp?.id}
        offerData={claimApp ? {
          offer_url: claimApp.offerUrl,
          credential_offer_uris: claimApp.offerUris,
          credential_offer_labels: claimApp.offerLabels,
          expires_at: claimApp.offerExpiresAt,
        } : undefined}
      />

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

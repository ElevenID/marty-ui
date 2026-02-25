/**
 * ApplicationReviewPage
 *
 * Full-screen decision workspace for reviewing a credential application.
 * Opened when clicking a row in ApplicationsPage.
 *
 * Layout (top → bottom):
 *   A. Sticky header  — identity, status, primary actions
 *   B. Decision summary panel — verification / compliance / policy signals
 *   C. Applicant claims section
 *   D. Verification evidence (vetting checks)
 *   E. Reviewer notes panel
 *   F. Bottom sticky decision bar
 *
 * Decision flows (Approve / Reject / Request Info) open confirmation dialogs.
 */

import { useState, useEffect, useCallback, useRef } from 'react';
import { useParams, useNavigate, Link } from 'react-router-dom';
import {
  Box,
  AppBar,
  Toolbar,
  Typography,
  Button,
  IconButton,
  Chip,
  Tooltip,
  Alert,
  LinearProgress,
  Paper,
  Grid,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  Divider,
  TextField,
  Stack,
  CircularProgress,
} from '@mui/material';
import ArrowBackIcon from '@mui/icons-material/ArrowBack';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import CancelIcon from '@mui/icons-material/Cancel';
import HelpOutlineIcon from '@mui/icons-material/HelpOutline';
import LockIcon from '@mui/icons-material/Lock';
import LockOpenIcon from '@mui/icons-material/LockOpen';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import PersonIcon from '@mui/icons-material/Person';
import BadgeIcon from '@mui/icons-material/Badge';
import AssignmentIcon from '@mui/icons-material/Assignment';
import VerifiedIcon from '@mui/icons-material/Verified';
import NoteAddIcon from '@mui/icons-material/NoteAdd';
import RefreshIcon from '@mui/icons-material/Refresh';

import { useAuth } from '../../../hooks/useAuth';
import { StatusChip } from '../../common';
import IssuingSection from './IssuingSection';
import {
  getApplication,
  getVettingChecks,
  reviewOrganizationApplication,
  requestApplicationInfo,
  acquireReviewerLock,
  releaseReviewerLock,
} from '../../../services/applicantApi';
import {
  CHECK_TYPE_ICONS,
  CHECK_TYPE_LABELS,
  CHECK_STATUS_COLORS,
  CHECK_STATUS_LABELS,
} from '../../../config/checkConstants';

import ApproveDialog from './dialogs/ApproveDialog';
import RejectDialog from './dialogs/RejectDialog';
import RequestInfoDialog from './dialogs/RequestInfoDialog';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function fmt(dateStr) {
  if (!dateStr) return '—';
  try {
    return new Date(dateStr).toLocaleString(undefined, {
      dateStyle: 'medium',
      timeStyle: 'short',
    });
  } catch {
    return dateStr;
  }
}

function VerificationSignal({ label, value, color }) {
  const colorMap = { success: 'success.main', warning: 'warning.main', error: 'error.main', default: 'text.secondary' };
  return (
    <Box sx={{ textAlign: 'center', px: 2 }}>
      <Typography variant="caption" color="text.secondary" display="block" gutterBottom>
        {label}
      </Typography>
      <Typography variant="h6" fontWeight="bold" color={colorMap[color] || 'text.primary'}>
        {value}
      </Typography>
    </Box>
  );
}

function SectionCard({ title, icon, children }) {
  return (
    <Paper variant="outlined" sx={{ mb: 3 }}>
      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, px: 2.5, py: 1.5, borderBottom: '1px solid', borderColor: 'divider' }}>
        {icon}
        <Typography variant="subtitle1" fontWeight="medium">{title}</Typography>
      </Box>
      <Box sx={{ p: 2.5 }}>{children}</Box>
    </Paper>
  );
}

function ClaimField({ label, value, source }) {
  const sourceColor = source === 'verified' ? 'success' : source === 'manual' ? 'default' : 'info';
  return (
    <Box sx={{ mb: 2 }}>
      <Typography variant="caption" color="text.secondary" display="block">{label}</Typography>
      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mt: 0.25 }}>
        <Typography variant="body2" fontWeight="medium">{value || '—'}</Typography>
        {source && (
          <Chip label={source} size="small" color={sourceColor} variant="outlined" sx={{ fontSize: '0.65rem', height: 18 }} />
        )}
      </Box>
    </Box>
  );
}

function CheckRow({ check }) {
  const Icon = CHECK_TYPE_ICONS[check.check_type] || BadgeIcon;
  const statusColor = CHECK_STATUS_COLORS[check.status] || 'default';
  const statusLabel = CHECK_STATUS_LABELS[check.status] || check.status;
  const typeLabel = check.custom_name || CHECK_TYPE_LABELS[check.check_type] || check.check_type;

  return (
    <Accordion disableGutters elevation={0} sx={{ border: '1px solid', borderColor: 'divider', mb: 1, borderRadius: 1, '&:before': { display: 'none' } }}>
      <AccordionSummary expandIcon={<ExpandMoreIcon />} sx={{ minHeight: 48 }}>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5, width: '100%' }}>
          <Icon fontSize="small" color="action" />
          <Typography variant="body2" sx={{ flexGrow: 1 }}>{typeLabel}</Typography>
          {check.is_required && (
            <Chip label="Required" size="small" variant="outlined" sx={{ fontSize: '0.65rem', height: 18, mr: 1 }} />
          )}
          <Chip label={statusLabel} size="small" color={statusColor} />
        </Box>
      </AccordionSummary>
      <AccordionDetails sx={{ bgcolor: 'action.hover', pt: 1 }}>
        {check.external_provider && (
          <Typography variant="caption" color="text.secondary">Provider: {check.external_provider}</Typography>
        )}
        {check.notes && <Typography variant="body2" sx={{ mt: 0.5 }}>Notes: {check.notes}</Typography>}
        {check.performed_by && <Typography variant="caption" color="text.secondary" display="block">Performed by: {check.performed_by}</Typography>}
        {check.started_at && <Typography variant="caption" color="text.secondary" display="block">Started: {fmt(check.started_at)}</Typography>}
        {check.completed_at && <Typography variant="caption" color="text.secondary" display="block">Completed: {fmt(check.completed_at)}</Typography>}
        {check.result && Object.keys(check.result).length > 0 && (
          <Box sx={{ mt: 1 }}>
            <Typography variant="caption" color="text.secondary">Result data:</Typography>
            <Box component="pre" sx={{ fontSize: '0.7rem', overflow: 'auto', mt: 0.5, p: 1, bgcolor: 'background.paper', borderRadius: 1 }}>
              {JSON.stringify(check.result, null, 2)}
            </Box>
          </Box>
        )}
      </AccordionDetails>
    </Accordion>
  );
}

// ---------------------------------------------------------------------------
// Derive summary signal from checks and status
// ---------------------------------------------------------------------------

function deriveSignals(application, checks) {
  // Verification signal from checks
  let verificationColor = 'default';
  let verificationValue = 'No Checks';
  if (checks.length > 0) {
    const failed = checks.filter(c => ['failed', 'completed_failed'].includes(c.status));
    const passed = checks.filter(c => ['passed', 'completed_passed'].includes(c.status));
    const pending = checks.filter(c => ['not_started', 'pending', 'in_progress'].includes(c.status));
    if (failed.length > 0) { verificationColor = 'error'; verificationValue = `${failed.length} Failed`; }
    else if (pending.length > 0) { verificationColor = 'warning'; verificationValue = `${pending.length} Pending`; }
    else if (passed.length > 0) { verificationColor = 'success'; verificationValue = 'All Passed'; }
  }

  // Policy outcome based on application status
  let policyColor = 'default';
  let policyValue = 'Unknown';
  const s = application?.status;
  if (s === 'approved' || s === 'issued') { policyColor = 'success'; policyValue = 'Eligible'; }
  else if (s === 'rejected') { policyColor = 'error'; policyValue = 'Blocked'; }
  else if (s === 'needs_info') { policyColor = 'warning'; policyValue = 'Info Required'; }
  else if (s === 'submitted' || s === 'under_review') { policyColor = 'warning'; policyValue = 'Pending Review'; }

  return { verificationColor, verificationValue, policyColor, policyValue };
}

// ---------------------------------------------------------------------------
// Main Component
// ---------------------------------------------------------------------------

export default function ApplicationReviewPage() {
  const { applicationId } = useParams();
  const navigate = useNavigate();
  const { user } = useAuth();

  const [application, setApplication] = useState(null);
  const [checks, setChecks] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [actionLoading, setActionLoading] = useState(false);
  const [actionError, setActionError] = useState(null);
  const [actionSuccess, setActionSuccess] = useState(null);

  // Reviewer lock
  const [lock, setLock] = useState(null); // { locked, reviewer_name, reviewer_id }
  const lockIntervalRef = useRef(null);

  // Notes
  const [reviewerNote, setReviewerNote] = useState('');

  // Dialog state
  const [approveOpen, setApproveOpen] = useState(false);
  const [rejectOpen, setRejectOpen] = useState(false);
  const [requestInfoOpen, setRequestInfoOpen] = useState(false);

  const reviewerId = user?.user_id || user?.sub || 'unknown';
  const reviewerName = user?.name || user?.email || 'Reviewer';

  // ---------------------------------------------------------------------------
  // Data loading
  // ---------------------------------------------------------------------------

  const loadData = useCallback(async () => {
    if (!applicationId) return;
    setLoading(true);
    setError(null);
    try {
      const [app, checkList] = await Promise.all([
        getApplication(applicationId),
        getVettingChecks(applicationId).catch(() => []),
      ]);
      setApplication(app);
      setChecks(Array.isArray(checkList) ? checkList : []);
      if (app.metadata?.review_notes) setReviewerNote(app.metadata.review_notes);
    } catch (err) {
      setError(err.message || 'Failed to load application');
    } finally {
      setLoading(false);
    }
  }, [applicationId]);

  useEffect(() => { loadData(); }, [loadData]);

  // ---------------------------------------------------------------------------
  // Reviewer lock — acquire on mount, release on unmount, refresh every 90s
  // ---------------------------------------------------------------------------

  useEffect(() => {
    if (!applicationId || !reviewerId) return;

    const acquire = async () => {
      try {
        const result = await acquireReviewerLock(applicationId, reviewerId, reviewerName);
        setLock(result);
      } catch {
        // Non-critical; don't block the review
      }
    };

    acquire();
    lockIntervalRef.current = setInterval(acquire, 90_000);

    const handleUnload = () => releaseReviewerLock(applicationId, reviewerId);
    window.addEventListener('beforeunload', handleUnload);

    return () => {
      clearInterval(lockIntervalRef.current);
      window.removeEventListener('beforeunload', handleUnload);
      releaseReviewerLock(applicationId, reviewerId).catch(() => {});
    };
  }, [applicationId, reviewerId, reviewerName]);

  // ---------------------------------------------------------------------------
  // Decision handlers
  // ---------------------------------------------------------------------------

  const handleApprove = async ({ notes }) => {
    setActionLoading(true);
    setActionError(null);
    try {
      await reviewOrganizationApplication(applicationId, 'approve', { notes: notes || reviewerNote || undefined });
      setActionSuccess('Application approved. Click "Generate Wallet Invite" to send the credential to the applicant.');
      await loadData();
      setApproveOpen(false);
    } catch (err) {
      setActionError(err.message || 'Failed to approve application');
    } finally {
      setActionLoading(false);
    }
  };

  const handleReject = async ({ reason, notes, notifyApplicant: _notifyApplicant }) => {
    setActionLoading(true);
    setActionError(null);
    try {
      await reviewOrganizationApplication(applicationId, 'reject', { reason, notes: notes || undefined });
      setActionSuccess('Application rejected.');
      await loadData();
      setRejectOpen(false);
    } catch (err) {
      setActionError(err.message || 'Failed to reject application');
    } finally {
      setActionLoading(false);
    }
  };

  const handleRequestInfo = async ({ missingItems, message, deadline }) => {
    setActionLoading(true);
    setActionError(null);
    try {
      await requestApplicationInfo(applicationId, {
        missing_items: missingItems,
        message,
        deadline: deadline || null,
      });
      setActionSuccess('Info request sent to applicant.');
      await loadData();
      setRequestInfoOpen(false);
    } catch (err) {
      setActionError(err.message || 'Failed to request info');
    } finally {
      setActionLoading(false);
    }
  };

  // ---------------------------------------------------------------------------
  // Derived state
  // ---------------------------------------------------------------------------

  const isTerminal = ['issued', 'rejected'].includes(application?.status);
  const canAct = !isTerminal && !actionLoading;
  const isLocked = lock && !lock.locked && lock.reviewer_id !== reviewerId;

  const signals = deriveSignals(application, checks);

  const allChecksPass =
    checks.length > 0 &&
    checks.every(c => ['passed', 'completed_passed', 'waived', 'skipped'].includes(c.status));

  // Build applicant claims from metadata + applicant fields
  const claims = application
    ? [
        { label: 'Given Name', value: application.applicant_given_name, source: 'manual' },
        { label: 'Family Name', value: application.applicant_family_name, source: 'manual' },
        { label: 'Email', value: application.applicant_email, source: 'manual' },
        { label: 'Phone', value: application.applicant_phone, source: 'manual' },
        // Spread any extra metadata fields (excluding internal keys)
        ...Object.entries(application.metadata || {})
          .filter(([k]) => !['credential_display_name', 'review_notes', 'rejection_reason', 'issuance_transaction_id', 'credential_offer_uri', 'issuance_fallback', 'info_requests'].includes(k))
          .map(([k, v]) => ({ label: k.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase()), value: String(v), source: 'manual' })),
      ]
    : [];

  // ---------------------------------------------------------------------------
  // Render
  // ---------------------------------------------------------------------------

  if (loading) {
    return (
      <Box sx={{ p: 4 }}>
        <LinearProgress />
        <Typography variant="body2" color="text.secondary" sx={{ mt: 2 }}>
          Loading application…
        </Typography>
      </Box>
    );
  }

  if (error || !application) {
    return (
      <Box sx={{ p: 4 }}>
        <Alert severity="error">{error || 'Application not found.'}</Alert>
        <Button startIcon={<ArrowBackIcon />} sx={{ mt: 2 }} onClick={() => navigate(-1)}>
          Back to Applications
        </Button>
      </Box>
    );
  }

  const applicantDisplay = [application.applicant_given_name, application.applicant_family_name]
    .filter(Boolean)
    .join(' ') || application.applicant_email || application.applicant_id;

  const credentialDisplay = application.credential_display_name || application.credential_configuration_id;

  return (
    <Box sx={{ display: 'flex', flexDirection: 'column', minHeight: '100vh', bgcolor: 'background.default' }}>

      {/* ── A. STICKY HEADER ── */}
      <AppBar position="sticky" color="default" elevation={1} sx={{ zIndex: 1100 }}>
        <Toolbar sx={{ gap: 1, flexWrap: 'wrap' }}>
          <Tooltip title="Back to Applications">
            <IconButton component={Link} to="/console/org/operate/applications" edge="start" size="small">
              <ArrowBackIcon />
            </IconButton>
          </Tooltip>

          <Box sx={{ flexGrow: 1, minWidth: 0 }}>
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, flexWrap: 'wrap' }}>
              <Typography variant="subtitle1" fontWeight="bold" noWrap>
                {applicantDisplay}
              </Typography>
              <Typography variant="body2" color="text.secondary" noWrap>
                — {credentialDisplay}
              </Typography>
              <StatusChip status={application.status} showIcon />
            </Box>
            <Typography variant="caption" color="text.secondary">
              {application.reference_number && `Ref: ${application.reference_number} · `}
              Submitted {application.submitted_at ? fmt(application.submitted_at) : 'Not yet submitted'}
            </Typography>
          </Box>

          {/* Lock indicator */}
          {isLocked ? (
            <Chip
              icon={<LockIcon fontSize="small" />}
              label={`Being reviewed by ${lock.reviewer_name}`}
              size="small"
              color="warning"
              variant="outlined"
            />
          ) : (
            lock?.locked && (
              <Chip
                icon={<LockOpenIcon fontSize="small" />}
                label="You have this open"
                size="small"
                color="success"
                variant="outlined"
              />
            )
          )}

          {/* Primary actions */}
          {!isTerminal && (
            <Stack direction="row" spacing={1}>
              <Button
                variant="outlined"
                size="small"
                startIcon={<HelpOutlineIcon />}
                onClick={() => setRequestInfoOpen(true)}
                disabled={!canAct || isLocked}
              >
                Request Info
              </Button>
              <Button
                variant="outlined"
                size="small"
                color="error"
                startIcon={<CancelIcon />}
                onClick={() => setRejectOpen(true)}
                disabled={!canAct || isLocked}
              >
                Reject
              </Button>
              <Button
                variant="contained"
                size="small"
                color="success"
                startIcon={allChecksPass ? <VerifiedIcon /> : <CheckCircleIcon />}
                onClick={() => setApproveOpen(true)}
                disabled={!canAct || isLocked}
                sx={allChecksPass ? { animation: 'pulse 1.5s ease-in-out 3' } : {}}
              >
                Approve
              </Button>
            </Stack>
          )}

          <Tooltip title="Refresh">
            <IconButton size="small" onClick={loadData} disabled={loading}>
              <RefreshIcon fontSize="small" />
            </IconButton>
          </Tooltip>
        </Toolbar>

        {actionLoading && <LinearProgress color="primary" sx={{ height: 2 }} />}
      </AppBar>

      {/* ── Page Body ── */}
      <Box sx={{ flex: 1, p: { xs: 2, md: 3 }, maxWidth: 1100, mx: 'auto', width: '100%' }}>

        {/* Feedback alerts */}
        {actionSuccess && (
          <Alert severity="success" onClose={() => setActionSuccess(null)} sx={{ mb: 2 }}>
            {actionSuccess}
          </Alert>
        )}
        {actionError && (
          <Alert severity="error" onClose={() => setActionError(null)} sx={{ mb: 2 }}>
            {actionError}
          </Alert>
        )}

        {/* Already-issued state */}
        {application.status === 'issued' && (
          <Alert severity="success" sx={{ mb: 2 }}>
            Credential issued on {fmt(application.issued_at)}.
            {application.metadata?.credential_offer_uri && (
              <> &nbsp;<a href={application.metadata.credential_offer_uri} target="_blank" rel="noreferrer">View credential offer</a></>
            )}
          </Alert>
        )}

        {/* Approved – credential issuance section */}
        <IssuingSection applicationId={applicationId} applicationStatus={application.status} />

        {/* Needs-info state */}
        {application.status === 'needs_info' && (
          <Alert severity="info" sx={{ mb: 2 }}>
            Awaiting additional information from the applicant.
            {application.metadata?.info_requests?.length > 0 && (
              <> Last request sent {fmt(application.metadata.info_requests.at(-1).requested_at)}.</>
            )}
          </Alert>
        )}

        {/* ── B. DECISION SUMMARY PANEL ── */}
        <SectionCard title="Decision Summary" icon={<AssignmentIcon color="action" />}>
          <Grid container spacing={2} alignItems="center">
            <Grid item xs={12} md={6}>
              <Typography variant="body2" color="text.secondary" gutterBottom>Credential</Typography>
              <Typography variant="h6" fontWeight="bold">{credentialDisplay}</Typography>
              {application.metadata?.issuer && (
                <Typography variant="caption" color="text.secondary">Issuer: {application.metadata.issuer}</Typography>
              )}
            </Grid>
            <Grid item xs={12} md={6}>
              <Box sx={{ display: 'flex', justifyContent: { xs: 'flex-start', md: 'flex-end' }, gap: 2, flexWrap: 'wrap' }}>
                <VerificationSignal
                  label="Verification"
                  value={signals.verificationValue}
                  color={signals.verificationColor}
                />
                <Divider orientation="vertical" flexItem />
                <VerificationSignal
                  label="Policy Outcome"
                  value={signals.policyValue}
                  color={signals.policyColor}
                />
              </Box>
            </Grid>
          </Grid>
        </SectionCard>

        {/* ── C. APPLICANT CLAIMS ── */}
        <SectionCard title="Applicant Claims" icon={<PersonIcon color="action" />}>
          {claims.length === 0 ? (
            <Typography variant="body2" color="text.secondary">No claim data available.</Typography>
          ) : (
            <Grid container spacing={0}>
              {claims.map((claim, i) => (
                <Grid item xs={12} sm={6} md={4} key={i}>
                  <ClaimField label={claim.label} value={claim.value} source={claim.source} />
                </Grid>
              ))}
            </Grid>
          )}
        </SectionCard>

        {/* ── D. VERIFICATION EVIDENCE (VETTING CHECKS) ── */}
        <SectionCard title="Verification Evidence" icon={<VerifiedIcon color="action" />}>
          {checks.length === 0 ? (
            <Alert severity="info" variant="outlined">
              No vetting checks defined for this application.
              Checks are created automatically from the application template&apos;s required checks.
            </Alert>
          ) : (
            checks.map(check => <CheckRow key={check.id} check={check} />)
          )}
        </SectionCard>

        {/* ── E. REVIEWER NOTES ── */}
        <SectionCard title="Reviewer Notes" icon={<NoteAddIcon color="action" />}>
          <TextField
            label="Add a note (optional)"
            multiline
            rows={3}
            fullWidth
            value={reviewerNote}
            onChange={e => setReviewerNote(e.target.value)}
            disabled={isTerminal}
            size="small"
            placeholder="Record your observations, caveats, or reasons for the decision…"
          />
          {/* Previous system notes */}
          {application.metadata?.rejection_reason && (
            <Box sx={{ mt: 2, p: 1.5, bgcolor: 'error.50', borderRadius: 1, border: '1px solid', borderColor: 'error.light' }}>
              <Typography variant="caption" color="error.main" fontWeight="medium">Rejection reason:</Typography>
              <Typography variant="body2">{application.metadata.rejection_reason}</Typography>
            </Box>
          )}
          {application.metadata?.info_requests?.map((req, i) => (
            <Box key={i} sx={{ mt: 2, p: 1.5, bgcolor: 'info.50', borderRadius: 1, border: '1px solid', borderColor: 'info.light' }}>
              <Typography variant="caption" color="info.main" fontWeight="medium">
                Info request — {fmt(req.requested_at)}
              </Typography>
              {req.missing_items?.length > 0 && (
                <Typography variant="body2">Missing: {req.missing_items.join(', ')}</Typography>
              )}
              {req.message && <Typography variant="body2">{req.message}</Typography>}
            </Box>
          ))}
        </SectionCard>

        {/* ── APPLICATION METADATA (for developers / audit) ── */}
        <Accordion disableGutters elevation={0} sx={{ border: '1px solid', borderColor: 'divider', borderRadius: 1, mb: 3 }}>
          <AccordionSummary expandIcon={<ExpandMoreIcon />}>
            <Typography variant="body2" color="text.secondary">Technical Details</Typography>
          </AccordionSummary>
          <AccordionDetails>
            <Grid container spacing={2}>
              <Grid item xs={6} md={3}>
                <ClaimField label="Application ID" value={application.id} />
              </Grid>
              <Grid item xs={6} md={3}>
                <ClaimField label="Applicant ID" value={application.applicant_id} />
              </Grid>
              <Grid item xs={6} md={3}>
                <ClaimField label="Credential Config ID" value={application.credential_configuration_id} />
              </Grid>
              <Grid item xs={6} md={3}>
                <ClaimField label="Vetting Level" value={application.applicant_vetting_level} />
              </Grid>
              <Grid item xs={6} md={3}>
                <ClaimField label="Created" value={fmt(application.created_at)} />
              </Grid>
              <Grid item xs={6} md={3}>
                <ClaimField label="Reviewed" value={fmt(application.reviewed_at)} />
              </Grid>
              <Grid item xs={6} md={3}>
                <ClaimField label="Issued" value={fmt(application.issued_at)} />
              </Grid>
              {application.metadata?.issuance_transaction_id && (
                <Grid item xs={6} md={3}>
                  <ClaimField label="Issuance Transaction" value={application.metadata.issuance_transaction_id} />
                </Grid>
              )}
            </Grid>
          </AccordionDetails>
        </Accordion>

        {/* Bottom spacer so bottom bar doesn't obscure content */}
        <Box sx={{ height: 80 }} />
      </Box>

      {/* ── F. BOTTOM STICKY DECISION BAR ── */}
      {!isTerminal && (
        <AppBar position="sticky" color="default" elevation={3} sx={{ top: 'auto', bottom: 0 }}>
          <Toolbar sx={{ justifyContent: 'center', gap: 2 }}>
            <Button
              variant="outlined"
              size="large"
              startIcon={<HelpOutlineIcon />}
              onClick={() => setRequestInfoOpen(true)}
              disabled={!canAct || isLocked}
            >
              Request More Info
            </Button>
            <Button
              variant="outlined"
              size="large"
              color="error"
              startIcon={<CancelIcon />}
              onClick={() => setRejectOpen(true)}
              disabled={!canAct || isLocked}
            >
              Reject Application
            </Button>
            <Button
              variant="contained"
              size="large"
              color="success"
              startIcon={actionLoading ? <CircularProgress size={18} color="inherit" /> : <CheckCircleIcon />}
              onClick={() => setApproveOpen(true)}
              disabled={!canAct || isLocked}
            >
              Approve Application
            </Button>
          </Toolbar>
        </AppBar>
      )}

      {/* ── DECISION DIALOGS ── */}
      <ApproveDialog
        open={approveOpen}
        application={application}
        checks={checks}
        initialNote={reviewerNote}
        loading={actionLoading}
        onConfirm={handleApprove}
        onClose={() => setApproveOpen(false)}
      />
      <RejectDialog
        open={rejectOpen}
        application={application}
        loading={actionLoading}
        onConfirm={handleReject}
        onClose={() => setRejectOpen(false)}
      />
      <RequestInfoDialog
        open={requestInfoOpen}
        application={application}
        checks={checks}
        loading={actionLoading}
        onConfirm={handleRequestInfo}
        onClose={() => setRequestInfoOpen(false)}
      />
    </Box>
  );
}

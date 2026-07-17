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
import HelpOutlineIcon from '@mui/icons-material/HelpOutlined';
import LockIcon from '@mui/icons-material/Lock';
import LockOpenIcon from '@mui/icons-material/LockOpen';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import PersonIcon from '@mui/icons-material/Person';
import BadgeIcon from '@mui/icons-material/Badge';
import AssignmentIcon from '@mui/icons-material/Assignment';
import VerifiedIcon from '@mui/icons-material/Verified';
import NoteAddIcon from '@mui/icons-material/NoteAdd';
import RefreshIcon from '@mui/icons-material/Refresh';
import PolicyIcon from '@mui/icons-material/Policy';

import { useAuth } from '../../../hooks/useAuth';
import { useConsole } from '../../../contexts/ConsoleContext';
import { StatusChip } from '../../common';
import IssuingSection from './IssuingSection';
import {
  getOrganizationApplication,
  getApplicationEvidenceSummary,
  getVettingChecks,
  runApplicationExternalEvidenceApiCheck,
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
import { formatOfficialReference, pickOfficialReference } from '../../../utils/officialReferences';

import { listCredentialTemplates } from '../../../services/presentationPolicyApi';
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

function compactObjectEntries(value) {
  if (!value || typeof value !== 'object') return [];
  return Object.entries(value).filter(([, item]) => item !== null && item !== undefined && item !== '');
}

function EvidenceFactRow({ fact }) {
  const scopeEntries = compactObjectEntries(fact.scope);
  const verificationStatus = fact.verification?.status || 'unknown';
  const verificationColor = String(verificationStatus).toLowerCase() === 'verified' ? 'success' : 'default';

  return (
    <Accordion disableGutters elevation={0} sx={{ border: '1px solid', borderColor: 'divider', mb: 1, borderRadius: 1, '&:before': { display: 'none' } }}>
      <AccordionSummary expandIcon={<ExpandMoreIcon />} sx={{ minHeight: 48 }}>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5, width: '100%', minWidth: 0 }}>
          <VerifiedIcon fontSize="small" color="action" />
          <Typography variant="body2" sx={{ flexGrow: 1, minWidth: 0, overflowWrap: 'anywhere' }}>
            {fact.fact_type}
          </Typography>
          <Chip label={fact.provider || 'provider'} size="small" variant="outlined" />
          <Chip label={verificationStatus} size="small" color={verificationColor} />
        </Box>
      </AccordionSummary>
      <AccordionDetails sx={{ bgcolor: 'action.hover', pt: 1 }}>
        <Grid container spacing={2}>
          <Grid item xs={12} sm={6} md={3}>
            <ClaimField label="Subject" value={fact.subject_id} />
          </Grid>
          <Grid item xs={12} sm={6} md={3}>
            <ClaimField label="Created" value={fmt(fact.created_at)} />
          </Grid>
          <Grid item xs={12} sm={6} md={3}>
            <ClaimField label="Source Event" value={fact.source?.provider_event_id || fact.source?.event_id} />
          </Grid>
          <Grid item xs={12} sm={6} md={3}>
            <ClaimField label="Verification Method" value={fact.verification?.method} />
          </Grid>
        </Grid>
        {scopeEntries.length > 0 && (
          <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.75, mt: 1 }}>
            {scopeEntries.map(([key, value]) => (
              <Chip
                key={key}
                label={`${key}: ${value}`}
                size="small"
                variant="outlined"
                sx={{ maxWidth: '100%', '& .MuiChip-label': { overflowWrap: 'anywhere', whiteSpace: 'normal' } }}
              />
            ))}
          </Box>
        )}
        <Box component="pre" sx={{ fontSize: '0.7rem', overflow: 'auto', mt: 1, p: 1, bgcolor: 'background.paper', borderRadius: 1 }}>
          {JSON.stringify({ assertion: fact.assertion, verification: fact.verification, source: fact.source }, null, 2)}
        </Box>
      </AccordionDetails>
    </Accordion>
  );
}

function EvidencePolicySection({ summary, onRunCheck, runningCheckId, disabled }) {
  const facts = Array.isArray(summary?.evidence_facts) ? summary.evidence_facts : [];
  const availableChecks = Array.isArray(summary?.available_api_checks) ? summary.available_api_checks : [];
  const policy = summary?.policy_decision;
  const allowed = policy?.allowed;
  const decisionLabel = allowed === true ? 'Permit' : allowed === false ? 'Deny' : 'No Decision';
  const decisionColor = allowed === true ? 'success' : allowed === false ? 'warning' : 'default';

  return (
    <SectionCard title="Evidence & Policy" icon={<PolicyIcon color="action" />}>
      <Stack direction="row" spacing={1} useFlexGap flexWrap="wrap" sx={{ mb: facts.length || availableChecks.length ? 2 : 0 }}>
        <Chip label={`Policy: ${decisionLabel}`} color={decisionColor} size="small" />
        {summary?.policy_source && <Chip label={`Source: ${summary.policy_source}`} size="small" variant="outlined" />}
        {summary?.policy_set_id && <Chip label={`Policy Set: ${summary.policy_set_id}`} size="small" variant="outlined" />}
        {summary?.issuance_transaction_id && (
          <Chip label={`Issuance: ${summary.issuance_transaction_id}`} size="small" variant="outlined" />
        )}
        {summary?.canvas?.canvas_platform_id && (
          <Chip label={`Canvas platform: ${summary.canvas.canvas_platform_id}`} size="small" variant="outlined" />
        )}
      </Stack>
      {Array.isArray(policy?.errors) && policy.errors.length > 0 && (
        <Alert severity="warning" variant="outlined" sx={{ mb: 2 }}>
          {policy.errors.join('; ')}
        </Alert>
      )}
      {availableChecks.length > 0 && (
        <Stack direction="row" spacing={1} useFlexGap flexWrap="wrap" sx={{ mb: 2 }}>
          {availableChecks.map(check => {
            const isRunning = runningCheckId === check.check_id;
            return (
              <Button
                key={check.check_id}
                size="small"
                variant="outlined"
                startIcon={isRunning ? <CircularProgress size={14} /> : <RefreshIcon />}
                onClick={() => onRunCheck?.(check.check_id)}
                disabled={disabled || isRunning}
                sx={{ textTransform: 'none', maxWidth: '100%', whiteSpace: 'normal', textAlign: 'left' }}
              >
                {isRunning ? 'Running' : `Run ${check.description || check.check_id}`}
              </Button>
            );
          })}
        </Stack>
      )}
      {availableChecks.length > 0 && (
        <Stack direction="row" spacing={1} useFlexGap flexWrap="wrap" sx={{ mb: 2 }}>
          {availableChecks.map(check => (
            <Chip
              key={`${check.check_id}-meta`}
              size="small"
              variant="outlined"
              label={`${check.provider || 'external_api'}${check.fact_type ? `: ${check.fact_type}` : ''}${check.auto_issue_on_permit ? ' | auto-issue' : ''}`}
              sx={{ maxWidth: '100%', '& .MuiChip-label': { overflowWrap: 'anywhere', whiteSpace: 'normal' } }}
            />
          ))}
        </Stack>
      )}
      {facts.map(fact => <EvidenceFactRow key={fact.id} fact={fact} />)}
    </SectionCard>
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
  if (['approved', 'offered', 'credentialed', 'issued'].includes(s)) { policyColor = 'success'; policyValue = 'Eligible'; }
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
  const { activeOrgId: organizationId } = useConsole();

  const [application, setApplication] = useState(null);
  const [checks, setChecks] = useState([]);
  const [evidenceSummary, setEvidenceSummary] = useState(null);
  const [credentialTemplate, setCredentialTemplate] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [sideLoadErrors, setSideLoadErrors] = useState([]);
  const [actionLoading, setActionLoading] = useState(false);
  const [actionError, setActionError] = useState(null);
  const [actionSuccess, setActionSuccess] = useState(null);
  const [runningEvidenceCheckId, setRunningEvidenceCheckId] = useState(null);

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
    if (!applicationId || !organizationId) {
      setLoading(false);
      setError('Select an organization before reviewing applications.');
      return;
    }
    setLoading(true);
    setError(null);
    setSideLoadErrors([]);
    try {
      const [app, checkResult, evidenceResult] = await Promise.all([
        getOrganizationApplication(organizationId, applicationId),
        getVettingChecks(organizationId, applicationId).then(
          (value) => ({ status: 'fulfilled', value }),
          (reason) => ({ status: 'rejected', reason }),
        ),
        getApplicationEvidenceSummary(organizationId, applicationId).then(
          (value) => ({ status: 'fulfilled', value }),
          (reason) => ({ status: 'rejected', reason }),
        ),
      ]);
      const nextSideLoadErrors = [];
      if (checkResult.status === 'rejected') {
        nextSideLoadErrors.push(`Vetting checks: ${checkResult.reason?.message || String(checkResult.reason)}`);
      }
      if (evidenceResult.status === 'rejected') {
        nextSideLoadErrors.push(`Evidence policy: ${evidenceResult.reason?.message || String(evidenceResult.reason)}`);
      }
      setApplication({ ...app, status: app.status?.toLowerCase() });
      setChecks(checkResult.status === 'fulfilled' && Array.isArray(checkResult.value) ? checkResult.value : []);
      setEvidenceSummary(evidenceResult.status === 'fulfilled' ? evidenceResult.value : null);
      setSideLoadErrors(nextSideLoadErrors);
      if (app.metadata?.review_notes) setReviewerNote(app.metadata.review_notes);

      // Fetch the credential template to drive the claims display dynamically
      if (app.organization_id && app.credential_template_id) {
        try {
          const templates = await listCredentialTemplates({ organization_id: app.organization_id });
          const matched = Array.isArray(templates)
            ? templates.find(t => t.id === app.credential_template_id)
            : null;
          setCredentialTemplate(matched || null);
        } catch {
          // Non-critical — fall back to metadata-based display
          setCredentialTemplate(null);
        }
      }
    } catch (err) {
      setEvidenceSummary(null);
      setError(err.message || 'Failed to load application');
    } finally {
      setLoading(false);
    }
  }, [applicationId, organizationId]);

  useEffect(() => { loadData(); }, [loadData]);

  // ---------------------------------------------------------------------------
  // Reviewer lock — acquire on mount, release on unmount, refresh every 90s
  // ---------------------------------------------------------------------------

  useEffect(() => {
    if (!applicationId || !organizationId || !reviewerId) return;

    const acquire = async () => {
      try {
        const result = await acquireReviewerLock(organizationId, applicationId);
        setLock(result);
      } catch {
        // Non-critical; don't block the review
      }
    };

    acquire();
    lockIntervalRef.current = setInterval(acquire, 90_000);

    const handleUnload = () => { releaseReviewerLock(organizationId, applicationId).catch(() => {}); };
    window.addEventListener('beforeunload', handleUnload);

    return () => {
      clearInterval(lockIntervalRef.current);
      window.removeEventListener('beforeunload', handleUnload);
      releaseReviewerLock(organizationId, applicationId).catch(() => {});
    };
  }, [applicationId, organizationId, reviewerId]);

  // ---------------------------------------------------------------------------
  // Decision handlers
  // ---------------------------------------------------------------------------

  const handleApprove = async ({ notes }) => {
    setActionLoading(true);
    setActionError(null);
    try {
      await reviewOrganizationApplication(organizationId, applicationId, 'approve', { notes: notes || reviewerNote || undefined });
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
      await reviewOrganizationApplication(organizationId, applicationId, 'reject', { reason, notes: notes || undefined });
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
      await requestApplicationInfo(organizationId, applicationId, {
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

  const handleRunEvidenceCheck = async (checkId) => {
    setActionLoading(true);
    setRunningEvidenceCheckId(checkId);
    setActionError(null);
    setActionSuccess(null);
    try {
      const result = await runApplicationExternalEvidenceApiCheck(organizationId, applicationId, checkId, {
        issue_on_permit: true,
      });
      const allowed = result?.policy_decision?.allowed;
      setActionSuccess(
        allowed === true
          ? 'Evidence check completed and policy permitted approval.'
          : 'Evidence check completed and policy metadata was recorded.',
      );
      await loadData();
    } catch (err) {
      setActionError(err.message || 'Failed to run evidence check');
    } finally {
      setRunningEvidenceCheckId(null);
      setActionLoading(false);
    }
  };

  // ---------------------------------------------------------------------------
  // Derived state
  // ---------------------------------------------------------------------------

  const reviewableStatuses = ['submitted', 'under_review', 'vetting_in_progress', 'pending_approval', 'needs_info'];
  const isTerminal = ['credentialed', 'issued', 'rejected'].includes(application?.status);
  const canReview = reviewableStatuses.includes(application?.status);
  const canAct = canReview && !actionLoading;
  const isLocked = lock && !lock.locked && lock.reviewer_id !== reviewerId;

  const signals = deriveSignals(application, checks);
  const policyDecision = evidenceSummary?.policy_decision;
  const policySignal = policyDecision
    ? {
        value: policyDecision.allowed === true ? 'Permitted' : policyDecision.allowed === false ? 'Denied' : 'Unknown',
        color: policyDecision.allowed === true ? 'success' : policyDecision.allowed === false ? 'warning' : 'default',
      }
    : { value: signals.policyValue, color: signals.policyColor };
  const hasEvidencePolicy =
    Boolean(policyDecision) ||
    Boolean(evidenceSummary?.canvas) ||
    ((evidenceSummary?.available_api_checks || []).length > 0) ||
    ((evidenceSummary?.evidence_facts || []).length > 0);

  const allChecksPass =
    checks.length > 0 &&
    checks.every(c => ['passed', 'completed_passed', 'waived', 'skipped'].includes(c.status));

  // Build applicant claims — driven by the credential template definition when available,
  // falling back to metadata keys + standard applicant fields otherwise.
  const _INTERNAL_CLAIM_KEYS = [
    'credential_display_name', 'review_notes', 'rejection_reason',
    'issuance_transaction_id', 'credential_offer_uri', 'credential_offer_uris',
    'issuance_fallback', 'info_requests', 'credential_type', 'offer_expires_at',
  ];

  const claims = application
    ? (() => {
        const meta = application.metadata || {};

        if (credentialTemplate?.claims?.length > 0) {
          // Template-driven: use display_name labels, look up values from metadata
          // then fall back to top-level applicant_* fields.
          return credentialTemplate.claims.map(c => {
            const value =
              meta[c.name] !== undefined
                ? meta[c.name]
                : application[c.name] !== undefined
                  ? application[c.name]
                  : application[`applicant_${c.name}`] !== undefined
                    ? application[`applicant_${c.name}`]
                    : null;
            return {
              label: c.display_name || c.name.replace(/_/g, ' ').replace(/\b\w/g, ch => ch.toUpperCase()),
              value: value !== null && value !== undefined && typeof value !== 'object' ? String(value) : null,
              source: 'manual',
            };
          });
        }

        // Fallback: standard applicant fields + non-internal metadata entries
        return [
          { label: 'Given Name', value: application.applicant_given_name, source: 'manual' },
          { label: 'Family Name', value: application.applicant_family_name, source: 'manual' },
          { label: 'Email', value: application.applicant_email, source: 'manual' },
          { label: 'Phone', value: application.applicant_phone, source: 'manual' },
          ...Object.entries(meta)
            .filter(([k]) => !_INTERNAL_CLAIM_KEYS.includes(k))
            .filter(([, v]) => v !== null && v !== undefined && typeof v !== 'object')
            .map(([k, v]) => ({ label: k.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase()), value: String(v), source: 'manual' })),
        ];
      })()
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

  const credentialDisplay = application.credential_display_name || application.credential_template_id;

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
          {canReview && (
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
        {sideLoadErrors.length > 0 && (
          <Alert severity="warning" sx={{ mb: 2 }}>
            Some review signals could not be loaded. Retry before treating this review as fully evaluated.
            <Box component="ul" sx={{ mt: 1, mb: 0, pl: 3 }}>
              {sideLoadErrors.map((item) => (
                <li key={item}>{item}</li>
              ))}
            </Box>
          </Alert>
        )}

        {/* Already-issued state */}
        {['credentialed', 'issued'].includes(application.status) && (
          <Alert severity="success" sx={{ mb: 2 }}>
            Credential issued on {fmt(application.issued_at)}.
            {application.metadata?.credential_offer_uri && (
              <> &nbsp;<a href={application.metadata.credential_offer_uri} target="_blank" rel="noreferrer">View credential offer</a></>
            )}
          </Alert>
        )}

        {application.status === 'offered' && (
          <Alert severity="info" sx={{ mb: 2 }}>
            Wallet invite generated. The application will move to issued after the wallet completes credential issuance.
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
                  value={policySignal.value}
                  color={policySignal.color}
                />
              </Box>
            </Grid>
          </Grid>
        </SectionCard>

        {/* ── C. CREDENTIAL CLAIMS ── */}
        {hasEvidencePolicy && (
          <EvidencePolicySection
            summary={evidenceSummary}
            onRunCheck={handleRunEvidenceCheck}
            runningCheckId={runningEvidenceCheckId}
            disabled={actionLoading || isLocked || isTerminal}
          />
        )}

        <SectionCard title="Credential Claims" icon={<PersonIcon color="action" />}>
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
                <ClaimField
                  label="Application Reference"
                  value={pickOfficialReference({
                    reference: application.reference_number,
                    rawId: application.id,
                    kind: 'application',
                  })}
                />
              </Grid>
              <Grid item xs={6} md={3}>
                <ClaimField label="Applicant Reference" value={formatOfficialReference(application.applicant_id, 'applicant')} />
              </Grid>
              <Grid item xs={6} md={3}>
                <ClaimField label="Credential Template Reference" value={formatOfficialReference(application.credential_template_id, 'template')} />
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
                  <ClaimField label="Issuance Transaction Reference" value={formatOfficialReference(application.metadata.issuance_transaction_id, 'record')} />
                </Grid>
              )}
            </Grid>
          </AccordionDetails>
        </Accordion>

        {/* Bottom spacer so bottom bar doesn't obscure content */}
        <Box sx={{ height: 80 }} />
      </Box>

      {/* ── F. BOTTOM STICKY DECISION BAR ── */}
      {canReview && (
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

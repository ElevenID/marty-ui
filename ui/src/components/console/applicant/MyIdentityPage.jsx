/**
 * My Identity Page
 *
 * Unified view combining credentials and applications into a single
 * status-aware dashboard. Replaces the separate MyCredentialsPage and
 * MyApplicationsPage with one holistic identity view.
 *
 * Design principles:
 *  - Show WHERE the user is, WHAT'S NEXT, and IF ACTION IS REQUIRED at a glance
 *  - Step-based progress (1–5 stages) with inline messaging
 *  - Group by status section (Action Required / In Progress / Completed)
 *  - Last-updated relative time
 *  - Action buttons tied to status
 */

import { useState, useEffect, useRef, useMemo, useCallback } from 'react';
import { useSearchParams } from 'react-router-dom';
import {
  Box,
  Avatar,
  Paper,
  Typography,
  Chip,
  IconButton,
  Tooltip,
  Alert,
  LinearProgress,
  Button,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  ToggleButtonGroup,
  ToggleButton,
  Stack,
  Card,
  CardContent,
  useMediaQuery,
  useTheme,
  Divider,
} from '@mui/material';
import { useTranslation } from 'react-i18next';
import VisibilityIcon from '@mui/icons-material/Visibility';
import DownloadIcon from '@mui/icons-material/Download';
import QrCodeIcon from '@mui/icons-material/QrCode';
import AddIcon from '@mui/icons-material/Add';
import CheckIcon from '@mui/icons-material/Check';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import CloseIcon from '@mui/icons-material/Close';
import FiberManualRecordIcon from '@mui/icons-material/FiberManualRecord';
import MoveToInboxIcon from '@mui/icons-material/MoveToInbox';
import WarningAmberIcon from '@mui/icons-material/WarningAmber';
import SchoolIcon from '@mui/icons-material/School';
import SyncAltIcon from '@mui/icons-material/SyncAlt';
import WorkspacePremiumIcon from '@mui/icons-material/WorkspacePremium';

import { getMyCredentials, getMyApplications } from '../../../services/applicantApi';
import ClaimCredentialDialog from './ClaimCredentialDialog';

// ---------------------------------------------------------------------------
// Pipeline stages (1-indexed for display, 0-indexed internally)
// ---------------------------------------------------------------------------

const STAGES = [
  { key: 'submitted',    label: 'Submitted' },
  { key: 'review',       label: 'Review' },
  { key: 'approved',     label: 'Approved' },
  { key: 'claim',        label: 'Claim' },
  { key: 'issued',       label: 'Issued' },
];

const TERMINAL_STATUSES = new Set(['issued', 'credentialed', 'rejected']);
const ACTION_STATUSES = new Set(['approved', 'needs_info']);

/** Map raw status → pipeline step index (0-based). */
function getStepIndex(status) {
  switch (status) {
    case 'draft':
    case 'submitted':               return 0;
    case 'under_review':
    case 'vetting_in_progress':     return 1;
    case 'pending_approval':        return 2;
    case 'approved':                return 3;
    case 'offered':                 return 3;
    case 'needs_info':              return 1;
    case 'credentialed':
    case 'issued':                  return 4;
    case 'rejected':                return -1; // special
    default:                        return 0;
  }
}

/** Status → inline explanation message. */
function getStatusMessage(status) {
  switch (status) {
    case 'draft':                   return 'Draft — not yet submitted';
    case 'submitted':               return 'Waiting for issuer review';
    case 'under_review':
    case 'vetting_in_progress':     return 'Under review by issuer';
    case 'pending_approval':        return 'Awaiting final approval';
    case 'needs_info':              return 'Additional information required';
    case 'approved':                return 'Ready for you to claim';
    case 'offered':                 return 'Wallet invite ready';
    case 'credentialed':
    case 'issued':                  return 'Credential issued';
    case 'rejected':                return 'Application was not approved';
    default:                        return '';
  }
}

/** Status → whether user needs to take action. */
function isActionRequired(row) {
  if (row.kind === 'credential' && row.status === 'expired') return true;
  if (row.kind === 'application' && ACTION_STATUSES.has(row.status)) return true;
  return false;
}

/** Status → primary action label. */
function getActionLabel(row) {
  if (row.kind === 'credential') {
    if (row.status === 'expired') return 'Renew';
    return 'Present';
  }
  switch (row.status) {
    case 'approved':
    case 'offered':      return 'Claim';
    case 'credentialed':
    case 'issued':       return 'Receive Again';
    case 'needs_info':   return 'Continue';
    default:             return null;
  }
}

/** Relative time string. */
function timeAgo(dateStr) {
  if (!dateStr) return '';
  const now = Date.now();
  const then = new Date(dateStr).getTime();
  const diffMs = now - then;
  if (diffMs < 0) return 'just now';
  const mins = Math.floor(diffMs / 60000);
  if (mins < 1) return 'just now';
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  if (days < 30) return `${days}d ago`;
  return new Date(dateStr).toLocaleDateString();
}

// ---------------------------------------------------------------------------
// Normalise API data → unified row
// ---------------------------------------------------------------------------

function normaliseCredential(doc) {
  const imageUrl = credentialImageFromData(doc, doc.metadata || {});
  return {
    id: doc.id,
    kind: 'credential',
    type: doc.credential_display_name || doc.name || doc.document_type || doc.credential_type || 'Credential',
    credentialConfigId: doc.credential_configuration_id || doc.credential_template_id || doc.credential_type,
    issuer: doc.issuing_authority || doc.issuer || 'Issuer',
    issuerDid: doc.issuer_did || doc.issuerDid || null,
    date: doc.issued_at || doc.created_at,
    updatedAt: doc.updated_at || doc.issued_at || doc.created_at,
    expiresAt: doc.expiry_date || doc.valid_until,
    status: doc.status?.toLowerCase() || 'active',
    step: null,
    deliveries: Array.isArray(doc.deliveries) ? doc.deliveries : [],
    canvasContext: doc.canvas_context || doc.metadata?.canvas || null,
    subjectClaimsHash: doc.subject_claims_hash || null,
    imageUrl,
  };
}

function normaliseApplication(app) {
  const status = app.status?.toLowerCase() || 'submitted';
  const integrationContext = app.integration_context || app.integrationContext || {};
  const formData = app.form_data || app.formData || {};
  const imageUrl = credentialImageFromData(formData, integrationContext);
  return {
    id: app.id,
    kind: 'application',
    organizationId: app.organization_id || app.organizationId || null,
    type: app.credential_display_name || app.credential_type || app.document_type || 'Credential',
    credentialConfigId: app.credential_configuration_id || app.credential_type,
    issuer: null,
    issuerDid: integrationContext.issuer_did || integrationContext.issuerDid || null,
    date: app.submitted_at || app.created_at,
    updatedAt: app.updated_at || app.submitted_at || app.created_at,
    expiresAt: null,
    status,
    step: getStepIndex(status),
    reference: app.reference_number,
    offerUrl: app.credential_offer_uri || null,
    offerUris: app.credential_offer_uris || {},
    offerLabels: app.credential_offer_labels || {},
    offerExpiresAt: app.offer_expires_at || null,
    formData,
    integrationContext,
    canvasContext: integrationContext.canvas || formData.canvas_context || null,
    evidenceSubmissions: Array.isArray(app.evidence_submissions) ? app.evidence_submissions : [],
    issuanceTransactionId: app.issuance_transaction_id || null,
    deliveryMode: integrationContext.delivery_mode || integrationContext.delivery?.mode || null,
    imageUrl,
  };
}

function firstPresent(...values) {
  return values.find((value) => value !== undefined && value !== null && String(value).trim() !== '');
}

function credentialImageFromData(data = {}, context = {}) {
  return firstPresent(
    data.badge_image_url,
    data.image_url,
    data.logo_url,
    data.display_style?.logo_url,
    data.display?.logo?.uri,
    data.claims?.badge_image_url,
    data.claims?.achievement?.image?.id,
    data.claims?.achievement?.image,
    data.credential?.credentialSubject?.achievement?.image?.id,
    data.credential?.credentialSubject?.achievement?.image,
    data.credential_subject?.achievement?.image?.id,
    data.credential_subject?.achievement?.image,
    context.badge_image_url,
    context.credential_metadata?.badge_image_url,
    context.credential_metadata?.image_url,
    context.open_badge?.image?.id,
    context.open_badge?.image,
  );
}

function claimStatusForRow(row = {}) {
  if (row.kind === 'credential') {
    if (row.status === 'active') return 'Claimed';
    if (row.status === 'revoked') return 'No longer valid';
    if (row.status === 'expired') return 'Expired';
    return getStatusLabel(row);
  }
  if (['approved', 'offered'].includes(row.status)) return 'Ready to claim';
  if (['credentialed', 'issued'].includes(row.status)) return 'Claimed';
  if (row.status === 'rejected') return 'Not claimable';
  return 'Not ready to claim';
}

function canvasDetailsForRow(row = {}) {
  const canvas = row.canvasContext || {};
  const formData = row.formData || {};
  const nestedContext = canvas.canvas_context || {};
  return [
    {
      label: 'Course',
      value: firstPresent(
        canvas.canvas_course_name,
        canvas.course_name,
        canvas.title,
        nestedContext.title,
        formData.canvas_course_name,
        formData.course_name,
      ),
    },
    {
      label: 'Canvas activity',
      value: firstPresent(
        canvas.canvas_assignment_name,
        canvas.assignment_name,
        canvas.resource_link_title,
        nestedContext.resource_link_title,
        formData.canvas_assignment_name,
        formData.quiz_name,
      ),
    },
    {
      label: 'Canvas account',
      value: firstPresent(canvas.canvas_account_id, row.integrationContext?.canvas_account_id, formData.canvas_account_id),
    },
    {
      label: 'Program binding',
      value: firstPresent(canvas.canvas_program_binding_id, row.integrationContext?.canvas_program_binding_id),
    },
  ].filter((item) => item.value);
}

function canvasDeliveriesForRow(row = {}) {
  return (row.deliveries || []).filter((delivery) => (
    delivery.delivery_target === 'canvas_credentials'
    || delivery.provider === 'canvas_credentials'
  ));
}

function formatDeliveryStatus(status) {
  if (!status) return 'Unknown';
  return String(status).replace(/_/g, ' ').replace(/\b\w/g, (char) => char.toUpperCase());
}

// ---------------------------------------------------------------------------
// Filters
// ---------------------------------------------------------------------------

const FILTER_ALL      = 'all';
const FILTER_ISSUED   = 'issued';
const FILTER_PROGRESS = 'in-progress';
const FILTER_ACTION   = 'action';

function matchesFilter(row, filter) {
  if (filter === FILTER_ALL) return true;
  if (filter === FILTER_ISSUED) {
    return row.kind === 'credential' || row.status === 'issued' || row.status === 'credentialed';
  }
  if (filter === FILTER_PROGRESS) {
    return (
      row.kind === 'application' &&
      !['approved', 'issued', 'credentialed', 'rejected'].includes(row.status)
    );
  }
  if (filter === FILTER_ACTION) {
    return isActionRequired(row);
  }
  return true;
}

// ---------------------------------------------------------------------------
// Status chip helpers
// ---------------------------------------------------------------------------

function getStatusColor(row) {
  if (row.kind === 'credential') {
    switch (row.status) {
      case 'active':  return 'success';
      case 'expired': return 'error';
      case 'revoked': return 'error';
      default:        return 'default';
    }
  }
  switch (row.status) {
    case 'approved':
    case 'offered':               return 'primary';
    case 'credentialed':
    case 'issued':                return 'success';
    case 'rejected':              return 'error';
    case 'needs_info':            return 'warning';
    case 'under_review':
    case 'vetting_in_progress':
    case 'pending_approval':      return 'info';
    case 'submitted':             return 'default';
    default:                      return 'default';
  }
}

function getStatusLabel(row) {
  if (row.kind === 'credential') {
    if (row.status === 'active') return 'Active';
    if (row.status === 'expired') return 'Expired';
    if (row.status === 'revoked') return 'Revoked';
    return row.status.charAt(0).toUpperCase() + row.status.slice(1);
  }
  switch (row.status) {
    case 'submitted':             return 'Submitted';
    case 'under_review':
    case 'vetting_in_progress':   return 'Under Review';
    case 'pending_approval':      return 'Pending Approval';
    case 'needs_info':            return 'Info Required';
    case 'approved':              return 'Ready to Claim';
    case 'offered':               return 'Wallet Invite Ready';
    case 'credentialed':
    case 'issued':                return 'Credential Issued';
    case 'rejected':              return 'Rejected';
    default:                      return row.status;
  }
}

// ---------------------------------------------------------------------------
// Inline step indicator — CSS circles with labels below
// ---------------------------------------------------------------------------

function StepIndicator({ step, status }) {
  const isRejected = status === 'rejected';
  const n = STAGES.length;

  return (
    <Box
      sx={{
        display: 'grid',
        gridTemplateColumns: `repeat(${n}, 1fr)`,
        width: '100%',
        minWidth: 220,
      }}
    >
      {STAGES.map((stage, i) => {
        const isComplete = !isRejected && step > i;
        const isCurrent  = !isRejected && step === i;

        // Circle border + fill
        const circleColor = isComplete
          ? 'success.main'
          : isCurrent
          ? 'primary.main'
          : 'action.disabled';

        // Connector: left half (i-1 → i) is green when step >= i
        const leftColor  = !isRejected && step >= i ? 'success.main' : 'divider';
        // Connector: right half (i → i+1) is green when step > i
        const rightColor = !isRejected && step > i  ? 'success.main' : 'divider';

        return (
          <Box
            key={stage.key}
            sx={{
              position: 'relative',
              display: 'flex',
              flexDirection: 'column',
              alignItems: 'center',
              pt: '2px',
            }}
          >
            {/* Left connector half */}
            {i > 0 && (
              <Box
                sx={{
                  position: 'absolute',
                  left: 0,
                  right: '50%',
                  top: '12px',   // circle center = pt(2) + circleH(22)/2 - lineH(2)/2
                  height: 2,
                  bgcolor: leftColor,
                }}
              />
            )}
            {/* Right connector half */}
            {i < n - 1 && (
              <Box
                sx={{
                  position: 'absolute',
                  left: '50%',
                  right: 0,
                  top: '12px',
                  height: 2,
                  bgcolor: rightColor,
                }}
              />
            )}

            {/* Circle node */}
            <Box
              sx={{
                width: 22,
                height: 22,
                borderRadius: '50%',
                border: '2px solid',
                borderColor: circleColor,
                bgcolor: isComplete ? circleColor : 'background.paper',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                position: 'relative',
                zIndex: 1,
                flexShrink: 0,
              }}
            >
              {isComplete && <CheckIcon sx={{ fontSize: 13, color: 'white' }} />}
              {isCurrent && (
                <Box
                  sx={{
                    width: 8,
                    height: 8,
                    borderRadius: '50%',
                    bgcolor: 'primary.main',
                  }}
                />
              )}
            </Box>

            {/* Label below circle */}
            <Typography
              variant="caption"
              sx={{
                fontSize: '0.6rem',
                mt: 0.5,
                color: isComplete
                  ? 'success.dark'
                  : isCurrent
                  ? 'primary.main'
                  : 'text.disabled',
                fontWeight: isCurrent ? 700 : 400,
                textAlign: 'center',
                lineHeight: 1.2,
                whiteSpace: 'nowrap',
              }}
            >
              {stage.label}
            </Typography>
          </Box>
        );
      })}
    </Box>
  );
}

// ---------------------------------------------------------------------------
// StatusCircle — compact single-state indicator replacing the progress bar
// ---------------------------------------------------------------------------

const STATUS_META = {
  // Application pipeline
  draft:               { label: 'Draft',            color: '#9e9e9e', variant: 'outlined'  },
  submitted:           { label: 'Submitted',         color: '#9e9e9e', variant: 'outlined'  },
  under_review:        { label: 'Under Review',      color: '#f59e0b', variant: 'spin'      },
  vetting_in_progress: { label: 'Under Review',      color: '#f59e0b', variant: 'spin'      },
  pending_approval:    { label: 'Pending Approval',  color: '#6366f1', variant: 'outlined'  },
  needs_info:          { label: 'Info Required',     color: '#f97316', variant: 'filled'    },
  approved:            { label: 'Ready to Claim',    color: '#3b82f6', variant: 'emphasis'  },
  offered:             { label: 'Wallet Invite Ready', color: '#3b82f6', variant: 'emphasis'  },
  credentialed:        { label: 'Credential Issued', color: '#22c55e', variant: 'filled'    },
  issued:              { label: 'Issued',            color: '#22c55e', variant: 'filled'    },
  rejected:            { label: 'Rejected',          color: '#ef4444', variant: 'filled'    },
  // Credential document
  active:              { label: 'Active',            color: '#22c55e', variant: 'filled'    },
  expired:             { label: 'Expired',           color: '#ef4444', variant: 'filled'    },
  revoked:             { label: 'Revoked',           color: '#ef4444', variant: 'filled'    },
};

/**
 * StatusCircle
 *
 * A single compact circle that encodes status via color + icon shape.
 * - sm (16 px): table use, tooltip on hover
 * - md (24 px): card/detail use, label always visible
 */
function StatusCircle({ status, showLabel = false, size = 'sm' }) {
  const px = size === 'sm' ? 16 : 24;
  const meta = STATUS_META[status] ?? { label: status, color: '#9e9e9e', variant: 'outlined' };
  const { color, variant, label } = meta;

  const isSpin     = variant === 'spin';
  const isEmphasis = variant === 'emphasis';
  const isFilled   = variant === 'filled' || isEmphasis;
  const iconSz     = Math.round(px * 0.58);

  // Inner content of the circle
  let inner;
  if (isSpin) {
    // Animated spinner arc — pure CSS, no SVG dependency
    inner = (
      <Box
        sx={{
          width: '62%',
          height: '62%',
          borderRadius: '50%',
          border: '2px solid',
          borderColor: `${color}35`,
          borderTopColor: color,
          animation: 'statusSpin 0.9s linear infinite',
          '@keyframes statusSpin': {
            from: { transform: 'rotate(0deg)' },
            to:   { transform: 'rotate(360deg)' },
          },
        }}
      />
    );
  } else if (isEmphasis) {
    // inbox / ready-to-claim arrow
    inner = <MoveToInboxIcon sx={{ fontSize: iconSz, color: 'white' }} />;
  } else if (['issued', 'credentialed', 'active'].includes(status)) {
    inner = <CheckIcon sx={{ fontSize: iconSz, color: 'white' }} />;
  } else if (['rejected', 'revoked', 'expired'].includes(status)) {
    inner = <CloseIcon sx={{ fontSize: iconSz, color: 'white' }} />;
  } else if (status === 'needs_info') {
    inner = <WarningAmberIcon sx={{ fontSize: iconSz, color: 'white' }} />;
  } else {
    // outlined states (submitted, pending_approval, draft): filled dot
    inner = (
      <Box
        sx={{
          width: Math.round(px * 0.36),
          height: Math.round(px * 0.36),
          borderRadius: '50%',
          bgcolor: color,
        }}
      />
    );
  }

  const circle = (
    <Tooltip
      title={`Status: ${label}`}
      arrow
      disableHoverListener={showLabel}
      disableFocusListener={showLabel}
    >
      <Box
        component="span"
        aria-label={`Status: ${label}`}
        role="img"
        sx={{
          display: 'inline-flex',
          width: px,
          height: px,
          borderRadius: '50%',
          border:   isFilled ? 'none' : `1.5px solid ${color}`,
          bgcolor:  isFilled ? color  : 'transparent',
          alignItems: 'center',
          justifyContent: 'center',
          flexShrink: 0,
          transition: 'box-shadow 0.2s',
          ...(isEmphasis && {
            boxShadow: `0 0 0 3px ${color}30`,
          }),
        }}
      >
        {inner}
      </Box>
    </Tooltip>
  );

  if (!showLabel) return circle;

  return (
    <Stack direction="row" alignItems="center" spacing={0.75} sx={{ display: 'inline-flex' }}>
      {circle}
      <Typography
        variant={size === 'sm' ? 'body2' : 'body1'}
        sx={{
          fontWeight: isEmphasis ? 700 : 400,
          color: isEmphasis ? color : 'text.secondary',
        }}
      >
        {label}
      </Typography>
    </Stack>
  );
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

function MyIdentityPage() {
  const { t } = useTranslation('applicant');
  const theme = useTheme();
  const isMobile = useMediaQuery(theme.breakpoints.down('sm'));

  // --- URL highlight support ---
  const [searchParams] = useSearchParams();
  const highlightId = searchParams.get('id');
  const highlightHandled = useRef(false);

  // --- State ---
  const [credentials, setCredentials] = useState([]);
  const [applications, setApplications] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [filter, setFilter] = useState(FILTER_ALL);
  const [selectedApp, setSelectedApp] = useState(null);
  const [claimApp, setClaimApp] = useState(null);

  // --- Data loading ---
  useEffect(() => {
    let cancelled = false;

    const load = async (showLoading = true) => {
      try {
        if (showLoading) setLoading(true);

        const [credResult, appResult] = await Promise.all([
          getMyCredentials().catch(() => ({ credentials: [] })),
          getMyApplications({ limit: 100 }).catch(() => ({ applications: [] })),
        ]);

        if (cancelled) return;

        const creds = (credResult.credentials || credResult.documents || []).map(normaliseCredential);
        const apps  = (appResult.applications || []).map(normaliseApplication);

        // Deduplicate: keep only the most-advanced row per credential config.
        // If an application reaches credentialed/issued, discard any matching
        // credential document row (the app row has richer progress context).
        // Also deduplicate multiple applications for the same credential config
        // by keeping only the most recent one.
        const appsByConfig = new Map();
        for (const app of apps) {
          const key = app.credentialConfigId || app.id;
          const existing = appsByConfig.get(key);
          if (!existing || new Date(app.updatedAt || 0) > new Date(existing.updatedAt || 0)) {
            appsByConfig.set(key, app);
          }
        }
        const dedupedApps = Array.from(appsByConfig.values());

        const appConfigIds = new Set(dedupedApps.map((a) => a.credentialConfigId).filter(Boolean));
        const dedupedCreds = creds.filter((c) => !appConfigIds.has(c.credentialConfigId));

        setCredentials(dedupedCreds);
        setApplications(dedupedApps);
        setError(null);
      } catch (err) {
        if (!cancelled) {
          console.error('Error loading identity data:', err);
          setError(err?.message || String(err));
        }
      } finally {
        if (!cancelled && showLoading) setLoading(false);
      }
    };

    load(true);

    const interval = setInterval(() => load(false), 15000);
    const onFocus = () => load(false);
    window.addEventListener('focus', onFocus);

    return () => {
      cancelled = true;
      clearInterval(interval);
      window.removeEventListener('focus', onFocus);
    };
  }, []);

  // Auto-open detail dialog when arriving via ?id=
  useEffect(() => {
    if (highlightId && applications.length > 0 && !highlightHandled.current) {
      const match = applications.find((a) => a.id === highlightId);
      if (match) {
        highlightHandled.current = true;
        setSelectedApp(match);
      }
    }
  }, [highlightId, applications]);

  // --- Merge + filter ---
  const allRows = useMemo(() => [...credentials, ...applications], [credentials, applications]);

  const rows = useMemo(() => {
    const filtered = allRows.filter((row) => matchesFilter(row, filter));
    filtered.sort((a, b) => {
      const aAction = isActionRequired(a);
      const bAction = isActionRequired(b);
      if (aAction && !bAction) return -1;
      if (!aAction && bAction) return 1;
      return new Date(b.updatedAt || b.date || 0) - new Date(a.updatedAt || a.date || 0);
    });
    return filtered;
  }, [allRows, filter]);

  // --- Grouped rows for section display ---
  const grouped = useMemo(() => {
    const action = [];
    const progress = [];
    const completed = [];
    for (const row of rows) {
      if (isActionRequired(row)) {
        action.push(row);
      } else if (row.kind === 'application' && !TERMINAL_STATUSES.has(row.status)) {
        progress.push(row);
      } else {
        completed.push(row);
      }
    }
    return { action, progress, completed };
  }, [rows]);

  // --- Filter counts ---
  const counts = useMemo(() => ({
    all: allRows.length,
    issued: allRows.filter((r) => matchesFilter(r, FILTER_ISSUED)).length,
    progress: allRows.filter((r) => matchesFilter(r, FILTER_PROGRESS)).length,
    action: allRows.filter((r) => matchesFilter(r, FILTER_ACTION)).length,
  }), [allRows]);

  // --- Row action handler ---
  const handlePrimaryAction = useCallback((row) => {
    const label = getActionLabel(row);
    if (label === 'Claim' || label === 'Receive Again') {
      setClaimApp(row);
    } else if (label === 'Continue' || label === 'Present') {
      setSelectedApp(row);
    }
  }, []);

  // -----------------------------------------------------------------------
  // Row renderer (shared between mobile card and desktop row)
  // -----------------------------------------------------------------------

  const renderMobileCard = (row, highlight = false) => (
    <Card
      key={`${row.kind}-${row.id}`}
      variant="outlined"
      sx={{
        borderColor: highlight ? 'warning.main' : undefined,
        bgcolor: highlight ? 'warning.50' : undefined,
        borderWidth: highlight ? 2 : 1,
      }}
    >
      <CardContent sx={{ pb: '12px !important' }}>
        {/* Header: type + status */}
        <Stack direction="row" justifyContent="space-between" alignItems="center" sx={{ mb: 0.75 }}>
          <Stack direction="row" spacing={1} alignItems="center" sx={{ flex: 1, minWidth: 0 }}>
            <Avatar
              src={row.imageUrl || undefined}
              alt={row.type}
              variant="rounded"
              sx={{ width: 34, height: 34, bgcolor: 'action.hover', color: 'primary.main', flexShrink: 0 }}
            >
              <WorkspacePremiumIcon fontSize="small" />
            </Avatar>
            <Box sx={{ minWidth: 0 }}>
              <Typography fontWeight={600} noWrap>{row.type}</Typography>
              <Typography variant="caption" color="text.secondary" noWrap>
                {claimStatusForRow(row)}
              </Typography>
            </Box>
          </Stack>
          <Box sx={{ ml: 1.5, flexShrink: 0 }}>
            <StatusCircle status={row.status} size="md" showLabel />
          </Box>
        </Stack>

        {/* Inline message */}
        {getStatusMessage(row.status) && (
          <Stack direction="row" alignItems="center" spacing={0.5} sx={{ mb: 0.5 }}>
            {isActionRequired(row) && (
              <WarningAmberIcon sx={{ fontSize: 14, color: 'warning.main' }} />
            )}
            <Typography
              variant="caption"
              color={isActionRequired(row) ? 'warning.dark' : 'text.secondary'}
              fontWeight={isActionRequired(row) ? 600 : 400}
            >
              {getStatusMessage(row.status)}
            </Typography>
          </Stack>
        )}

        {/* Updated time */}
        <Typography variant="caption" color="text.secondary" sx={{ display: 'block', mb: 1 }}>
          Updated {timeAgo(row.updatedAt || row.date)}
        </Typography>

        {/* Actions */}
        <Stack direction="row" spacing={1} alignItems="center">
          {row.kind === 'credential' && (
            <>
              <Tooltip title={t('credentials.actions.viewDetails')}>
                <IconButton size="small" aria-label={`View ${row.type} details`} onClick={() => setSelectedApp(row)}>
                  <VisibilityIcon fontSize="small" />
                </IconButton>
              </Tooltip>
              <Tooltip title={t('credentials.actions.showQRCode')}>
                <IconButton size="small" color="primary"><QrCodeIcon fontSize="small" /></IconButton>
              </Tooltip>
              <Tooltip title={t('credentials.actions.download')}>
                <IconButton size="small"><DownloadIcon fontSize="small" /></IconButton>
              </Tooltip>
            </>
          )}
          {row.kind === 'application' && (
            <>
              {getActionLabel(row) && (
                <Button
                  size="small"
                  variant="contained"
                  color={getActionLabel(row) === 'Continue' ? 'warning' : 'primary'}
                  onClick={() => handlePrimaryAction(row)}
                >
                  {getActionLabel(row)}
                </Button>
              )}
              <Button size="small" variant="text" onClick={() => setSelectedApp(row)}>
                Details
              </Button>
            </>
          )}
        </Stack>
      </CardContent>
    </Card>
  );

  const renderDesktopRow = (row, highlight = false) => (
    <Stack
      key={`${row.kind}-${row.id}`}
      direction="row"
      alignItems="center"
      spacing={2}
      sx={{
        px: 2,
        py: 1.5,
        borderBottom: '1px solid',
        borderColor: 'divider',
        bgcolor: highlight ? 'warning.50' : 'transparent',
        borderLeft: highlight ? '3px solid' : '3px solid transparent',
        borderLeftColor: highlight ? 'warning.main' : 'transparent',
        '&:hover': { bgcolor: highlight ? 'warning.100' : 'action.hover' },
        transition: 'background-color 0.15s',
      }}
    >
      {/* Credential name */}
      <Box sx={{ flex: '0 0 200px', minWidth: 0 }}>
        <Stack direction="row" spacing={1} alignItems="center">
          <Avatar
            src={row.imageUrl || undefined}
            alt={row.type}
            variant="rounded"
            sx={{ width: 34, height: 34, bgcolor: 'action.hover', color: 'primary.main', flexShrink: 0 }}
          >
            <WorkspacePremiumIcon fontSize="small" />
          </Avatar>
          <Box sx={{ minWidth: 0 }}>
            <Typography fontWeight={500} noWrap>{row.type}</Typography>
            <Typography variant="caption" color="text.secondary" noWrap>
              {row.kind === 'credential' ? (row.issuer || 'Credential') : 'Application'} - {claimStatusForRow(row)}
            </Typography>
          </Box>
        </Stack>
      </Box>

      {/* Status — StatusCircle + label + optional message */}
      <Box sx={{ flex: '1 1 200px', minWidth: 0 }}>
        <StatusCircle status={row.status} showLabel size="sm" />
        {getStatusMessage(row.status) && (
          <Typography
            variant="caption"
            color={isActionRequired(row) ? 'warning.dark' : 'text.secondary'}
            fontWeight={isActionRequired(row) ? 600 : 400}
            sx={{ display: 'block', mt: 0.25, pl: '22px' }}
          >
            {getStatusMessage(row.status)}
          </Typography>
        )}
      </Box>

      {/* Updated */}
      <Box sx={{ flex: '0 0 80px', textAlign: 'right' }}>
        <Typography variant="caption" color="text.secondary">
          {timeAgo(row.updatedAt || row.date)}
        </Typography>
      </Box>

      {/* Actions */}
      <Box sx={{ flex: '0 0 160px', textAlign: 'right' }}>
        {row.kind === 'credential' && (
          <>
            <Tooltip title={t('credentials.actions.viewDetails')}>
              <IconButton size="small" aria-label={`View ${row.type} details`} onClick={() => setSelectedApp(row)}>
                <VisibilityIcon fontSize="small" />
              </IconButton>
            </Tooltip>
            <Tooltip title={t('credentials.actions.showQRCode')}>
              <IconButton size="small" color="primary"><QrCodeIcon fontSize="small" /></IconButton>
            </Tooltip>
            <Tooltip title={t('credentials.actions.download')}>
              <IconButton size="small"><DownloadIcon fontSize="small" /></IconButton>
            </Tooltip>
          </>
        )}
        {row.kind === 'application' && (
          <Stack direction="row" spacing={0.5} justifyContent="flex-end">
            {getActionLabel(row) && (
              <Button
                size="small"
                variant="contained"
                color={getActionLabel(row) === 'Continue' ? 'warning' : 'primary'}
                onClick={() => handlePrimaryAction(row)}
              >
                {getActionLabel(row)}
              </Button>
            )}
            <Button size="small" variant="text" onClick={() => setSelectedApp(row)}>
              Details
            </Button>
          </Stack>
        )}
      </Box>
    </Stack>
  );

  // Section header
  const renderSection = (title, icon, rows, options = {}) => {
    if (rows.length === 0) return null;
    const { highlight = false } = options;
    return (
      <Box sx={{ mb: 3 }}>
        <Stack direction="row" alignItems="center" spacing={1} sx={{ mb: 1, px: isMobile ? 0 : 2 }}>
          {icon}
          <Typography variant="subtitle2" fontWeight={700} color="text.secondary" textTransform="uppercase" letterSpacing={0.5}>
            {title} ({rows.length})
          </Typography>
        </Stack>
        {isMobile ? (
          <Stack spacing={1.5}>
            {rows.map((row) => renderMobileCard(row, highlight))}
          </Stack>
        ) : (
          <Paper variant="outlined">
            {rows.map((row) => renderDesktopRow(row, highlight))}
          </Paper>
        )}
      </Box>
    );
  };

  // -----------------------------------------------------------------------
  // Render
  // -----------------------------------------------------------------------

  return (
    <Box>
      {/* Header */}
      <Stack direction="row" justifyContent="space-between" alignItems="center" sx={{ mb: 2 }}>
        <Box>
          <Typography variant="h4" gutterBottom>
            {t('identity.title', 'My Identity')}
          </Typography>
          <Typography variant="body1" color="text.secondary">
            {t('identity.description', 'All your credentials and applications in one place.')}
          </Typography>
        </Box>
        <Button
          variant="contained"
          startIcon={<AddIcon />}
          href="/console/applicant/catalog"
          sx={{ whiteSpace: 'nowrap' }}
        >
          {t('identity.applyButton', 'Apply for Credential')}
        </Button>
      </Stack>

      {/* Filters */}
      <ToggleButtonGroup
        value={filter}
        exclusive
        onChange={(_, v) => v && setFilter(v)}
        size="small"
        sx={{ mb: 2 }}
      >
        <ToggleButton value={FILTER_ALL}>
          {t('identity.filters.all', 'All')} ({counts.all})
        </ToggleButton>
        <ToggleButton value={FILTER_ISSUED}>
          {t('identity.filters.issued', 'Issued')} ({counts.issued})
        </ToggleButton>
        <ToggleButton value={FILTER_PROGRESS}>
          {t('identity.filters.inProgress', 'In Progress')} ({counts.progress})
        </ToggleButton>
        <ToggleButton value={FILTER_ACTION}>
          {t('identity.filters.actionRequired', 'Action Required')} ({counts.action})
        </ToggleButton>
      </ToggleButtonGroup>

      {error && <Alert severity="error" sx={{ mb: 2 }}>{error}</Alert>}

      {loading ? (
        <LinearProgress />
      ) : rows.length === 0 ? (
        <Paper sx={{ p: 6, textAlign: 'center' }}>
          <Typography variant="h6" gutterBottom>
            {filter === FILTER_ALL
              ? t('identity.empty.title', 'No credentials yet')
              : t('identity.empty.filteredTitle', 'Nothing matches this filter')}
          </Typography>
          <Typography color="text.secondary" paragraph>
            {t('identity.empty.message', 'Browse the catalog to apply for your first credential.')}
          </Typography>
          {filter === FILTER_ALL && (
            <Button variant="contained" href="/console/applicant/catalog">
              {t('identity.empty.browseButton', 'Browse Credentials')}
            </Button>
          )}
          {filter !== FILTER_ALL && (
            <Button variant="text" onClick={() => setFilter(FILTER_ALL)}>
              {t('identity.empty.clearFilter', 'Clear filter')}
            </Button>
          )}
        </Paper>
      ) : (
        <Box>
          {/* Desktop header row */}
          {!isMobile && rows.length > 0 && (
            <Stack
              direction="row"
              spacing={2}
              sx={{
                px: 2,
                py: 1,
                mb: 1,
              }}
            >
              <Typography variant="caption" fontWeight={700} color="text.secondary" sx={{ flex: '0 0 200px' }}>
                CREDENTIAL
              </Typography>
              <Typography variant="caption" fontWeight={700} color="text.secondary" sx={{ flex: '1 1 200px' }}>
                STATUS
              </Typography>
              <Typography variant="caption" fontWeight={700} color="text.secondary" sx={{ flex: '0 0 80px', textAlign: 'right' }}>
                UPDATED
              </Typography>
              <Typography variant="caption" fontWeight={700} color="text.secondary" sx={{ flex: '0 0 160px', textAlign: 'right' }}>
                ACTIONS
              </Typography>
            </Stack>
          )}

          {/* Grouped sections */}
          {renderSection(
            'Action Required',
            <WarningAmberIcon sx={{ fontSize: 18, color: 'warning.main' }} />,
            grouped.action,
            { highlight: true },
          )}
          {renderSection(
            'In Progress',
            <FiberManualRecordIcon sx={{ fontSize: 14, color: 'info.main' }} />,
            grouped.progress,
          )}
          {renderSection(
            'Completed',
            <CheckCircleIcon sx={{ fontSize: 18, color: 'success.main' }} />,
            grouped.completed,
          )}
        </Box>
      )}

      {/* Claim Credential Dialog */}
      <ClaimCredentialDialog
        open={!!claimApp}
        onClose={() => setClaimApp(null)}
        applicationId={claimApp?.id}
        offerData={
          claimApp
            ? {
                organization_id: claimApp.organizationId,
                offer_url: claimApp.offerUrl,
                credential_offer_uris: claimApp.offerUris,
                credential_offer_labels: claimApp.offerLabels,
                expires_at: claimApp.offerExpiresAt,
              }
            : undefined
        }
        organizationId={claimApp?.organizationId}
      />

      {/* Application Details Dialog */}
      <Dialog open={!!selectedApp} onClose={() => setSelectedApp(null)} maxWidth="sm" fullWidth>
        <DialogTitle>{selectedApp?.kind === 'credential' ? 'Credential Details' : 'Application Details'}</DialogTitle>
        <DialogContent>
          {selectedApp && (
            <Box sx={{ pt: 1 }}>
              <Stack direction="row" spacing={2} alignItems="center" sx={{ mb: 2 }}>
                <Avatar
                  src={selectedApp.imageUrl || undefined}
                  alt={selectedApp.type}
                  variant="rounded"
                  sx={{ width: 64, height: 64, bgcolor: 'action.hover', color: 'primary.main' }}
                >
                  <WorkspacePremiumIcon />
                </Avatar>
                <Box sx={{ minWidth: 0 }}>
                  <Typography variant="subtitle2" color="text.secondary">Credential</Typography>
                  <Typography variant="h6" sx={{ overflowWrap: 'anywhere' }}>{selectedApp.type}</Typography>
                </Box>
              </Stack>

              {selectedApp.issuerDid && (
                <>
                  <Typography variant="subtitle2" color="text.secondary">Issuer DID</Typography>
                  <Typography paragraph sx={{ fontFamily: 'monospace', overflowWrap: 'anywhere' }}>
                    {selectedApp.issuerDid}
                  </Typography>
                </>
              )}

              <Typography variant="subtitle2" color="text.secondary">
                {selectedApp.kind === 'credential' ? 'Issued' : 'Submitted'}
              </Typography>
              <Typography paragraph>
                {selectedApp.date ? new Date(selectedApp.date).toLocaleString() : 'Not recorded'}
              </Typography>

              <Typography variant="subtitle2" color="text.secondary">Last Updated</Typography>
              <Typography paragraph>
                {selectedApp.updatedAt || selectedApp.date
                  ? new Date(selectedApp.updatedAt || selectedApp.date).toLocaleString()
                  : 'Not recorded'}{' '}
                ({timeAgo(selectedApp.updatedAt || selectedApp.date)})
              </Typography>

              <Typography variant="subtitle2" color="text.secondary">Status</Typography>
              <Stack direction="row" alignItems="center" spacing={1} sx={{ mb: 1 }}>
                <Chip label={getStatusLabel(selectedApp)} color={getStatusColor(selectedApp)} size="small" />
                <Chip label={`Claim: ${claimStatusForRow(selectedApp)}`} size="small" variant="outlined" />
                {selectedApp.deliveryMode && (
                  <Chip label={`Delivery: ${selectedApp.deliveryMode.replace(/_/g, ' ')}`} size="small" variant="outlined" />
                )}
              </Stack>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                {getStatusMessage(selectedApp.status)}
              </Typography>

              {canvasDetailsForRow(selectedApp).length > 0 && (
                <Paper variant="outlined" sx={{ p: 2, mb: 2, borderRadius: 1 }} data-testid="identity-canvas-source">
                  <Stack spacing={1.25}>
                    <Stack direction="row" spacing={1} alignItems="center">
                      <SchoolIcon color="primary" fontSize="small" />
                      <Typography variant="subtitle2" sx={{ fontWeight: 800 }}>
                        Canvas course source
                      </Typography>
                    </Stack>
                    <Box sx={{ display: 'grid', gap: 1, gridTemplateColumns: { xs: '1fr', sm: 'repeat(2, minmax(0, 1fr))' } }}>
                      {canvasDetailsForRow(selectedApp).map((item) => (
                        <Box key={item.label}>
                          <Typography variant="caption" color="text.secondary">{item.label}</Typography>
                          <Typography variant="body2" sx={{ overflowWrap: 'anywhere' }}>{item.value}</Typography>
                        </Box>
                      ))}
                    </Box>
                  </Stack>
                </Paper>
              )}

              {canvasDeliveriesForRow(selectedApp).length > 0 && (
                <Paper variant="outlined" sx={{ p: 2, mb: 2, borderRadius: 1 }} data-testid="identity-canvas-delivery">
                  <Stack spacing={1.25}>
                    <Stack direction="row" spacing={1} alignItems="center">
                      <SyncAltIcon color="primary" fontSize="small" />
                      <Typography variant="subtitle2" sx={{ fontWeight: 800 }}>
                        Canvas Credentials display
                      </Typography>
                    </Stack>
                    {canvasDeliveriesForRow(selectedApp).map((delivery) => (
                      <Box key={delivery.id || delivery.external_credential_id || delivery.delivery_target}>
                        <Stack direction="row" spacing={1} alignItems="center" flexWrap="wrap" useFlexGap>
                          <Chip
                            label={formatDeliveryStatus(delivery.status)}
                            size="small"
                            color={delivery.status === 'delivered' ? 'success' : delivery.status === 'failed' ? 'error' : 'default'}
                            variant="outlined"
                          />
                          {delivery.external_credential_id && (
                            <Chip label="Mirror linked" size="small" color="success" variant="outlined" />
                          )}
                        </Stack>
                        {delivery.external_credential_id && (
                          <Typography variant="caption" color="text.secondary" sx={{ display: 'block', mt: 0.5, overflowWrap: 'anywhere' }}>
                            Canvas credential ID: {delivery.external_credential_id}
                          </Typography>
                        )}
                        {delivery.last_error && (
                          <Typography variant="caption" color="error" sx={{ display: 'block', mt: 0.5 }}>
                            {delivery.last_error}
                          </Typography>
                        )}
                      </Box>
                    ))}
                  </Stack>
                </Paper>
              )}

              {/* Timeline */}
              {selectedApp.kind === 'application' && (
                <>
                  <Divider sx={{ my: 2 }} />
                  <Typography variant="subtitle2" color="text.secondary" sx={{ mb: 1 }}>Progress Timeline</Typography>
                  <StepIndicator step={selectedApp.step ?? 0} status={selectedApp.status} />
                </>
              )}

              {/* Action prompt */}
              {getActionLabel(selectedApp) && (
                <Box sx={{ mt: 3 }}>
                  <Button
                    variant="contained"
                    fullWidth
                    onClick={() => {
                      setSelectedApp(null);
                      handlePrimaryAction(selectedApp);
                    }}
                  >
                    {getActionLabel(selectedApp)}
                  </Button>
                </Box>
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

export default MyIdentityPage;

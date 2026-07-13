import { useState, useEffect, useCallback } from 'react';
import {
  Box,
  Paper,
  Typography,
  Button,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  IconButton,
  Chip,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Alert,
  CircularProgress,
  Tabs,
  Tab,
  Tooltip,
  Stepper,
  Step,
  StepLabel,
} from '@mui/material';
import AddIcon from '@mui/icons-material/Add';
import RefreshIcon from '@mui/icons-material/Refresh';
import QrCode2Icon from '@mui/icons-material/QrCode2';
import VisibilityIcon from '@mui/icons-material/Visibility';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import ErrorIcon from '@mui/icons-material/Error';
import HourglassTopIcon from '@mui/icons-material/HourglassTop';
import { useNotifications } from '../../../hooks/useNotifications';
import { startVerificationFlow } from '../../../services/zkVerificationApi';
import { listFlowExecutions } from '../../../services/flowsApi';
import PolicySelectStep from './steps/PolicySelectStep';
import SessionConfigStep from './steps/SessionConfigStep';
import QRDisplayStep from './steps/QRDisplayStep';
import VerificationResultSummary from './VerificationResultSummary';
import Oid4vpQrCode from './Oid4vpQrCode';
import { formatOfficialReference } from '../../../utils/officialReferences';

const WIZARD_STEPS = ['Select Policy', 'Configure Session', 'Scan & Verify'];

const STATUS_CHIP = {
  pending:   { label: 'Pending',   color: 'warning', icon: <HourglassTopIcon sx={{ fontSize: 14 }} /> },
  completed: { label: 'Verified',  color: 'success', icon: <CheckCircleIcon  sx={{ fontSize: 14 }} /> },
  failed:    { label: 'Failed',    color: 'error',   icon: <ErrorIcon        sx={{ fontSize: 14 }} /> },
  expired:   { label: 'Expired',   color: 'default', icon: <ErrorIcon        sx={{ fontSize: 14 }} /> },
  cancelled: { label: 'Cancelled', color: 'default', icon: <ErrorIcon        sx={{ fontSize: 14 }} /> },
};

const ACTIVE_STATUSES   = ['pending'];
const HISTORY_STATUSES  = ['completed', 'failed', 'expired', 'cancelled'];

function normalizeSessionStatus(status) {
  const value = String(status || '').toLowerCase();
  if (['passed', 'completed', 'verified'].includes(value)) return 'completed';
  if (['failed', 'denied'].includes(value)) return 'failed';
  if (value === 'expired') return 'expired';
  if (['cancelled', 'canceled'].includes(value)) return 'cancelled';
  return 'pending';
}

function normalizeFlowSession(session) {
  const sessionId = session?.instance_id || session?.id || session?.session_id;
  if (!sessionId) return session;
  const context = session.context_data || session.context || {};
  return {
    ...session,
    session_id: sessionId,
    status: normalizeSessionStatus(session.status === 'awaiting_wallet' ? 'pending' : session.status),
    purpose: session.purpose || session.external_reference || context.purpose || context.external_reference || 'Credential verification',
    qr_code_data: session.qr_code_data || context.qr_code_data,
    request_uri: session.request_uri || context.request_uri,
    dc_api_request_url: session.dc_api_request_url || `/v1/flows/instances/${encodeURIComponent(sessionId)}/request?transport=dc_api`,
    dc_api_submit_url: session.dc_api_submit_url || `/v1/flows/instances/${encodeURIComponent(sessionId)}/submit/dc-api`,
  };
}

function isVerificationFlowInstance(session = {}) {
  const metadata = session.metadata || {};
  const context = session.context_data || session.context || {};
  const values = [
    session.flow_type,
    metadata.flow_type,
    metadata.flow_definition_reference,
    context.flow_type,
    context.protocol_flow_type,
    context.flow_definition_reference,
  ].map((value) => String(value || '').toLowerCase());

  return values.some((value) => (
    value.includes('verification')
    || value.includes('oid4vp')
    || value.includes('presentation')
    || value === '__verification__'
  ));
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function StatusChip({ status }) {
  const normalized = normalizeSessionStatus(status);
  const cfg = STATUS_CHIP[normalized] || { label: status, color: 'default' };
  return (
    <Chip
      size="small"
      label={cfg.label}
      color={cfg.color}
      icon={cfg.icon}
    />
  );
}

function TabPanel({ children, value, index }) {
  return (
    <div role="tabpanel" hidden={value !== index}>
      {value === index && <Box>{children}</Box>}
    </div>
  );
}

function formatDate(iso) {
  if (!iso) return '—';
  return new Date(iso).toLocaleString();
}

const formatSessionReference = (id) => formatOfficialReference(id, 'record');

function VerificationSessionManager({ organizationId }) {
  const { showSuccess } = useNotifications();

  // Sessions state
  const [sessions, setSessions] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [tabIndex, setTabIndex] = useState(0);

  // Wizard state
  const [wizardOpen, setWizardOpen] = useState(false);
  const [wizardStep, setWizardStep] = useState(0);
  const [wizardData, setWizardData] = useState({});
  const [pendingSession, setPendingSession] = useState(null);
  const [wizardLoading, setWizardLoading] = useState(false);
  const [wizardError, setWizardError] = useState(null);

  // Detail drawer state
  const [detailSession, setDetailSession] = useState(null);
  const [detailOpen, setDetailOpen] = useState(false);

  // ── Data fetching ─────────────────────────────────────────────────────────

  const fetchSessions = useCallback(async () => {
    if (!organizationId) {
      setSessions([]);
      setLoading(false);
      return;
    }
    setLoading(true);
    setError(null);
    try {
      const flowData = await listFlowExecutions(null, { organization_id: organizationId });
      const flowSessions = flowData
        .filter(isVerificationFlowInstance)
        .map(normalizeFlowSession);
      setSessions(flowSessions);
    } catch (err) {
      setSessions([]);
      setError(err.message || 'Failed to load verification sessions');
    } finally {
      setLoading(false);
    }
  }, [organizationId]);

  useEffect(() => {
    fetchSessions();
  }, [fetchSessions]);

  // ── Filtered session lists ────────────────────────────────────────────────

  const activeSessions  = sessions.filter((s) => ACTIVE_STATUSES.includes(normalizeSessionStatus(s.status)));
  const historySessions = sessions.filter((s) => HISTORY_STATUSES.includes(normalizeSessionStatus(s.status)));

  // ── Wizard handlers ───────────────────────────────────────────────────────

  const openWizard = () => {
    setWizardStep(0);
    setWizardData({});
    setPendingSession(null);
    setWizardError(null);
    setWizardOpen(true);
  };

  const closeWizard = () => {
    setWizardOpen(false);
    fetchSessions();
  };

  const handleWizardNext = async () => {
    if (wizardStep === 1) {
      // Step 1 → 2: create the session
      setWizardLoading(true);
      setWizardError(null);
      try {
        let session = await startVerificationFlow({
          organization_id: organizationId,
          presentation_policy_id: wizardData.policy_id || undefined,
          trust_profile_id: wizardData.trust_profile_id || undefined,
          deployment_profile_id: wizardData.deployment_profile_id || undefined,
          external_reference: wizardData.purpose || wizardData.flow_name || undefined,
        });
        session = normalizeFlowSession(session);
        setPendingSession(session);
        setWizardStep(2);
      } catch (err) {
        setWizardError(err.message || 'Failed to start verification session');
      } finally {
        setWizardLoading(false);
      }
      return;
    }
    setWizardStep((s) => s + 1);
  };

  const handleWizardBack = () => setWizardStep((s) => s - 1);

  const handleVerificationComplete = (completedSession) => {
    showSuccess(`Verification ${completedSession.status}`);
    fetchSessions();
  };

  // ── Detail handlers ───────────────────────────────────────────────────────

  const openDetail = async (session) => {
    setDetailSession(session);
    setDetailOpen(true);

  };

  const closeDetail = () => {
    setDetailOpen(false);
    setDetailSession(null);
  };

  // ── Render ────────────────────────────────────────────────────────────────

  const renderSessionTable = (rows) => (
    <TableContainer>
      <Table size="small">
        <TableHead>
          <TableRow>
            <TableCell>Session Reference</TableCell>
            <TableCell>Purpose</TableCell>
            <TableCell>Status</TableCell>
            <TableCell>Created</TableCell>
            <TableCell>Updated</TableCell>
            <TableCell align="right">Actions</TableCell>
          </TableRow>
        </TableHead>
        <TableBody>
          {rows.length === 0 ? (
            <TableRow>
              <TableCell colSpan={6} align="center" sx={{ py: 4 }}>
                <Typography variant="body2" color="text.secondary">
                  No sessions
                </Typography>
              </TableCell>
            </TableRow>
          ) : (
            rows.map((session) => (
              <TableRow key={session.session_id} hover>
                <TableCell>
                  <Tooltip title={formatSessionReference(session.session_id)}>
                    <Typography variant="body2" sx={{ fontFamily: 'monospace' }}>
                      {formatSessionReference(session.session_id)}
                    </Typography>
                  </Tooltip>
                </TableCell>
                <TableCell>{session.purpose || '—'}</TableCell>
                <TableCell><StatusChip status={session.status} /></TableCell>
                <TableCell>{formatDate(session.created_at)}</TableCell>
                <TableCell>{formatDate(session.updated_at)}</TableCell>
                <TableCell align="right">
                  {normalizeSessionStatus(session.status) === 'pending' && (session.qr_code_data || session.request_uri) && (
                    <Tooltip title="Show QR code">
                      <IconButton
                        size="small"
                        aria-label="Show QR code"
                        onClick={() => openDetail(session)}
                      >
                        <QrCode2Icon fontSize="small" />
                      </IconButton>
                    </Tooltip>
                  )}
                  {normalizeSessionStatus(session.status) !== 'pending' && (
                    <Tooltip title="View details">
                      <IconButton
                        size="small"
                        aria-label="View session details"
                        onClick={() => openDetail(session)}
                      >
                        <VisibilityIcon fontSize="small" />
                      </IconButton>
                    </Tooltip>
                  )}
                </TableCell>
              </TableRow>
            ))
          )}
        </TableBody>
      </Table>
    </TableContainer>
  );

  return (
    <Box>
      {/* Header */}
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
        <Typography variant="h5">Verification Sessions</Typography>
        <Box sx={{ display: 'flex', gap: 1 }}>
          <Tooltip title="Refresh">
            <span>
              <IconButton onClick={fetchSessions} disabled={loading}>
                <RefreshIcon />
              </IconButton>
            </span>
          </Tooltip>
          <Button
            variant="contained"
            startIcon={<AddIcon />}
            onClick={openWizard}
          >
            New Verification
          </Button>
        </Box>
      </Box>

      <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
        Create standalone credential verification sessions using OID4VP.
        Wallet holders scan a QR code to share their credentials.
      </Typography>

      {error && (
        <Alert severity="error" sx={{ mb: 2 }} onClose={() => setError(null)}>
          {error}
        </Alert>
      )}

      {/* Session Tabs */}
      <Paper>
        <Tabs
          value={tabIndex}
          onChange={(_, v) => setTabIndex(v)}
          sx={{ borderBottom: 1, borderColor: 'divider', px: 2 }}
        >
          <Tab label={`Active (${activeSessions.length})`} />
          <Tab label={`History (${historySessions.length})`} />
        </Tabs>

        {loading ? (
          <Box sx={{ display: 'flex', justifyContent: 'center', py: 6 }}>
            <CircularProgress />
          </Box>
        ) : (
          <>
            <TabPanel value={tabIndex} index={0}>
              {renderSessionTable(activeSessions)}
            </TabPanel>
            <TabPanel value={tabIndex} index={1}>
              {renderSessionTable(historySessions)}
            </TabPanel>
          </>
        )}
      </Paper>

      <Dialog
        open={wizardOpen}
        onClose={wizardStep < 2 ? closeWizard : undefined}
        maxWidth="sm"
        fullWidth
      >
        <DialogTitle>New Verification Session</DialogTitle>
        <DialogContent>
          <Stepper activeStep={wizardStep} sx={{ mb: 3 }}>
            {WIZARD_STEPS.map((label) => (
              <Step key={label}>
                <StepLabel>{label}</StepLabel>
              </Step>
            ))}
          </Stepper>

          {wizardError && (
            <Alert severity="error" sx={{ mb: 2 }}>
              {wizardError}
            </Alert>
          )}

          {wizardStep === 0 && (
            <PolicySelectStep
              value={wizardData}
              onChange={setWizardData}
              organizationId={organizationId}
            />
          )}
          {wizardStep === 1 && (
            <SessionConfigStep
              value={wizardData}
              onChange={setWizardData}
            />
          )}
          {wizardStep === 2 && (
            <QRDisplayStep
              session={pendingSession}
              onComplete={handleVerificationComplete}
            />
          )}
        </DialogContent>
        <DialogActions>
          {wizardStep < 2 && (
            <Button onClick={closeWizard} disabled={wizardLoading}>
              Cancel
            </Button>
          )}
          {wizardStep > 0 && wizardStep < 2 && (
            <Button onClick={handleWizardBack} disabled={wizardLoading}>
              Back
            </Button>
          )}
          {wizardStep < 2 && (
            <Button
              variant="contained"
              onClick={handleWizardNext}
              disabled={
                wizardLoading ||
                (wizardStep === 0 && !wizardData.policy_id)
              }
              startIcon={wizardLoading ? <CircularProgress size={14} /> : null}
            >
              {wizardStep === 1 ? 'Start Session' : 'Next'}
            </Button>
          )}
          {wizardStep === 2 && (
            <Button variant="contained" onClick={closeWizard}>
              Done
            </Button>
          )}
        </DialogActions>
      </Dialog>

      <Dialog
        open={detailOpen}
        onClose={closeDetail}
        maxWidth="sm"
        fullWidth
      >
        <DialogTitle>
          Session Details
          {detailSession && (
            <Typography variant="caption" display="block" color="text.secondary">
              {detailSession.session_id}
            </Typography>
          )}
        </DialogTitle>
        <DialogContent>
          {detailSession && (
            <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
              <Box sx={{ display: 'flex', gap: 1 }}>
                <StatusChip status={detailSession.status} />
                {detailSession.purpose && (
                  <Typography variant="body2">{detailSession.purpose}</Typography>
                )}
              </Box>

              {normalizeSessionStatus(detailSession.status) === 'pending' && (detailSession.qr_code_data || detailSession.request_uri) && (
                <Box sx={{ display: 'flex', justifyContent: 'center' }}>
                  <Paper variant="outlined" sx={{ p: 2, background: '#fff', display: 'inline-block' }}>
                    <Oid4vpQrCode
                      value={detailSession.qr_code_data || detailSession.request_uri}
                      size={200}
                    />
                  </Paper>
                </Box>
              )}

              {normalizeSessionStatus(detailSession.status) !== 'pending' && (
                <VerificationResultSummary session={detailSession} />
              )}

              <Box>
                <Typography variant="caption" color="text.secondary">
                  Created: {formatDate(detailSession.created_at)}
                </Typography>
                <br />
                <Typography variant="caption" color="text.secondary">
                  Updated: {formatDate(detailSession.updated_at)}
                </Typography>
              </Box>
            </Box>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={closeDetail}>Close</Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
}

export default VerificationSessionManager;

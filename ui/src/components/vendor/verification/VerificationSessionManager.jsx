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
import { useAuth } from '../../../hooks/useAuth';
import { useNotifications } from '../../../hooks/useNotifications';
import {
  startVerificationSession,
  listVerificationSessions,
  getInspectionResult,
} from '../../../services/verificationApi';
import { startVerificationFlow } from '../../../services/zkVerificationApi';
import PolicySelectStep from './steps/PolicySelectStep';
import SessionConfigStep from './steps/SessionConfigStep';
import QRDisplayStep from './steps/QRDisplayStep';
import { formatOfficialReference } from '../../../utils/officialReferences';

const WIZARD_STEPS = ['Select Policy', 'Configure Session', 'Scan & Verify'];

const STATUS_CHIP = {
  pending:   { label: 'Pending',   color: 'warning', icon: <HourglassTopIcon sx={{ fontSize: 14 }} /> },
  completed: { label: 'Verified',  color: 'success', icon: <CheckCircleIcon  sx={{ fontSize: 14 }} /> },
  failed:    { label: 'Failed',    color: 'error',   icon: <ErrorIcon        sx={{ fontSize: 14 }} /> },
  expired:   { label: 'Expired',   color: 'default', icon: <ErrorIcon        sx={{ fontSize: 14 }} /> },
};

const ACTIVE_STATUSES   = ['pending'];
const HISTORY_STATUSES  = ['completed', 'failed', 'expired'];

function normalizeFlowSession(session) {
  if (!session?.instance_id) return session;
  return {
    ...session,
    session_id: session.instance_id,
    status: session.status === 'awaiting_wallet' ? 'pending' : session.status,
    dc_api_request_url: `/v1/flows/instances/${encodeURIComponent(session.instance_id)}/request?transport=dc_api`,
    dc_api_submit_url: `/v1/flows/instances/${encodeURIComponent(session.instance_id)}/submit/dc-api`,
  };
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function StatusChip({ status }) {
  const cfg = STATUS_CHIP[status] || { label: status, color: 'default' };
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

function VerificationSessionManager() {
  const { user } = useAuth();
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
  const [inspectionResult, setInspectionResult] = useState(null);
  const [inspectionLoading, setInspectionLoading] = useState(false);

  // ── Data fetching ─────────────────────────────────────────────────────────

  const fetchSessions = useCallback(async () => {
    if (!user?.organization_id) return;
    setLoading(true);
    setError(null);
    try {
      const data = await listVerificationSessions(user.organization_id);
      setSessions(data?.sessions || []);
    } catch (err) {
      setError(err.message || 'Failed to load verification sessions');
    } finally {
      setLoading(false);
    }
  }, [user?.organization_id]);

  useEffect(() => {
    fetchSessions();
  }, [fetchSessions]);

  // ── Filtered session lists ────────────────────────────────────────────────

  const activeSessions  = sessions.filter((s) => ACTIVE_STATUSES.includes(s.status));
  const historySessions = sessions.filter((s) => HISTORY_STATUSES.includes(s.status));

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
        let session;
        try {
          session = await startVerificationFlow({
            organization_id: user.organization_id,
            presentation_policy_id: wizardData.policy_id || undefined,
            external_reference: wizardData.purpose || undefined,
          });
          session = normalizeFlowSession(session);
        } catch {
          session = await startVerificationSession({
            organization_id: user.organization_id,
            policy_id: wizardData.policy_id || undefined,
            inline_policy: wizardData.inline_policy || undefined,
            purpose: wizardData.purpose || undefined,
            request_inspection: wizardData.request_inspection || false,
          });
        }
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
    setInspectionResult(null);
    setDetailOpen(true);

    if (session.inspection_performed) {
      setInspectionLoading(true);
      try {
        const ir = await getInspectionResult(session.session_id);
        setInspectionResult(ir);
      } catch {
        // inspection result not available — non-fatal
      } finally {
        setInspectionLoading(false);
      }
    }
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
                  {session.status === 'pending' && session.qr_code_data && (
                    <Tooltip title="Show QR code">
                      <IconButton size="small" onClick={() => openDetail(session)}>
                        <QrCode2Icon fontSize="small" />
                      </IconButton>
                    </Tooltip>
                  )}
                  {session.status !== 'pending' && (
                    <Tooltip title="View details">
                      <IconButton size="small" onClick={() => openDetail(session)}>
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
            <IconButton onClick={fetchSessions} disabled={loading}>
              <RefreshIcon />
            </IconButton>
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

              {detailSession.status === 'pending' && detailSession.qr_code_data && (
                <Box sx={{ display: 'flex', justifyContent: 'center' }}>
                  <Paper variant="outlined" sx={{ p: 2, background: '#fff', display: 'inline-block' }}>
                    <img
                      src={`data:image/png;base64,${detailSession.qr_code_data}`}
                      alt="OID4VP QR Code"
                      style={{ width: 200, height: 200, display: 'block' }}
                    />
                  </Paper>
                </Box>
              )}

              {detailSession.verified_claims &&
                Object.keys(detailSession.verified_claims).length > 0 && (
                  <Box>
                    <Typography variant="subtitle2" sx={{ mb: 1 }}>
                      Verified Claims
                    </Typography>
                    <Paper variant="outlined" sx={{ p: 1.5 }}>
                      {Object.entries(detailSession.verified_claims).map(([k, v]) => (
                        <Box
                          key={k}
                          sx={{ display: 'flex', gap: 1.5, py: 0.5 }}
                        >
                          <Typography
                            variant="body2"
                            sx={{ fontWeight: 600, minWidth: 140 }}
                          >
                            {k}
                          </Typography>
                          <Typography variant="body2" color="text.secondary">
                            {String(v)}
                          </Typography>
                        </Box>
                      ))}
                    </Paper>
                  </Box>
                )}

              {detailSession.inspection_performed && (
                <Box>
                  <Typography variant="subtitle2" sx={{ mb: 1 }}>
                    Document Inspection
                  </Typography>
                  {inspectionLoading ? (
                    <CircularProgress size={18} />
                  ) : inspectionResult ? (
                    <Paper variant="outlined" sx={{ p: 1.5 }}>
                      <Typography variant="body2" sx={{ whiteSpace: 'pre-wrap' }}>
                        {inspectionResult.inspection_result}
                      </Typography>
                    </Paper>
                  ) : (
                    <Alert severity="info" sx={{ mt: 0.5 }}>
                      Inspection result not available yet.
                    </Alert>
                  )}
                </Box>
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

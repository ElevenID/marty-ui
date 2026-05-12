/**
 * Flow Manager Component
 * 
 * Manages digital identity flows (issuance + presentation orchestration).
 * Provides flow creation, execution monitoring, approval queue, and batch revocation.
 */

import { useState, useEffect, useCallback, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
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
  Checkbox,
  Tooltip,
} from '@mui/material';
import AddIcon from '@mui/icons-material/Add';
import PlayArrowIcon from '@mui/icons-material/PlayArrow';
import PreviewIcon from '@mui/icons-material/Preview';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import CancelIcon from '@mui/icons-material/Cancel';
import RefreshIcon from '@mui/icons-material/Refresh';
import WarningIcon from '@mui/icons-material/Warning';
import BatchPredictionIcon from '@mui/icons-material/BatchPrediction';
import LinkIcon from '@mui/icons-material/Link';
import QrCode2Icon from '@mui/icons-material/QrCode2';
import AppleIcon from '@mui/icons-material/Apple';
import AndroidIcon from '@mui/icons-material/Android';
import AccountTreeIcon from '@mui/icons-material/AccountTree';

import { useAuth } from '../../hooks/useAuth';
import { useNotifications } from '../../hooks/useNotifications';
import flowsApi, { FLOW_STATES } from '../../services/flowsApi';
import credentialsApi from '../../services/credentialsApi';
import sseService, { EVENT_TYPES } from '../../services/sseService';
import { listTrustProfiles, listCredentialTemplates } from '../../services/presentationPolicyApi';
import { listDeploymentProfiles } from '../../services/deploymentProfilesApi';
import { formatOfficialReference, formatStructuredIdentifiers } from '../../utils/officialReferences';
import {
  approveFlowManagerExecution,
  batchRevokeFlowManagerCredentials,
  getApprovalStrategyPresentation,
  getCredentialSelectionState,
  getFlowStatusPresentation,
  loadFlowManagerCredentials,
  loadFlowManagerExecutions,
  loadFlowManagerFlows,
  loadFlowManagerRevocationBatches,
  getPendingExecutions,
  startFlowManagerRealtimeUpdates,
  toggleAllCredentialSelections,
  toggleCredentialSelection,
} from '../../application/flows';
import FlowPublishDialog from './FlowPublishDialog';
import FlowDisableDialog from './FlowDisableDialog';
import { EmptyState } from '../common';

const FlowManager = ({ hideHeader = false }) => {
  const { t } = useTranslation(['vendor', 'common']);
  const { user } = useAuth();
  const { showSuccess, showError, showWarning } = useNotifications();
  const navigate = useNavigate();
  const [activeTab, setActiveTab] = useState(0);
  const [flows, setFlows] = useState([]);
  const [executions, setExecutions] = useState([]);
  const [credentials, setCredentials] = useState([]);
  const [revocationBatches, setRevocationBatches] = useState([]);
  const [credentialsLoaded, setCredentialsLoaded] = useState(false);
  const [revocationBatchesLoaded, setRevocationBatchesLoaded] = useState(false);
  // Ref instead of state: these flags are only read inside callbacks (never rendered),
  // so using state would recreate callbacks on every fetch → infinite loop.
  const unsupportedEndpointsRef = useRef({
    flows: false,
    executions: false,
    credentials: false,
    revocationBatches: false,
  });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [prereqStatus, setPrereqStatus] = useState({
    trustProfile: 'loading',
    template: 'loading',
    deployment: 'loading',
  });
  
  // Dialog states
  const [revocationDialog, setRevocationDialog] = useState(false);
  const [selectedCredentials, setSelectedCredentials] = useState([]);
  const [publishDialog, setPublishDialog] = useState(false);
  const [disableDialog, setDisableDialog] = useState(false);
  const [selectedFlow, setSelectedFlow] = useState(null);
  const pendingExecutions = getPendingExecutions(executions);
  const credentialSelectionState = getCredentialSelectionState(credentials, selectedCredentials);

  const showNotification = useCallback((notification) => {
    if (!notification) return;

    if (notification.type === 'success') {
      showSuccess(notification.message, notification.options);
    } else if (notification.type === 'warning') {
      showWarning(notification.message, notification.options);
    } else if (notification.type === 'error') {
      showError(notification.message, notification.options);
    }
  }, [showError, showSuccess, showWarning]);

  // Load data
  const loadFlows = useCallback(async () => {
    if (unsupportedEndpointsRef.current.flows) {
      setFlows([]);
      setError(null);
      return;
    }

    const result = await loadFlowManagerFlows({
      listFlows: flowsApi.listFlows,
      organizationId: user?.organization_id,
    });
    setFlows(result.flows);
    setError(result.error);
    unsupportedEndpointsRef.current.flows = Boolean(result.unsupported);
    showNotification(result.notification);
  }, [showNotification, user?.organization_id]);

  const loadExecutions = useCallback(async (flowId = null) => {
    if (unsupportedEndpointsRef.current.executions) {
      setExecutions([]);
      return;
    }

    const result = await loadFlowManagerExecutions({
      listFlowExecutions: flowsApi.listFlowExecutions,
      organizationId: user?.organization_id,
      flows,
      flowId,
    });
    setExecutions(result.executions);
    unsupportedEndpointsRef.current.executions = Boolean(result.unsupported);
    showNotification(result.notification);
  }, [flows, showNotification, user?.organization_id]);

  const loadCredentials = useCallback(async () => {
    if (unsupportedEndpointsRef.current.credentials) {
      setCredentials([]);
      setCredentialsLoaded(true);
      return;
    }

    const result = await loadFlowManagerCredentials({
      listCredentials: credentialsApi.listCredentials,
      organizationId: user?.organization_id,
    });
    setCredentials(result.credentials);
    setCredentialsLoaded(true);
    unsupportedEndpointsRef.current.credentials = Boolean(result.unsupported);
    showNotification(result.notification);
  }, [showNotification, user?.organization_id]);

  const loadRevocationBatches = useCallback(async () => {
    if (unsupportedEndpointsRef.current.revocationBatches) {
      setRevocationBatches([]);
      setRevocationBatchesLoaded(true);
      return;
    }

    const result = await loadFlowManagerRevocationBatches({
      listRevocationBatches: credentialsApi.listRevocationBatches,
      organizationId: user?.organization_id,
    });
    setRevocationBatches(result.revocationBatches);
    setRevocationBatchesLoaded(true);
    unsupportedEndpointsRef.current.revocationBatches = Boolean(result.unsupported);
    showNotification(result.notification);
  }, [showNotification, user?.organization_id]);

  useEffect(() => {
    const loadAllData = async () => {
      setLoading(true);
      const [, trustProfilesResult, templatesResult, deploymentsResult] = await Promise.all([
        loadFlows(),
        listTrustProfiles({ organization_id: user?.organization_id }).catch(() => []),
        listCredentialTemplates({ organization_id: user?.organization_id }).catch(() => []),
        listDeploymentProfiles({ organization_id: user?.organization_id }).catch(() => []),
      ]);
      setPrereqStatus({
        trustProfile: (trustProfilesResult?.length > 0) ? 'ready' : 'missing',
        template: (templatesResult?.length > 0) ? 'ready' : 'missing',
        deployment: (deploymentsResult?.length > 0) ? 'ready' : 'missing',
      });
      setLoading(false);
    };
    loadAllData();
  }, [loadFlows, user?.organization_id]);

  useEffect(() => {
    loadExecutions();
  }, [flows, loadExecutions]);

  useEffect(() => {
    if ((activeTab === 3 || activeTab === 4) && !credentialsLoaded) {
      loadCredentials();
    }

    if (activeTab === 4 && !revocationBatchesLoaded) {
      loadRevocationBatches();
    }
  }, [
    activeTab,
    credentialsLoaded,
    revocationBatchesLoaded,
    loadCredentials,
    loadRevocationBatches,
  ]);

  // SSE real-time updates
  useEffect(() => {
    return startFlowManagerRealtimeUpdates({
      sseService,
      eventTypes: EVENT_TYPES,
      organizationId: user?.organization_id,
      loadExecutions,
      loadCredentials,
      loadRevocationBatches,
      showSuccess,
    });
  }, [user, loadExecutions, loadCredentials, loadRevocationBatches]);

  // Handle approval
  const handleApprove = async (execution) => {
    try {
      const result = await approveFlowManagerExecution({
        approveFlowExecution: flowsApi.approveFlowExecution,
        execution,
        user,
      });
      showNotification(result.notification);
      if (result.shouldReloadExecutions) {
        loadExecutions();
      }
    } catch (err) {
      showError(`Failed to approve: ${err.message}`);
    }
  };

  // Handle batch revocation
  const handleBatchRevoke = async (strategy) => {
    try {
      const result = await batchRevokeFlowManagerCredentials({
        batchRevokeCredentials: credentialsApi.batchRevokeCredentials,
        selectedCredentials,
        strategy,
      });
      setRevocationDialog(result.revocationDialog);
      setSelectedCredentials(result.selectedCredentials);
      showNotification(result.notification);
      if (result.shouldReloadCredentials) {
        loadCredentials();
      }
      if (result.shouldReloadRevocationBatches) {
        loadRevocationBatches();
      }
    } catch (err) {
      showError(`Batch revocation failed: ${err.message}`);
    }
  };

  const getStatusColor = (status) => {
    const colors = {
      'active': 'success',
      'completed': 'success',
      'pending': 'warning',
      'processing': 'info',
      'failed': 'error',
      'revoked': 'error',
      'expired': 'default',
    };
    return colors[status?.toLowerCase()] || 'default';
  };

  const formatFlowExecutionReference = (value) => formatOfficialReference(value, 'flow');
  const formatCredentialReference = (value) => formatOfficialReference(value, 'credential');
  const formatTemplateReference = (value) => formatOfficialReference(value, 'template');
  const formatBatchReference = (value) => formatOfficialReference(value, 'record');
  const formatFlowContextPreview = (context) => {
    if (!context) return '—';
    const serialized = JSON.stringify(formatStructuredIdentifiers(context));
    return serialized.length > 50 ? `${serialized.substring(0, 50)}...` : serialized;
  };

  if (loading) {
    return (
      <Box display="flex" justifyContent="center" alignItems="center" minHeight="400px">
        <CircularProgress />
      </Box>
    );
  }

  return (
    <Box>
      {!hideHeader && (
        <Box display="flex" justifyContent="space-between" alignItems="center" mb={3}>
          <Typography variant="h4">{t('flowManager.title')}</Typography>
          <Button
            variant="contained"
            color="primary"
            startIcon={<AddIcon />}
          >
            {t('flowManager.createFlow')}
          </Button>
        </Box>
      )}

      {error && (
        <Alert severity="error" sx={{ mb: 2 }} onClose={() => setError(null)}>
          {error}
        </Alert>
      )}

      <Paper sx={{ mb: 3 }}>
        <Tabs value={activeTab} onChange={(e, v) => setActiveTab(v)}>
          <Tab label={t('flowManager.tabs.flows')} />
          <Tab label={t('flowManager.tabs.executions')} />
          <Tab label={t('flowManager.tabs.approvals')} />
          <Tab label={t('flowManager.tabs.credentials')} />
          <Tab label={t('flowManager.tabs.revocations')} />
        </Tabs>

        {/* Flows Tab */}
        {activeTab === 0 && (
          <Box p={2}>
            {flows.length === 0 ? (
              <EmptyState
                icon={AccountTreeIcon}
                title="Issuance Flows connect applicants to credentials"
                description="To create one, you'll need:"
                actionLabel="Create Issuance Flow"
                onAction={() => navigate('/console/org/flows/definitions/new')}
                prerequisites={[
                  { 
                    label: 'Trust Profile', 
                    status: prereqStatus.trustProfile,
                    path: '/console/org/trust/profiles' 
                  },
                  { 
                    label: 'Credential Template', 
                    status: prereqStatus.template,
                    path: '/console/org/templates/credentials' 
                  },
                  { 
                    label: 'Deployment Profile', 
                    status: prereqStatus.deployment,
                    path: '/console/org/deploy/profiles' 
                  },
                ]}
                whyItMatters="Flows are the applicant-facing product. Templates are just inputs."
              />
            ) : (
            <TableContainer>
              <Table>
                <TableHead>
                  <TableRow>
                    <TableCell>Name</TableCell>
                    <TableCell>Status</TableCell>
                    <TableCell>Credential</TableCell>
                    <TableCell>Applicant Entry</TableCell>
                    <TableCell>Approval Mode</TableCell>
                    <TableCell>Wallet Targets</TableCell>
                    <TableCell align="right">Actions</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {flows.map((flow) => {
                    const statusPresentation = getFlowStatusPresentation(flow.status, FLOW_STATES);
                    const approvalPresentation = getApprovalStrategyPresentation(flow.approval_strategy);
                    
                    return (
                    <TableRow 
                      key={flow.id}
                      hover
                      sx={{ 
                        cursor: 'pointer',
                        '&:hover': {
                          bgcolor: 'action.hover',
                        },
                      }}
                      onClick={() => navigate(`/console/org/flows/definitions/${flow.id}`)}
                    >
                      <TableCell>
                        <Typography variant="body2" fontWeight={500}>
                          {flow.name}
                        </Typography>
                        <Typography variant="caption" color="text.secondary">
                          {flow.flow_type}
                        </Typography>
                      </TableCell>
                      <TableCell>
                        <Chip 
                          label={statusPresentation.label}
                          color={statusPresentation.color}
                          size="small"
                          icon={statusPresentation.icon === 'warning' ? <WarningIcon /> : statusPresentation.icon === 'success' ? <CheckCircleIcon /> : <CancelIcon />}
                        />
                      </TableCell>
                      <TableCell>
                        <Typography variant="body2">
                          {flow.credential_template_name || 'Not configured'}
                        </Typography>
                      </TableCell>
                      <TableCell>
                        {statusPresentation.hasApplicantEntry ? (
                          <Box sx={{ display: 'flex', gap: 1 }}>
                            <Tooltip title="Application URL available">
                              <Chip 
                                icon={<LinkIcon />} 
                                label="URL" 
                                size="small" 
                                color="primary"
                                variant="outlined"
                              />
                            </Tooltip>
                            <Tooltip title="QR code available">
                              <Chip 
                                icon={<QrCode2Icon />} 
                                label="QR" 
                                size="small" 
                                color="primary"
                                variant="outlined"
                              />
                            </Tooltip>
                          </Box>
                        ) : (
                          <Chip label="Not Published" size="small" variant="outlined" />
                        )}
                      </TableCell>
                      <TableCell>
                        <Chip 
                          label={approvalPresentation.label}
                          size="small"
                          color={approvalPresentation.color}
                          variant="outlined"
                        />
                      </TableCell>
                      <TableCell>
                        <Box sx={{ display: 'flex', gap: 0.5 }}>
                          <Tooltip title="Apple Wallet">
                            <AppleIcon fontSize="small" color="action" />
                          </Tooltip>
                          <Tooltip title="Google Wallet">
                            <AndroidIcon fontSize="small" color="action" />
                          </Tooltip>
                        </Box>
                      </TableCell>
                      <TableCell align="right" onClick={(e) => e.stopPropagation()}>
                        {statusPresentation.isDraft && (
                          <Tooltip title="Publish Flow">
                            <IconButton
                              size="small"
                              color="success"
                              onClick={() => {
                                setSelectedFlow(flow);
                                setPublishDialog(true);
                              }}
                            >
                              <CheckCircleIcon />
                            </IconButton>
                          </Tooltip>
                        )}
                        {statusPresentation.isPublished && (
                          <Tooltip title="Disable Flow">
                            <IconButton
                              size="small"
                              color="error"
                              onClick={() => {
                                setSelectedFlow(flow);
                                setDisableDialog(true);
                              }}
                            >
                              <CancelIcon />
                            </IconButton>
                          </Tooltip>
                        )}
                      </TableCell>
                    </TableRow>
                    );
                  })}
                </TableBody>
              </Table>
            </TableContainer>
            )}
          </Box>
        )}

        {/* Executions Tab */}
        {activeTab === 1 && (
          <Box p={2}>
            <Box display="flex" justifyContent="flex-end" mb={2}>
              <Button
                startIcon={<RefreshIcon />}
                onClick={loadExecutions}
              >
                Refresh
              </Button>
            </Box>
            <TableContainer>
              <Table>
                <TableHead>
                  <TableRow>
                    <TableCell>Execution Reference</TableCell>
                    <TableCell>Flow Reference</TableCell>
                    <TableCell>Status</TableCell>
                    <TableCell>Current Step</TableCell>
                    <TableCell>Started At</TableCell>
                    <TableCell align="right">Actions</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {executions.map((exec) => (
                    <TableRow key={exec.id}>
                      <TableCell>{formatFlowExecutionReference(exec.id)}</TableCell>
                      <TableCell>{exec.flow_id}</TableCell>
                      <TableCell>
                        <Chip label={exec.status} color={getStatusColor(exec.status)} size="small" />
                      </TableCell>
                      <TableCell>{exec.current_step || 'N/A'}</TableCell>
                      <TableCell>{new Date(exec.started_at).toLocaleString()}</TableCell>
                      <TableCell align="right">
                        {exec.status === 'pending' && (
                          <Tooltip title="View Details">
                            <IconButton
                              size="small"
                            >
                              <CheckCircleIcon />
                            </IconButton>
                          </Tooltip>
                        )}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          </Box>
        )}

        {/* Approval Queue Tab */}
        {activeTab === 2 && (
          <Box p={2}>
            <Typography variant="body2" color="text.secondary" mb={2}>
              Executions awaiting manual approval
            </Typography>
            <TableContainer>
              <Table>
                <TableHead>
                  <TableRow>
                    <TableCell>Execution Reference</TableCell>
                    <TableCell>Flow</TableCell>
                    <TableCell>Context</TableCell>
                    <TableCell>Started At</TableCell>
                    <TableCell align="right">Actions</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {pendingExecutions.map((exec) => (
                    <TableRow key={exec.id}>
                      <TableCell>{formatFlowExecutionReference(exec.id)}</TableCell>
                      <TableCell>{formatFlowExecutionReference(exec.flow_id)}</TableCell>
                      <TableCell>
                        <Typography variant="caption">
                          {formatFlowContextPreview(exec.context)}
                        </Typography>
                      </TableCell>
                      <TableCell>{new Date(exec.started_at).toLocaleString()}</TableCell>
                      <TableCell align="right">
                        <Tooltip title="Approve">
                          <IconButton
                            size="small"
                            color="success"
                            onClick={() => handleApprove(exec)}
                          >
                            <CheckCircleIcon />
                          </IconButton>
                        </Tooltip>
                        <Tooltip title="Reject">
                          <IconButton
                            size="small"
                            color="error"
                          >
                            <CancelIcon />
                          </IconButton>
                        </Tooltip>
                      </TableCell>
                    </TableRow>
                  ))}
                  {pendingExecutions.length === 0 && (
                    <TableRow>
                      <TableCell colSpan={5} align="center">
                        <Typography color="text.secondary">No pending approvals</Typography>
                      </TableCell>
                    </TableRow>
                  )}
                </TableBody>
              </Table>
            </TableContainer>
          </Box>
        )}

        {/* Credentials Tab */}
        {activeTab === 3 && (
          <Box p={2}>
            <Box display="flex" justifyContent="space-between" mb={2}>
              <Typography variant="body2" color="text.secondary">
                {selectedCredentials.length} credential(s) selected
              </Typography>
              <Box>
                <Button
                  variant="outlined"
                  color="error"
                  startIcon={<BatchPredictionIcon />}
                  disabled={selectedCredentials.length === 0}
                  onClick={() => setRevocationDialog(true)}
                  sx={{ mr: 1 }}
                >
                  Batch Revoke
                </Button>
                <Button startIcon={<RefreshIcon />} onClick={loadCredentials}>
                  Refresh
                </Button>
              </Box>
            </Box>
            <TableContainer>
              <Table>
                <TableHead>
                  <TableRow>
                    <TableCell padding="checkbox">
                      <Checkbox
                        checked={credentialSelectionState.allSelected}
                        indeterminate={credentialSelectionState.partiallySelected}
                        onChange={(e) => {
                          setSelectedCredentials(toggleAllCredentialSelections(credentials, e.target.checked));
                        }}
                      />
                    </TableCell>
                    <TableCell>Credential Reference</TableCell>
                    <TableCell>Template Reference</TableCell>
                    <TableCell>Status</TableCell>
                    <TableCell>Issued At</TableCell>
                    <TableCell>Expires At</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {credentials.map((cred) => (
                    <TableRow key={cred.id}>
                      <TableCell padding="checkbox">
                        <Checkbox
                          checked={selectedCredentials.includes(cred.id)}
                          onChange={(e) => {
                            setSelectedCredentials(toggleCredentialSelection(selectedCredentials, cred.id, e.target.checked));
                          }}
                          disabled={cred.status !== 'active'}
                        />
                      </TableCell>
                      <TableCell>{formatCredentialReference(cred.id)}</TableCell>
                      <TableCell>{formatTemplateReference(cred.credential_template_id)}</TableCell>
                      <TableCell>
                        <Chip label={cred.status} color={getStatusColor(cred.status)} size="small" />
                      </TableCell>
                      <TableCell>{new Date(cred.issued_at).toLocaleString()}</TableCell>
                      <TableCell>
                        {cred.expires_at ? new Date(cred.expires_at).toLocaleString() : 'No expiry'}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          </Box>
        )}

        {/* Revocation Batches Tab */}
        {activeTab === 4 && (
          <Box p={2}>
            <Box display="flex" justifyContent="flex-end" mb={2}>
              <Button startIcon={<RefreshIcon />} onClick={loadRevocationBatches}>
                Refresh
              </Button>
            </Box>
            <TableContainer>
              <Table>
                <TableHead>
                  <TableRow>
                    <TableCell>Batch Reference</TableCell>
                    <TableCell>Credential Count</TableCell>
                    <TableCell>Status</TableCell>
                    <TableCell>Interval</TableCell>
                    <TableCell>Scheduled For</TableCell>
                    <TableCell>Completed At</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {revocationBatches.map((batch) => (
                    <TableRow key={batch.batch_id}>
                      <TableCell>{formatBatchReference(batch.batch_id)}</TableCell>
                      <TableCell>{batch.credential_count}</TableCell>
                      <TableCell>
                        <Chip label={batch.status} color={getStatusColor(batch.status)} size="small" />
                      </TableCell>
                      <TableCell>{batch.revocation_interval}</TableCell>
                      <TableCell>
                        {batch.scheduled_for ? new Date(batch.scheduled_for).toLocaleString() : 'N/A'}
                      </TableCell>
                      <TableCell>
                        {batch.completed_at ? new Date(batch.completed_at).toLocaleString() : 'N/A'}
                      </TableCell>
                    </TableRow>
                  ))}
                  {revocationBatches.length === 0 && (
                    <TableRow>
                      <TableCell colSpan={6} align="center">
                        <Typography color="text.secondary">No revocation batches</Typography>
                      </TableCell>
                    </TableRow>
                  )}
                </TableBody>
              </Table>
            </TableContainer>
          </Box>
        )}
      </Paper>

      {/* Batch Revocation Dialog */}
      <Dialog open={revocationDialog} onClose={() => setRevocationDialog(false)} maxWidth="sm" fullWidth>
        <DialogTitle>Batch Revoke Credentials</DialogTitle>
        <DialogContent>
          <Alert severity="info" sx={{ mb: 2 }}>
            {selectedCredentials.length} credential(s) selected for revocation
          </Alert>
          <Alert severity="warning" icon={<WarningIcon />} sx={{ mb: 2 }}>
            <Typography variant="subtitle2">Privacy Notice</Typography>
            <Typography variant="body2">
              Immediate revocation reveals which specific credential was revoked.
              Scheduled batch revocation (following W3C recommendations) protects holder privacy
              by grouping revocations together.
            </Typography>
          </Alert>
          <Typography variant="body2" color="text.secondary" mt={2}>
            Choose revocation strategy:
          </Typography>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setRevocationDialog(false)}>Cancel</Button>
          <Button
            variant="outlined"
            color="warning"
            onClick={() => handleBatchRevoke('immediate')}
          >
            Immediate (Privacy Warning)
          </Button>
          <Button
            variant="contained"
            color="primary"
            onClick={() => handleBatchRevoke('scheduled')}
          >
            Scheduled Batch (Recommended)
          </Button>
        </DialogActions>
      </Dialog>


      {/* Flow Publish Dialog */}
      <FlowPublishDialog
        open={publishDialog}
        onClose={() => {
          setPublishDialog(false);
          setSelectedFlow(null);
        }}
        flow={selectedFlow}
        onPublished={(updatedFlow) => {
          loadFlows();
          showSuccess(`Flow "${updatedFlow.name}" published successfully!`);
        }}
      />

      {/* Flow Disable Dialog */}
      <FlowDisableDialog
        open={disableDialog}
        onClose={() => {
          setDisableDialog(false);
          setSelectedFlow(null);
        }}
        flow={selectedFlow}
        onDisabled={(updatedFlow) => {
          loadFlows();
          showSuccess(`Flow "${updatedFlow.name}" disabled successfully.`);
        }}
      />
    </Box>
  );
};

export default FlowManager;

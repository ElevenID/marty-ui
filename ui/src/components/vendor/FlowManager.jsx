/**
 * Flow Manager Component
 * 
 * Manages digital identity flows (issuance + presentation orchestration).
 * Provides flow creation, execution monitoring, approval queue, and batch revocation.
 */

import { useState, useEffect, useCallback } from 'react';
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
import FlowPublishDialog from './FlowPublishDialog';
import FlowDisableDialog from './FlowDisableDialog';
import { EmptyState } from '../common';

const FlowManager = () => {
  const { t } = useTranslation(['vendor', 'common']);
  const { user } = useAuth();
  const { showSuccess, showError, showWarning } = useNotifications();
  const navigate = useNavigate();
  const [activeTab, setActiveTab] = useState(0);
  const [flows, setFlows] = useState([]);
  const [executions, setExecutions] = useState([]);
  const [credentials, setCredentials] = useState([]);
  const [revocationBatches, setRevocationBatches] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  
  // Dialog states
  const [revocationDialog, setRevocationDialog] = useState(false);
  const [selectedCredentials, setSelectedCredentials] = useState([]);
  const [publishDialog, setPublishDialog] = useState(false);
  const [disableDialog, setDisableDialog] = useState(false);
  const [selectedFlow, setSelectedFlow] = useState(null);

  // Load data
  const loadFlows = useCallback(async () => {
    try {
      const data = await flowsApi.listFlows({ limit: 100 });
      setFlows(data);
      setError(null);
    } catch (err) {
      console.error('Failed to load flows:', err);
      showWarning('Backend service unavailable - showing sample data for testing', {
        autoHideDuration: 8000,
      });
      // Use mock data for development/testing when API fails
      setFlows([
        {
          id: 'flow-1',
          name: 'EU Digital Identity – Employee Issuance',
          flow_type: 'issuance',
          status: 'PUBLISHED',
          approval_strategy: 'manual',
          credential_template_name: 'EU Digital Identity Credential',
          credential_template_id: 'ct-1',
        },
        {
          id: 'flow-2',
          name: 'Mobile Driver License Issuance',
          flow_type: 'issuance',
          status: 'DRAFT',
          approval_strategy: 'auto',
          credential_template_name: 'Mobile Driving License',
          credential_template_id: 'ct-2',
        },
      ]);
      setError(null); // Clear error since we're using mock data
    }
  }, [showWarning]);

  const loadExecutions = useCallback(async (flowId = null) => {
    try {
      if (flowId) {
        const data = await flowsApi.listFlowExecutions(flowId, { limit: 50 });
        setExecutions(data);
      } else if (flows.length > 0) {
        // Load executions for all flows
        const allExecutions = [];
        for (const flow of flows) {
          const data = await flowsApi.listFlowExecutions(flow.id, { limit: 10 });
          allExecutions.push(...data);
        }
        setExecutions(allExecutions);
      }
    } catch (err) {
      console.error('Failed to load executions:', err);
      showError('Unable to load flow executions', {
        details: 'The backend service may be unavailable. Check console for details.',
      });
      setExecutions([]); // Use empty array on error
    }
  }, [flows, showError]);

  const loadCredentials = useCallback(async () => {
    try {
      const data = await credentialsApi.listCredentials({ limit: 100 });
      setCredentials(data);
    } catch (err) {
      console.error('Failed to load credentials:', err);
      showError('Unable to load credentials', {
        details: 'The backend service may be unavailable. Check console for details.',
      });
      setCredentials([]); // Use empty array on error
    }
  }, [showError]);

  const loadRevocationBatches = useCallback(async () => {
    try {
      const data = await credentialsApi.listRevocationBatches();
      setRevocationBatches(data);
    } catch (err) {
      console.error('Failed to load revocation batches:', err);
      showError('Unable to load revocation batches', {
        details: 'The backend service may be unavailable. Check console for details.',
      });
      setRevocationBatches([]); // Use empty array on error
    }
  }, [showError]);

  useEffect(() => {
    const loadAllData = async () => {
      setLoading(true);
      await Promise.all([
        loadFlows(),
        loadCredentials(),
        loadRevocationBatches(),
      ]);
      setLoading(false);
    };
    loadAllData();
  }, [loadFlows, loadCredentials, loadRevocationBatches]);

  useEffect(() => {
    loadExecutions();
  }, [flows, loadExecutions]);

  // SSE real-time updates
  useEffect(() => {
    if (!user?.organization_id) return;

    // Connect to SSE with organization filter
    sseService.connect({
      organizationId: user.organization_id,
      subscriptions: [
        EVENT_TYPES.FLOW_EXECUTION_STARTED,
        EVENT_TYPES.FLOW_EXECUTION_COMPLETED,
        EVENT_TYPES.APPLICATION_APPROVED,
        EVENT_TYPES.CREDENTIAL_ISSUED,
        EVENT_TYPES.CREDENTIAL_REVOKED,
        EVENT_TYPES.REVOCATION_BATCH_COMPLETED,
      ],
    });

    // Set up event listeners
    const unsubscribers = [
      sseService.on(EVENT_TYPES.FLOW_EXECUTION_STARTED, (data) => {
        console.log('Flow execution started:', data);
        loadExecutions();
        showSuccess(`Flow execution started: ${data.flow_id}`);
      }),
      
      sseService.on(EVENT_TYPES.FLOW_EXECUTION_COMPLETED, (data) => {
        console.log('Flow execution completed:', data);
        loadExecutions();
        showSuccess(`Flow execution completed: ${data.execution_id}`);
      }),
      
      sseService.on(EVENT_TYPES.APPLICATION_APPROVED, (data) => {
        console.log('Application approved:', data);
        loadExecutions();
      }),
      
      sseService.on(EVENT_TYPES.CREDENTIAL_ISSUED, (data) => {
        console.log('Credential issued:', data);
        loadCredentials();
        showSuccess(`Credential issued: ${data.credential_id}`);
      }),
      
      sseService.on(EVENT_TYPES.CREDENTIAL_REVOKED, (data) => {
        console.log('Credential revoked:', data);
        loadCredentials();
        loadRevocationBatches();
      }),
      
      sseService.on(EVENT_TYPES.REVOCATION_BATCH_COMPLETED, (data) => {
        console.log('Revocation batch completed:', data);
        loadRevocationBatches();
        loadCredentials();
        showSuccess(`Revocation batch completed: ${data.credential_count} credentials`);
      }),
    ];

    // Cleanup
    return () => {
      unsubscribers.forEach(unsub => unsub());
      sseService.disconnect();
    };
  }, [user, loadExecutions, loadCredentials, loadRevocationBatches]);

  // Handle approval
  const handleApprove = async (execution) => {
    try {
      await flowsApi.approveFlowExecution(
        execution.flow_id,
        execution.id,
        { approver_id: user.id, notes: 'Approved via UI' }
      );
      showSuccess('Execution approved');
      loadExecutions();
    } catch (err) {
      showError(`Failed to approve: ${err.message}`);
    }
  };

  // Handle batch revocation
  const handleBatchRevoke = async (strategy) => {
    if (selectedCredentials.length === 0) {
      showWarning('No credentials selected');
      return;
    }

    try {
      await credentialsApi.batchRevokeCredentials(selectedCredentials, {
        revocation_strategy: strategy,
        revocation_reason: 'Batch revocation via UI',
      });
      
      setRevocationDialog(false);
      setSelectedCredentials([]);
      
      const message = strategy === 'immediate'
        ? `${selectedCredentials.length} credentials revoked immediately`
        : `${selectedCredentials.length} credentials queued for batch revocation`;
      
      if (strategy === 'immediate') {
        showWarning(message);
      } else {
        showSuccess(message);
      }
      
      loadCredentials();
      loadRevocationBatches();
    } catch (err) {
      showError(`Batch revocation failed: ${err.message}`);
    }
  };

  // Get status color
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

  if (loading) {
    return (
      <Box display="flex" justifyContent="center" alignItems="center" minHeight="400px">
        <CircularProgress />
      </Box>
    );
  }

  return (
    <Box>
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
                    status: 'ready', // TODO: Wire up actual status from API
                    path: '/console/org/trust/profiles' 
                  },
                  { 
                    label: 'Credential Template', 
                    status: 'ready', // TODO: Wire up actual status from API
                    path: '/console/org/templates/credentials' 
                  },
                  { 
                    label: 'Deployment Profile', 
                    status: 'ready', // TODO: Wire up actual status from API
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
                    const flowStatus = flow.status || FLOW_STATES.DRAFT;
                    const isDraft = flowStatus === FLOW_STATES.DRAFT;
                    const isPublished = flowStatus === FLOW_STATES.PUBLISHED;
                    const isDisabled = flowStatus === FLOW_STATES.DISABLED;
                    
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
                          label={flowStatus.charAt(0).toUpperCase() + flowStatus.slice(1)} 
                          color={isDraft ? 'default' : isPublished ? 'success' : 'error'} 
                          size="small"
                          icon={isDraft ? <WarningIcon /> : isPublished ? <CheckCircleIcon /> : <CancelIcon />}
                        />
                      </TableCell>
                      <TableCell>
                        <Typography variant="body2">
                          {flow.credential_template_name || 'Not configured'}
                        </Typography>
                      </TableCell>
                      <TableCell>
                        {isPublished ? (
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
                          label={flow.approval_strategy === 'auto' ? 'Auto' : 'Manual'} 
                          size="small"
                          color={flow.approval_strategy === 'auto' ? 'success' : 'warning'}
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
                        {isDraft && (
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
                        {isPublished && (
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
                    <TableCell>Execution ID</TableCell>
                    <TableCell>Flow</TableCell>
                    <TableCell>Status</TableCell>
                    <TableCell>Current Step</TableCell>
                    <TableCell>Started At</TableCell>
                    <TableCell align="right">Actions</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {executions.map((exec) => (
                    <TableRow key={exec.id}>
                      <TableCell>{exec.id.substring(0, 8)}</TableCell>
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
                    <TableCell>Execution ID</TableCell>
                    <TableCell>Flow</TableCell>
                    <TableCell>Context</TableCell>
                    <TableCell>Started At</TableCell>
                    <TableCell align="right">Actions</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {executions.filter(e => e.status === 'pending').map((exec) => (
                    <TableRow key={exec.id}>
                      <TableCell>{exec.id.substring(0, 8)}</TableCell>
                      <TableCell>{exec.flow_id}</TableCell>
                      <TableCell>
                        <Typography variant="caption">
                          {JSON.stringify(exec.context).substring(0, 50)}...
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
                  {executions.filter(e => e.status === 'pending').length === 0 && (
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
                        checked={selectedCredentials.length === credentials.length && credentials.length > 0}
                        indeterminate={selectedCredentials.length > 0 && selectedCredentials.length < credentials.length}
                        onChange={(e) => {
                          if (e.target.checked) {
                            setSelectedCredentials(credentials.map(c => c.id));
                          } else {
                            setSelectedCredentials([]);
                          }
                        }}
                      />
                    </TableCell>
                    <TableCell>Credential ID</TableCell>
                    <TableCell>Template</TableCell>
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
                            if (e.target.checked) {
                              setSelectedCredentials([...selectedCredentials, cred.id]);
                            } else {
                              setSelectedCredentials(selectedCredentials.filter(id => id !== cred.id));
                            }
                          }}
                          disabled={cred.status !== 'active'}
                        />
                      </TableCell>
                      <TableCell>{cred.id.substring(0, 12)}...</TableCell>
                      <TableCell>{cred.credential_template_id.substring(0, 12)}...</TableCell>
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
                    <TableCell>Batch ID</TableCell>
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
                      <TableCell>{batch.batch_id.substring(0, 12)}...</TableCell>
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

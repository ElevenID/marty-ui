/**
 * Issued Credentials Page
 *
 * Org-console lifecycle view for already issued credentials.
 */

import { useEffect, useMemo, useState } from 'react';
import {
  Alert,
  Box,
  Button,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  InputAdornment,
  LinearProgress,
  Paper,
  Stack,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  TextField,
  Typography,
} from '@mui/material';
import SearchIcon from '@mui/icons-material/Search';
import VisibilityIcon from '@mui/icons-material/Visibility';
import RefreshIcon from '@mui/icons-material/Refresh';
import AutorenewIcon from '@mui/icons-material/Autorenew';
import ContentCopyIcon from '@mui/icons-material/ContentCopy';
import OpenInNewIcon from '@mui/icons-material/OpenInNew';
import BlockIcon from '@mui/icons-material/Block';
import HistoryIcon from '@mui/icons-material/History';
import PauseCircleOutlineIcon from '@mui/icons-material/PauseCircleOutlined';
import PlayCircleOutlineIcon from '@mui/icons-material/PlayCircleOutlined';
import { useNavigate, useParams } from 'react-router';
import { useTranslation } from 'react-i18next';
import { useConsole } from '../../../contexts/ConsoleContext';
import { useAsyncData } from '../../../hooks/useAsyncData';
import { useNotifications } from '../../../hooks/useNotifications';
import {
  fetchIssuedCredentials,
  renewCredential,
  reinstateCredential,
  revokeCredential,
  suspendCredential,
} from '../../../application/vendor';
import { listCredentialTemplates } from '../../../services/presentationPolicyApi';
import { pickOfficialReference } from '../../../utils/officialReferences';
import { ResourcePage, StatusChip } from '../../common';

const getOperateTabs = (t) => [
  { label: 'Flow Instances', path: '/console/org/operate/flow-instances' },
  { label: t('operate.tabs.issuance'), path: '/console/org/operate/issuance' },
  { label: t('operate.tabs.applications'), path: '/console/org/operate/applications' },
  { label: t('operate.tabs.verify'), path: '/console/org/operate/verify' },
];

const getBreadcrumbs = (t) => [
  { label: t('operate.breadcrumbs.console'), path: '/console' },
  { label: t('operate.breadcrumbs.operate'), path: '/console/org/operate' },
  { label: t('operate.breadcrumbs.issuance'), path: '/console/org/operate/issuance' },
];

const LIFECYCLE_ACTIONS = {
  suspend: {
    label: 'Suspend credential',
    confirmLabel: 'Suspend',
    notificationMessage: 'Lifecycle state: Suspended. Verification policies may now deny this credential.',
    description: 'The credential will fail policies that require an active, non-suspended credential.',
  },
  reinstate: {
    label: 'Reinstate credential',
    confirmLabel: 'Reinstate',
    notificationMessage: 'Lifecycle state: Active. Verification may allow this credential again.',
    description: 'The credential will become active again. Revoked credentials cannot be reinstated.',
  },
  revoke: {
    label: 'Revoke credential',
    confirmLabel: 'Revoke',
    notificationMessage: 'Lifecycle state: Revoked. Verification policies must deny this credential.',
    description: 'Revocation is permanent. The holder will no longer be able to use this credential.',
  },
};

const normalizeStatus = (status) => String(status || '').trim().toUpperCase();

function IssuancePage() {
  const { t } = useTranslation('console');
  const navigate = useNavigate();
  const { credentialId } = useParams();
  const { activeOrgId: organizationId } = useConsole();
  const { showError, showInfo, showSuccess } = useNotifications();
  const [searchQuery, setSearchQuery] = useState('');
  const [renewingCredentialId, setRenewingCredentialId] = useState(null);
  const [latestOffer, setLatestOffer] = useState(null);
  const [lifecycleAction, setLifecycleAction] = useState(null);
  const [lifecycleTarget, setLifecycleTarget] = useState(null);
  const [lifecycleReason, setLifecycleReason] = useState('');
  const [lifecycleSubmitting, setLifecycleSubmitting] = useState(false);
  const [focusedCredentialId, setFocusedCredentialId] = useState(null);
  const [detailCredentialId, setDetailCredentialId] = useState(null);

  const {
    data: issuedCredentialsData,
    loading,
    error,
    reload,
  } = useAsyncData(async () => {
    return fetchIssuedCredentials({
      organizationId,
      searchQuery,
      page: 1,
      perPage: 200,
    });
  }, [organizationId, searchQuery]);

  const {
    data: credentialTemplatesData,
  } = useAsyncData(async () => {
    const result = await listCredentialTemplates({ organization_id: organizationId });
    return Array.isArray(result) ? result : [];
  }, [organizationId]);

  const issuedCredentials = issuedCredentialsData?.credentials || [];
  const getCredentialReference = (credential) => pickOfficialReference({
    rawId: credential?.credential_id || credential?.id,
    kind: 'credential',
  });
  const getApplicationReference = (credential) => pickOfficialReference({
    reference: credential?.application_reference || credential?.applicationReference,
    rawId: credential?.application_id,
    kind: 'application',
  });
  const getTemplateReference = (templateId) => pickOfficialReference({
    rawId: templateId,
    kind: 'template',
  });
  const getLifecycleCaseReference = (credential) => pickOfficialReference({
    rawId: credential?.flow_execution_id,
    kind: 'flow',
    fallback: 'Not linked',
  });
  const getHolderLabel = (credential) => {
    const candidate = String(credential?.holder_label || credential?.holder_email || '').trim();
    if (candidate && !candidate.startsWith('did:') && candidate.length <= 80) return candidate;
    const subjectId = credential?.subject_id || candidate;
    if (!subjectId) return 'Unknown holder';
    return `Lifecycle holder • ${pickOfficialReference({ rawId: subjectId, kind: 'account' })}`;
  };
  const getHolderSecondaryLabel = (credential) => {
    const primary = getHolderLabel(credential);
    const candidate = String(credential?.holder_email || '').trim();
    const isEmail = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(candidate);
    return isEmail && candidate !== primary ? candidate : null;
  };
  const getLifecycleRelationship = (credential) => {
    if (credential?.renewed_from_credential_id) {
      return `Renewed from ${pickOfficialReference({
        rawId: credential.renewed_from_credential_id,
        kind: 'credential',
      })}`;
    }
    if (credential?.renewed_to_credential_id) {
      return `Superseded by ${pickOfficialReference({
        rawId: credential.renewed_to_credential_id,
        kind: 'credential',
      })}`;
    }
    return 'Original issuance';
  };
  const templateNameById = useMemo(() => {
    const map = new Map();
    const templates = Array.isArray(credentialTemplatesData) ? credentialTemplatesData : [];
    templates.forEach((template) => {
      if (!template?.id) return;
      map.set(template.id, template.name || template.display_name || template.credential_type || template.id);
    });
    return map;
  }, [credentialTemplatesData]);

  const selectedCredential = useMemo(() => {
    const selectedId = credentialId || detailCredentialId;
    if (!selectedId) return null;
    return issuedCredentials.find((credential) => (
      credential.id === selectedId || credential.credential_id === selectedId
    )) || null;
  }, [credentialId, detailCredentialId, issuedCredentials]);

  useEffect(() => {
    setLatestOffer(null);
  }, [credentialId, detailCredentialId]);

  const handleOpenDetails = (credential) => {
    setFocusedCredentialId(credential.id || credential.credential_id);
    navigate(`/console/org/operate/issuance/${encodeURIComponent(credential.id)}`);
  };

  const handleCloseDetails = () => {
    setFocusedCredentialId(null);
    setDetailCredentialId(null);
    setLatestOffer(null);
    if (credentialId) navigate('/console/org/operate/issuance');
  };

  const handleCopyOffer = async () => {
    if (!latestOffer?.offer_url || !navigator?.clipboard?.writeText) return;
    await navigator.clipboard.writeText(latestOffer.offer_url);
    showSuccess('Offer link copied to clipboard');
  };

  const handleRenew = async (credential) => {
    setFocusedCredentialId(credential.id || credential.credential_id);
    setDetailCredentialId(credential.id || credential.credential_id);
    setRenewingCredentialId(credential.id);
    try {
      const offer = await renewCredential({ credentialId: credential.id });
      setLatestOffer({ ...offer, offer_url: offer.credential_offer_uri });
      showInfo('Renewal offer generated. Replacement issuance is pending wallet claim.', {
        replaceKey: 'credential-lifecycle',
      });
    } catch (err) {
      showError(err?.message || 'Failed to generate a renewal offer');
    } finally {
      setRenewingCredentialId(null);
    }
  };

  const openLifecycleDialog = (action, credential) => {
    setFocusedCredentialId(credential.id || credential.credential_id);
    setLifecycleAction(action);
    setLifecycleTarget(credential);
    setLifecycleReason('');
  };

  const closeLifecycleDialog = () => {
    if (lifecycleSubmitting) return;
    setLifecycleAction(null);
    setLifecycleTarget(null);
    setLifecycleReason('');
  };

  const handleLifecycleAction = async () => {
    const credentialId = lifecycleTarget?.id || lifecycleTarget?.credential_id;
    const reason = lifecycleReason.trim();
    const config = LIFECYCLE_ACTIONS[lifecycleAction];
    if (!credentialId || !reason || !config) return;

    const actions = {
      suspend: suspendCredential,
      reinstate: reinstateCredential,
      revoke: revokeCredential,
    };

    setLifecycleSubmitting(true);
    try {
      await actions[lifecycleAction]({ credentialId, reason });
      showInfo(config.notificationMessage, {
        title: 'Lifecycle updated',
        replaceKey: 'credential-lifecycle',
      });
      setLifecycleAction(null);
      setLifecycleTarget(null);
      setLifecycleReason('');
      await reload();
    } catch (err) {
      showError(err?.message || `Failed to ${lifecycleAction} credential`);
    } finally {
      setLifecycleSubmitting(false);
    }
  };

  const title = t('operate.issuance.title', 'Issued Credentials');
  const description = t(
    'operate.issuance.description',
    'Inspect issued credentials and generate a fresh wallet offer when a holder needs to claim or re-claim one.',
  );

  return (
    <ResourcePage
      title={title}
      description={description}
      tabs={getOperateTabs(t)}
      breadcrumbs={getBreadcrumbs(t)}
      pageTestId="issued-credentials-page"
      actions={
        <Button
          variant="outlined"
          startIcon={<RefreshIcon />}
          onClick={reload}
          disabled={loading}
        >
          {t('operate.applications.refresh', 'Refresh')}
        </Button>
      }
    >
      {error && (
        <Alert severity="error" sx={{ mb: 3 }}>
          {error?.message || String(error)}
        </Alert>
      )}
      <Box sx={{ display: 'flex', gap: 2, mb: 3 }}>
        <TextField
          placeholder="Search issued credentials..."
          value={searchQuery}
          onChange={(event) => setSearchQuery(event.target.value)}
          size="small"
          sx={{ width: 360 }}
          slotProps={{
            input: {
              startAdornment: (
                <InputAdornment position="start">
                  <SearchIcon color="action" />
                </InputAdornment>
              ),
            }
          }}
        />
      </Box>
      {loading && (
        <LinearProgress aria-label="Refreshing issued credentials" sx={{ mb: issuedCredentials.length > 0 ? 1 : 0 }} />
      )}
      {!loading && issuedCredentials.length === 0 ? (
        <Paper variant="outlined" sx={{ p: 4, textAlign: 'center' }}>
          <Typography variant="h6" gutterBottom>
            No issued credentials yet
          </Typography>
          <Typography color="text.secondary">
            Issued credentials will appear here once applications complete the wallet claim flow.
          </Typography>
        </Paper>
      ) : issuedCredentials.length > 0 ? (
        <TableContainer component={Paper}>
          <Table sx={{ tableLayout: 'fixed' }}>
            <colgroup>
              <col style={{ width: '18%' }} />
              <col style={{ width: '18%' }} />
              <col style={{ width: '11%' }} />
              <col style={{ width: '13%' }} />
              <col style={{ width: '10%' }} />
              <col style={{ width: '30%' }} />
            </colgroup>
            <TableHead>
              <TableRow>
                <TableCell>Credential</TableCell>
                <TableCell>Holder</TableCell>
                <TableCell>Lifecycle case</TableCell>
                <TableCell>Relationship</TableCell>
                <TableCell>Lifecycle state</TableCell>
                <TableCell align="right">Actions</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {issuedCredentials.map((credential) => (
                <TableRow
                  key={credential.id}
                  data-credential-record-id={credential.id || credential.credential_id}
                  hover
                  selected={(credential.id || credential.credential_id) === (credentialId || detailCredentialId || focusedCredentialId)}
                  aria-selected={(credential.id || credential.credential_id) === (credentialId || detailCredentialId || focusedCredentialId)}
                >
                  <TableCell>
                    <Stack spacing={0.25}>
                      <Typography variant="body2" fontWeight={600}>
                        {credential.credential_template_id
                          ? templateNameById.get(credential.credential_template_id)
                            || credential.type
                            || credential.credential_type
                          : credential.type || credential.credential_type}
                      </Typography>
                      <Typography variant="caption" color="text.secondary" sx={{ fontFamily: 'monospace' }}>
                        {getCredentialReference(credential)}
                      </Typography>
                    </Stack>
                  </TableCell>
                  <TableCell>
                    <Typography variant="body2" fontWeight={600}>{getHolderLabel(credential)}</Typography>
                    {getHolderSecondaryLabel(credential) && (
                      <Typography variant="caption" color="text.secondary">
                        {getHolderSecondaryLabel(credential)}
                      </Typography>
                    )}
                  </TableCell>
                  <TableCell>
                    <Typography variant="body2" sx={{ fontFamily: 'monospace' }}>
                      {getLifecycleCaseReference(credential)}
                    </Typography>
                  </TableCell>
                  <TableCell>
                    <Typography variant="body2">{getLifecycleRelationship(credential)}</Typography>
                  </TableCell>
                  <TableCell>
                    <StatusChip status={credential.status} showIcon />
                  </TableCell>
                  <TableCell align="right">
                    <Stack direction="row" spacing={0.75} justifyContent="flex-end" flexWrap="wrap" useFlexGap>
                      <Button
                        size="small"
                        startIcon={<VisibilityIcon />}
                        aria-label={`View credential details for ${getCredentialReference(credential)}`}
                        onClick={() => handleOpenDetails(credential)}
                      >
                        Details
                      </Button>
                      {credential.renewable && (
                        <Button
                          size="small"
                          startIcon={<AutorenewIcon />}
                          aria-label={`Renew credential ${getCredentialReference(credential)}`}
                          disabled={!credential.can_renew || renewingCredentialId === credential.id}
                          onClick={() => handleRenew(credential)}
                          title={credential.can_renew ? undefined : `Renewal available ${credential.renewal_eligible_at ? new Date(credential.renewal_eligible_at).toLocaleString() : 'later'}`}
                        >
                          Renew
                        </Button>
                      )}
                      {normalizeStatus(credential.status) === 'ACTIVE' && (
                        <Button
                          size="small"
                          startIcon={<PauseCircleOutlineIcon />}
                          aria-label={`Suspend credential ${getCredentialReference(credential)}`}
                          onClick={() => openLifecycleDialog('suspend', credential)}
                        >
                          Suspend
                        </Button>
                      )}
                      {normalizeStatus(credential.status) === 'SUSPENDED' && (
                        <Button
                          size="small"
                          color="success"
                          startIcon={<PlayCircleOutlineIcon />}
                          aria-label={`Reinstate credential ${getCredentialReference(credential)}`}
                          onClick={() => openLifecycleDialog('reinstate', credential)}
                        >
                          Reinstate
                        </Button>
                      )}
                      {['ACTIVE', 'SUSPENDED'].includes(normalizeStatus(credential.status)) && (
                        <Button
                          size="small"
                          color="error"
                          startIcon={<BlockIcon />}
                          aria-label={`Revoke credential ${getCredentialReference(credential)}`}
                          onClick={() => openLifecycleDialog('revoke', credential)}
                        >
                          Revoke
                        </Button>
                      )}
                    </Stack>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>
      ) : null}
      <Dialog
        open={Boolean(selectedCredential && !lifecycleAction)}
        onClose={handleCloseDetails}
        maxWidth="sm"
        fullWidth
      >
        <DialogTitle>Issued Credential Details</DialogTitle>
        <DialogContent dividers>
          {selectedCredential && (
            <Stack spacing={2} sx={{ pt: 1 }}>
              <Box>
                <Typography variant="subtitle2" color="text.secondary">Credential Reference</Typography>
                <Typography sx={{ fontFamily: 'monospace' }}>{getCredentialReference(selectedCredential)}</Typography>
              </Box>
              <Box>
                <Typography variant="subtitle2" color="text.secondary">Type</Typography>
                <Typography>{selectedCredential.type || selectedCredential.credential_type}</Typography>
              </Box>
              <Box>
                <Typography variant="subtitle2" color="text.secondary">Holder</Typography>
                <Typography>{getHolderLabel(selectedCredential)}</Typography>
              </Box>
              <Box>
                <Typography variant="subtitle2" color="text.secondary">Lifecycle state</Typography>
                <StatusChip status={selectedCredential.status} showIcon />
              </Box>
              <Box>
                <Typography variant="subtitle2" color="text.secondary">Lifecycle case</Typography>
                <Typography sx={{ fontFamily: 'monospace' }}>
                  {getLifecycleCaseReference(selectedCredential)}
                </Typography>
              </Box>
              <Box>
                <Typography variant="subtitle2" color="text.secondary">Credential relationship</Typography>
                <Typography>{getLifecycleRelationship(selectedCredential)}</Typography>
              </Box>
              <Box>
                <Typography variant="subtitle2" color="text.secondary">Application Reference</Typography>
                <Typography sx={{ fontFamily: 'monospace' }}>{getApplicationReference(selectedCredential)}</Typography>
              </Box>
              <Box>
                <Typography variant="subtitle2" color="text.secondary">Credential Template</Typography>
                {selectedCredential.credential_template_id ? (
                  <Stack spacing={0.25}>
                    <Typography>
                      {templateNameById.get(selectedCredential.credential_template_id)
                        || selectedCredential.credential_template_id}
                    </Typography>
                    <Typography sx={{ fontFamily: 'monospace' }} color="text.secondary" variant="caption">
                      {getTemplateReference(selectedCredential.credential_template_id)}
                    </Typography>
                  </Stack>
                ) : (
                  <Typography sx={{ fontFamily: 'monospace' }}>—</Typography>
                )}
              </Box>
              <Box>
                <Typography variant="subtitle2" color="text.secondary">Issuer DID</Typography>
                <Typography sx={{ wordBreak: 'break-word', fontFamily: 'monospace' }}>{selectedCredential.issuer_did || '—'}</Typography>
              </Box>

              {latestOffer?.offer_url && (
                <Alert severity="info">
                  <Typography variant="subtitle2" gutterBottom>
                    Renewal offer ready — replacement not issued yet
                  </Typography>
                  <Typography variant="body2" gutterBottom>
                    The holder must claim this offer before Marty records a replacement credential and predecessor relationship.
                  </Typography>
                  <Typography variant="body2">
                    The offer link is ready for secure delivery. Use Copy offer link or Open offer when needed.
                  </Typography>
                  {latestOffer.expires_at && (
                    <Typography variant="caption" display="block" sx={{ mt: 1 }}>
                      Expires: {new Date(latestOffer.expires_at).toLocaleString()}
                    </Typography>
                  )}
                </Alert>
              )}
            </Stack>
          )}
        </DialogContent>
        <DialogActions>
          {selectedCredential && (
            <Button
              startIcon={<HistoryIcon />}
              onClick={() => navigate(
                `/console/org/audit?search=${encodeURIComponent(selectedCredential.id || selectedCredential.credential_id)}`,
              )}
            >
              View lifecycle audit
            </Button>
          )}
          {latestOffer?.offer_url && (
            <>
              <Button
                startIcon={<ContentCopyIcon />}
                onClick={handleCopyOffer}
              >
                Copy offer link
              </Button>
              <Button
                startIcon={<OpenInNewIcon />}
                component="a"
                href={latestOffer.offer_url}
                target="_blank"
                rel="noreferrer"
              >
                Open offer
              </Button>
            </>
          )}
          {selectedCredential?.renewable && (
            <Button
              variant="contained"
              startIcon={<AutorenewIcon />}
              onClick={() => handleRenew(selectedCredential)}
              disabled={!selectedCredential.can_renew || renewingCredentialId === selectedCredential.id}
            >
              {renewingCredentialId === selectedCredential.id ? 'Generating…' : 'Renew'}
            </Button>
          )}
          {normalizeStatus(selectedCredential?.status) === 'ACTIVE' && (
            <Button
              startIcon={<PauseCircleOutlineIcon />}
              onClick={() => openLifecycleDialog('suspend', selectedCredential)}
            >
              Suspend
            </Button>
          )}
          {normalizeStatus(selectedCredential?.status) === 'SUSPENDED' && (
            <Button
              color="success"
              startIcon={<PlayCircleOutlineIcon />}
              onClick={() => openLifecycleDialog('reinstate', selectedCredential)}
            >
              Reinstate
            </Button>
          )}
          {['ACTIVE', 'SUSPENDED'].includes(normalizeStatus(selectedCredential?.status)) && (
            <Button
              color="error"
              startIcon={<BlockIcon />}
              onClick={() => openLifecycleDialog('revoke', selectedCredential)}
            >
              Revoke
            </Button>
          )}
          <Button onClick={handleCloseDetails}>Close</Button>
        </DialogActions>
      </Dialog>
      <Dialog
        open={Boolean(lifecycleAction && lifecycleTarget)}
        onClose={closeLifecycleDialog}
        maxWidth="xs"
        fullWidth
      >
        <DialogTitle>{LIFECYCLE_ACTIONS[lifecycleAction]?.label}</DialogTitle>
        <DialogContent dividers>
          <Stack spacing={2}>
            <Alert severity={lifecycleAction === 'revoke' ? 'warning' : 'info'}>
              {LIFECYCLE_ACTIONS[lifecycleAction]?.description}
            </Alert>
            <Box>
              <Typography variant="subtitle2" color="text.secondary">Credential Reference</Typography>
              <Typography sx={{ fontFamily: 'monospace' }}>
                {lifecycleTarget ? getCredentialReference(lifecycleTarget) : '-'}
              </Typography>
            </Box>
            <TextField
              label="Reason"
              value={lifecycleReason}
              onChange={(event) => setLifecycleReason(event.target.value)}
              required
              autoFocus
              multiline
              minRows={3}
              helperText={`${lifecycleReason.length}/500`}
              slotProps={{
                htmlInput: { maxLength: 500 }
              }}
            />
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={closeLifecycleDialog} disabled={lifecycleSubmitting}>Cancel</Button>
          <Button
            variant="contained"
            color={lifecycleAction === 'revoke' ? 'error' : 'primary'}
            onClick={handleLifecycleAction}
            disabled={lifecycleSubmitting || !lifecycleReason.trim()}
          >
            {lifecycleSubmitting ? 'Working...' : LIFECYCLE_ACTIONS[lifecycleAction]?.confirmLabel}
          </Button>
        </DialogActions>
      </Dialog>
    </ResourcePage>
  );
}

export default IssuancePage;

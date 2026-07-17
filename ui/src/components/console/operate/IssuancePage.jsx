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
  IconButton,
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
  Tooltip,
  Typography,
} from '@mui/material';
import SearchIcon from '@mui/icons-material/Search';
import VisibilityIcon from '@mui/icons-material/Visibility';
import RefreshIcon from '@mui/icons-material/Refresh';
import AutorenewIcon from '@mui/icons-material/Autorenew';
import ContentCopyIcon from '@mui/icons-material/ContentCopy';
import OpenInNewIcon from '@mui/icons-material/OpenInNew';
import BlockIcon from '@mui/icons-material/Block';
import PauseCircleOutlineIcon from '@mui/icons-material/PauseCircleOutlined';
import PlayCircleOutlineIcon from '@mui/icons-material/PlayCircleOutlined';
import { useNavigate, useParams } from 'react-router-dom';
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
    successMessage: 'Credential suspended',
    description: 'The credential will fail policies that require an active, non-suspended credential.',
  },
  reinstate: {
    label: 'Reinstate credential',
    confirmLabel: 'Reinstate',
    successMessage: 'Credential reinstated',
    description: 'The credential will become active again. Revoked credentials cannot be reinstated.',
  },
  revoke: {
    label: 'Revoke credential',
    confirmLabel: 'Revoke',
    successMessage: 'Credential revoked',
    description: 'Revocation is permanent. The holder will no longer be able to use this credential.',
  },
};

const normalizeStatus = (status) => String(status || '').trim().toUpperCase();

function IssuancePage() {
  const { t } = useTranslation('console');
  const navigate = useNavigate();
  const { credentialId } = useParams();
  const { activeOrgId: organizationId } = useConsole();
  const { showError, showSuccess } = useNotifications();
  const [searchQuery, setSearchQuery] = useState('');
  const [renewingCredentialId, setRenewingCredentialId] = useState(null);
  const [latestOffer, setLatestOffer] = useState(null);
  const [lifecycleAction, setLifecycleAction] = useState(null);
  const [lifecycleTarget, setLifecycleTarget] = useState(null);
  const [lifecycleReason, setLifecycleReason] = useState('');
  const [lifecycleSubmitting, setLifecycleSubmitting] = useState(false);

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
    if (!credentialId) return null;
    return issuedCredentials.find((credential) => (
      credential.id === credentialId || credential.credential_id === credentialId
    )) || null;
  }, [credentialId, issuedCredentials]);

  useEffect(() => {
    setLatestOffer(null);
  }, [credentialId]);

  const handleOpenDetails = (credential) => {
    navigate(`/console/org/operate/issuance/${encodeURIComponent(credential.id)}`);
  };

  const handleCloseDetails = () => {
    navigate('/console/org/operate/issuance');
  };

  const handleCopyOffer = async () => {
    if (!latestOffer?.offer_url || !navigator?.clipboard?.writeText) return;
    await navigator.clipboard.writeText(latestOffer.offer_url);
    showSuccess('Offer link copied to clipboard');
  };

  const handleRenew = async (credential) => {
    setRenewingCredentialId(credential.id);
    try {
      const offer = await renewCredential({ credentialId: credential.id });
      setLatestOffer({ ...offer, offer_url: offer.credential_offer_uri });
      navigate(`/console/org/operate/issuance/${encodeURIComponent(credential.id)}`);
      showSuccess('Renewal offer generated successfully');
    } catch (err) {
      showError(err?.message || 'Failed to generate a renewal offer');
    } finally {
      setRenewingCredentialId(null);
    }
  };

  const openLifecycleDialog = (action, credential) => {
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
      showSuccess(config.successMessage);
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
      {loading ? (
        <LinearProgress />
      ) : issuedCredentials.length === 0 ? (
        <Paper variant="outlined" sx={{ p: 4, textAlign: 'center' }}>
          <Typography variant="h6" gutterBottom>
            No issued credentials yet
          </Typography>
          <Typography color="text.secondary">
            Issued credentials will appear here once applications complete the wallet claim flow.
          </Typography>
        </Paper>
      ) : (
        <TableContainer component={Paper}>
          <Table>
            <TableHead>
              <TableRow>
                <TableCell>Credential Reference</TableCell>
                <TableCell>Type</TableCell>
                <TableCell>Credential Template</TableCell>
                <TableCell>Holder</TableCell>
                <TableCell>Issued</TableCell>
                <TableCell>Expires</TableCell>
                <TableCell>Status</TableCell>
                <TableCell align="right">Actions</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {issuedCredentials.map((credential) => (
                <TableRow key={credential.id} hover>
                  <TableCell>
                    <Typography variant="body2" sx={{ fontFamily: 'monospace', fontSize: 12 }}>
                      {getCredentialReference(credential)}
                    </Typography>
                  </TableCell>
                  <TableCell>{credential.type || credential.credential_type}</TableCell>
                  <TableCell>
                    {credential.credential_template_id ? (
                      <Stack spacing={0.25}>
                        <Typography variant="body2">
                          {templateNameById.get(credential.credential_template_id) || credential.credential_template_id}
                        </Typography>
                        <Typography variant="caption" color="text.secondary" sx={{ fontFamily: 'monospace' }}>
                          {getTemplateReference(credential.credential_template_id)}
                        </Typography>
                      </Stack>
                    ) : '—'}
                  </TableCell>
                  <TableCell>{credential.holder_email || credential.subject_id}</TableCell>
                  <TableCell>{credential.issued_date ? new Date(credential.issued_date).toLocaleString() : '—'}</TableCell>
                  <TableCell>{credential.expiry_date ? new Date(credential.expiry_date).toLocaleString() : '—'}</TableCell>
                  <TableCell>
                    <StatusChip status={credential.status} />
                  </TableCell>
                  <TableCell align="right">
                    <Tooltip title="View credential details">
                      <IconButton
                        size="small"
                        aria-label={`View credential details for ${getCredentialReference(credential)}`}
                        onClick={() => handleOpenDetails(credential)}
                      >
                        <VisibilityIcon fontSize="small" />
                      </IconButton>
                    </Tooltip>
                    {credential.renewable && (
                      <Tooltip title={credential.can_renew ? 'Renew credential' : `Renewal available ${credential.renewal_eligible_at ? new Date(credential.renewal_eligible_at).toLocaleString() : 'later'}`}>
                        <span>
                          <IconButton
                            size="small"
                            color="primary"
                            aria-label={`Renew credential ${getCredentialReference(credential)}`}
                            disabled={!credential.can_renew || renewingCredentialId === credential.id}
                            onClick={() => handleRenew(credential)}
                          >
                            <AutorenewIcon fontSize="small" />
                          </IconButton>
                        </span>
                      </Tooltip>
                    )}
                    {normalizeStatus(credential.status) === 'ACTIVE' && (
                      <Tooltip title="Suspend credential">
                        <IconButton
                          size="small"
                          aria-label={`Suspend credential ${getCredentialReference(credential)}`}
                          onClick={() => openLifecycleDialog('suspend', credential)}
                        >
                          <PauseCircleOutlineIcon fontSize="small" />
                        </IconButton>
                      </Tooltip>
                    )}
                    {normalizeStatus(credential.status) === 'SUSPENDED' && (
                      <Tooltip title="Reinstate credential">
                        <IconButton
                          size="small"
                          color="success"
                          aria-label={`Reinstate credential ${getCredentialReference(credential)}`}
                          onClick={() => openLifecycleDialog('reinstate', credential)}
                        >
                          <PlayCircleOutlineIcon fontSize="small" />
                        </IconButton>
                      </Tooltip>
                    )}
                    {['ACTIVE', 'SUSPENDED'].includes(normalizeStatus(credential.status)) && (
                      <Tooltip title="Revoke credential">
                        <IconButton
                          size="small"
                          color="error"
                          aria-label={`Revoke credential ${getCredentialReference(credential)}`}
                          onClick={() => openLifecycleDialog('revoke', credential)}
                        >
                          <BlockIcon fontSize="small" />
                        </IconButton>
                      </Tooltip>
                    )}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>
      )}
      <Dialog
        open={Boolean(credentialId && selectedCredential && !lifecycleAction)}
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
                <Typography>{selectedCredential.holder_email || selectedCredential.subject_id || '—'}</Typography>
              </Box>
              <Box>
                <Typography variant="subtitle2" color="text.secondary">Status</Typography>
                <StatusChip status={selectedCredential.status} />
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
                <Alert severity="success">
                  <Typography variant="subtitle2" gutterBottom>Fresh wallet offer ready</Typography>
                  <Typography variant="body2" sx={{ wordBreak: 'break-word' }}>
                    {latestOffer.offer_url}
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

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
import { useNavigate, useParams } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { useConsole } from '../../../contexts/ConsoleContext';
import { useAsyncData } from '../../../hooks/useAsyncData';
import { useNotifications } from '../../../hooks/useNotifications';
import { fetchIssuedCredentials } from '../../../application/vendor';
import { issueOrganizationApplication } from '../../../services/applicantApi';
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

function IssuancePage() {
  const { t } = useTranslation('console');
  const navigate = useNavigate();
  const { credentialId } = useParams();
  const { activeOrgId: organizationId } = useConsole();
  const { showError, showSuccess } = useNotifications();
  const [searchQuery, setSearchQuery] = useState('');
  const [reissuingCredentialId, setReissuingCredentialId] = useState(null);
  const [latestOffer, setLatestOffer] = useState(null);

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

  const handleReissue = async (credential) => {
    if (!credential?.application_id) {
      showError('This credential cannot be reissued because no source application is linked.');
      return;
    }

    setReissuingCredentialId(credential.id);
    try {
      const offer = await issueOrganizationApplication(organizationId, credential.application_id);
      setLatestOffer(offer);
      showSuccess('Fresh wallet offer generated successfully');
    } catch (err) {
      showError(err?.message || 'Failed to generate a fresh wallet offer');
    } finally {
      setReissuingCredentialId(null);
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
          InputProps={{
            startAdornment: (
              <InputAdornment position="start">
                <SearchIcon color="action" />
              </InputAdornment>
            ),
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
                    {credential.application_id && (
                      <Tooltip title="Generate a fresh wallet offer">
                        <span>
                          <IconButton
                            size="small"
                            color="primary"
                            aria-label={`Reissue credential ${getCredentialReference(credential)}`}
                            disabled={reissuingCredentialId === credential.id}
                            onClick={() => handleReissue(credential)}
                          >
                            <AutorenewIcon fontSize="small" />
                          </IconButton>
                        </span>
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
        open={Boolean(credentialId && selectedCredential)}
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
          {selectedCredential?.application_id && (
            <Button
              variant="contained"
              startIcon={<AutorenewIcon />}
              onClick={() => handleReissue(selectedCredential)}
              disabled={reissuingCredentialId === selectedCredential.id}
            >
              {reissuingCredentialId === selectedCredential.id ? 'Generating…' : 'Reissue'}
            </Button>
          )}
          <Button onClick={handleCloseDetails}>Close</Button>
        </DialogActions>
      </Dialog>
    </ResourcePage>
  );
}

export default IssuancePage;

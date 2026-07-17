import { useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useNavigate } from 'react-router-dom';
import {
  Alert,
  Box,
  Button,
  Chip,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
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
import AddIcon from '@mui/icons-material/Add';
import RefreshIcon from '@mui/icons-material/Refresh';
import SettingsEthernetIcon from '@mui/icons-material/SettingsEthernet';
import VpnKeyIcon from '@mui/icons-material/VpnKey';

import signingKeysApi from '../../../services/signingKeysApi';
import { isAuthError } from '../../../services/api';
import ResourcePage from '../../common/ResourcePage';
import EmptyState from '../../common/EmptyState';
import ErrorState from '../../common/ErrorState';
import StatusChip from '../../common/StatusChip';
import { TableSkeleton } from '../../common/skeletons';
import { usePermissions } from '../../../hooks/usePermissions';
import { useNotifications } from '../../../hooks/useNotifications';
import { useAsyncData } from '../../../hooks/useAsyncData';
import { useDialog } from '../../../hooks/useDialog';
import { useConsole } from '../../../contexts/ConsoleContext';
import {
  DEFAULT_KEY_MANAGEMENT_CONFIG,
  PURPOSES_REQUIRING_CERTIFICATE,
  getDefaultKeyManagementService,
  normalizeKeyManagementConfig,
} from './keyManagementServiceCatalog';

const getBreadcrumbs = (t) => [
  { label: t('deploy.breadcrumbs.console'), path: '/console' },
  { label: t('deploy.breadcrumbs.deploy'), path: '/console/org/deploy' },
  { label: 'Key Management', path: '/console/org/deploy/key-management' },
];

const statusSeverityMap = {
  configured: 'success',
  degraded: 'warning',
  metadata_only: 'info',
  registered: 'info',
};

function logSigningKeysPageError(message, error) {
  if (import.meta.env?.DEV && import.meta.env?.MODE !== 'test') {
    console.error(message, error);
  }
}

const formatListValue = (value) => {
  if (!Array.isArray(value) || value.length === 0) {
    return '-';
  }

  return value.join(', ');
};

const getStatusColor = (status) => {
  switch (status) {
    case 'valid':
    case 'active':
    case 'configured':
      return 'success';
    case 'expired':
    case 'deprecated':
    case 'degraded':
      return 'warning';
    case 'invalid':
    case 'revoked':
      return 'error';
    default:
      return 'default';
  }
};

const formatDate = (value) => {
  if (!value) {
    return '-';
  }
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) {
    return '-';
  }
  return parsed.toLocaleDateString();
};

const formatDateTime = (value) => {
  if (!value) {
    return '-';
  }
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) {
    return '-';
  }
  return parsed.toLocaleString();
};

const isExpiringSoon = (expiryDate) => {
  if (!expiryDate) return false;
  const now = new Date();
  const expiry = new Date(expiryDate);
  const daysUntilExpiry = (expiry - now) / (1000 * 60 * 60 * 24);
  return daysUntilExpiry <= 30 && daysUntilExpiry > 0;
};

const getServiceConnectionSummary = (service) => {
  if (service?.endpoint) {
    return service.endpoint;
  }
  if (service?.region) {
    return `Region: ${service.region}`;
  }
  return 'Connection details pending';
};

const BRAND_PATTERN = /\bmarty\b/gi;
const MANAGED_OPENBAO_SERVICE_ID = 'managed-openbao-transit';

const toBrandDisplay = (value) => (
  typeof value === 'string' ? value.replace(BRAND_PATTERN, 'Elevenidllc') : value
);

const normalizeRoleCandidate = (value) => (
  typeof value === 'string'
    ? value.trim().toLowerCase().replace(/[-\s]+/g, '_')
    : ''
);

const isOrgServiceAdminRole = (role) => {
  const roleCandidates = [
    role,
    role?.name,
    role?.display_name,
    role?.role,
    role?.role_name,
    role?.slug,
  ]
    .map(normalizeRoleCandidate)
    .filter(Boolean);

  return roleCandidates.some((candidate) => [
    'owner',
    'admin',
    'administrator',
    'org_admin',
    'organization_admin',
    'org_owner',
    'organization_owner',
  ].includes(candidate));
};

const normalizePurposeCandidate = (value) => (
  typeof value === 'string' ? value.trim().toLowerCase() : ''
);

const getSigningKeyPurpose = (key, t) => {
  const explicitPurpose = [
    key?.purpose,
    key?.usage,
    key?.use,
    key?.key_use,
    key?.key_purpose,
    key?.binding_type,
    key?.identity_type,
    key?.certificate_type,
  ]
    .map(normalizePurposeCandidate)
    .find(Boolean);

  const purposeHints = [
    explicitPurpose,
    key?.provider_key_name,
    key?.name,
    key?.id,
    ...(Array.isArray(key?.aliases) ? key.aliases : []),
    ...(Array.isArray(key?.key_aliases) ? key.key_aliases : []),
  ]
    .map(normalizePurposeCandidate)
    .filter(Boolean)
    .join(' ');

  if (/issuer key|cred-issuer|vc issuer|credential issuer/.test(purposeHints)) {
    return t('deploy.signingKeys.purposes.issuer', 'Credential issuer');
  }

  if (/x509|x\.509|certificate|document signer|doc signer|cred-dsc|\bdsc\b|csca|iaca|mdoc/.test(purposeHints)) {
    return t('deploy.signingKeys.purposes.x509', 'X.509 certificate');
  }

  if (/jwks|jwk/.test(purposeHints)) {
    return t('deploy.signingKeys.purposes.jwk', 'JWK signing');
  }

  return t('deploy.signingKeys.purposes.general', 'General signing');
};

const getSigningKeyAssociation = (key, t) => {
  const associationHints = [
    key?.provider_key_name,
    key?.name,
    key?.id,
    ...(Array.isArray(key?.aliases) ? key.aliases : []),
    ...(Array.isArray(key?.key_aliases) ? key.key_aliases : []),
  ]
    .map(normalizePurposeCandidate)
    .filter(Boolean)
    .join(' ');

  if (/cred-dsc|document signer|doc signer|\bdsc\b/.test(associationHints)) {
    return t('deploy.signingKeys.associations.documentSigner', 'Associated with document signer certificate');
  }

  if (/csca|iaca|root certificate|root cert|issuing authority/.test(associationHints)) {
    return t('deploy.signingKeys.associations.rootCertificate', 'Associated with issuing authority certificate');
  }

  if (/cred-issuer|issuer key|vc issuer|credential issuer/.test(associationHints)) {
    return t('deploy.signingKeys.associations.credentialIssuer', 'Associated with credential issuer signing');
  }

  if (/jwks|jwk/.test(associationHints)) {
    return t('deploy.signingKeys.associations.jwks', 'Associated with JWKS signing');
  }

  const reference = key?.provider_key_name || key?.id;
  if (reference) {
    return t('deploy.signingKeys.associations.reference', { reference }, `Associated with ${reference}`);
  }

  return t('deploy.signingKeys.associations.unknown', 'Association not specified');
};

function ServiceCard({
  service,
  isDefault,
  canManage,
  onMakeDefault,
  onRemove,
  onRotate,
  onManageCertificate,
}) {
  const hasCertPurpose = Array.isArray(service.key_purposes)
    && service.key_purposes.some((p) => PURPOSES_REQUIRING_CERTIFICATE.includes(p));
  const supportsRotation = service.service_type === 'openbao-transit'
    || service.service_type === 'hashicorp-vault-transit';

  return (
    <Paper variant="outlined" sx={{ p: 2.5 }}>
      <Stack direction={{ xs: 'column', md: 'row' }} justifyContent="space-between" spacing={2}>
        <Box>
          <Stack direction="row" spacing={1} flexWrap="wrap" useFlexGap sx={{ mb: 1 }}>
            <Typography variant="h6">{toBrandDisplay(service.name)}</Typography>
            {isDefault && <Chip size="small" color="primary" label="Default signer" />}
            {service.managed && <Chip size="small" color="success" label="Managed by stack" />}
            <Chip
              size="small"
              label={service.status || 'registered'}
              color={getStatusColor(service.status)}
              variant="outlined"
            />
          </Stack>
          <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
            {service.provider_label} via {service.protocol}
          </Typography>
          <Typography variant="body2" sx={{ mb: 0.5 }}>
            Connection: {getServiceConnectionSummary(service)}
          </Typography>
          <Typography variant="body2" sx={{ mb: 0.5 }}>
            Key reference: {service.key_reference || '-'}
          </Typography>
          <Typography variant="body2" sx={{ mb: 0.5 }}>
            Key aliases: {formatListValue(service.key_aliases)}
          </Typography>
          <Typography variant="body2" sx={{ mb: 0.5 }}>
            Algorithms: {formatListValue(service.algorithms)}
          </Typography>
          {Array.isArray(service.key_purposes) && service.key_purposes.length > 0 && (
            <Typography variant="body2" sx={{ mb: 0.5 }}>
              Purposes: {service.key_purposes.join(', ')}
            </Typography>
          )}
          {service.country_code && (
            <Typography variant="body2" sx={{ mb: 0.5 }}>
              Country: {service.country_code}{service.authority_code ? ` / ${service.authority_code}` : ''}
            </Typography>
          )}
          {service.rotation_policy && (
            <Typography variant="body2" sx={{ mb: 0.5 }}>
              Rotation: every {service.rotation_policy.rotation_interval_days} days
              {service.rotation_policy.auto_publish ? ', auto-publish' : ''}
            </Typography>
          )}
          <Typography variant="body2" sx={{ mb: 0.5 }}>
            Last rotated: {formatDateTime(service.last_rotated_at)}
          </Typography>
          <Typography variant="body2" sx={{ mb: 0.5 }}>
            Auth mode: {service.auth_mode || '-'}
          </Typography>
          <Typography variant="body2">
            Registration mode: {service.managed ? (toBrandDisplay(service.managed_by) || 'Managed by Elevenidllc') : 'Registered in console'}
          </Typography>
        </Box>

        <Stack direction={{ xs: 'row', md: 'column' }} spacing={1} alignItems={{ md: 'flex-end' }} flexWrap="wrap">
          {!isDefault && canManage && (
            <Button variant="outlined" onClick={() => onMakeDefault(service.id)}>
              Make default
            </Button>
          )}
          {canManage && hasCertPurpose && (
            <Button variant="outlined" onClick={() => onManageCertificate(service)}>
              Certificate
            </Button>
          )}
          {canManage && supportsRotation && (
            <Button variant="outlined" startIcon={<RefreshIcon />} onClick={() => onRotate(service.id)}>
              Rotate key
            </Button>
          )}
          {!service.read_only && canManage && (
            <Button color="error" onClick={() => onRemove(service.id)}>
              Remove
            </Button>
          )}
        </Stack>
      </Stack>
    </Paper>
  );
}

export default function SigningKeysPage() {
  const { t } = useTranslation('console');
  const navigate = useNavigate();
  const { activeOrgId } = useConsole();
  const orgRequestParams = useMemo(
    () => (activeOrgId ? { organization_id: activeOrgId } : {}),
    [activeOrgId],
  );

  const { data: signingKeysData, loading, error, reload: reloadKeys } = useAsyncData(async () => {
    const data = await signingKeysApi.listSigningKeys(orgRequestParams);
    const rawKeys = Array.isArray(data) ? data : data?.keys || [];
    const normalizedKeys = Array.isArray(rawKeys)
      ? rawKeys
          .filter((key) => key && typeof key === 'object')
          .map((key) => ({
            ...key,
            id: typeof key.id === 'string' && key.id.length > 0 ? key.id : 'unknown-key',
            name: typeof key.name === 'string' ? key.name : '',
            algorithm: typeof key.algorithm === 'string' ? key.algorithm : '-',
            status: typeof key.status === 'string' ? key.status : 'unknown',
            expiry_date: key.expiry_date ?? null,
            created_at: key.created_at ?? null,
            derived_purpose: getSigningKeyPurpose(key, t),
            derived_association: getSigningKeyAssociation(key, t),
          }))
      : [];

    return {
      keys: normalizedKeys,
      providerMetadata: data?.provider_metadata || null,
      domainConfig: data?.domain_config || null,
      message: typeof data?.message === 'string' ? data.message : null,
    };
  }, [orgRequestParams]);

  const {
    data: keyManagementData,
    error: keyManagementError,
    reload: reloadConfig,
  } = useAsyncData(
    async () => normalizeKeyManagementConfig(
      await signingKeysApi.getKeyManagementConfig(orgRequestParams)
    ),
    [orgRequestParams]
  );

  const keys = Array.isArray(signingKeysData?.keys) ? signingKeysData.keys : [];
  const providerMetadata = signingKeysData?.providerMetadata || null;
  const domainConfig = signingKeysData?.domainConfig || null;
  const keyManagementConfig = normalizeKeyManagementConfig(keyManagementData || DEFAULT_KEY_MANAGEMENT_CONFIG);
  const services = keyManagementConfig.services;
  const defaultService = getDefaultKeyManagementService(keyManagementConfig);
  const canCreateKeysThroughIssuerWizard = defaultService?.id === MANAGED_OPENBAO_SERVICE_ID;
  const providerSummary = keyManagementConfig.provider_metadata || providerMetadata;
  const domainSummary = keyManagementConfig.domain_config || domainConfig;
  const signingKeyMessage = signingKeysData?.message || null;
  const safeKeys = Array.isArray(keys) ? keys : [];

  const certDialog = useDialog();
  const [certAction, setCertAction] = useState('view'); // 'view' | 'csr' | 'upload'
  const [certData, setCertData] = useState({ cert_pem: '', cert_chain_pem: '', common_name: '' });

  const { can, roles, isLoading: permissionsLoading } = usePermissions();
  const { showNotification } = useNotifications();
  const canManageSigningKeys = can('signing-key', 'create');
  const canManageSigningServices = canManageSigningKeys || (Array.isArray(roles) && roles.some(isOrgServiceAdminRole));
  const canOpenServiceWizard = !permissionsLoading;
  const registerServiceDisabledReason = permissionsLoading
    ? 'Checking your organization permissions...'
    : '';

  const openServiceWizard = () => navigate('/console/org/deploy/key-management/services/new');

  const reloadAll = async () => {
    await Promise.all([reloadKeys(), reloadConfig()]);
  };

  const handleRotateService = async (serviceId) => {
    if (!window.confirm('Rotate the key for this signing service? The old key will remain active during the overlap period.')) {
      return;
    }
    try {
      const result = await signingKeysApi.rotateServiceKey(serviceId, orgRequestParams);
      if (result?.ok) {
        showNotification?.('Key rotation completed successfully.', 'success');
      } else {
        const reason = result?.rotation_state?.provider_rotation?.error || result?.note;
        showNotification?.(
          reason
            ? `Rotation recorded, but provider did not report success: ${reason}`
            : 'Rotation recorded, but provider did not report success.',
          'warning',
        );
      }
      await reloadAll();
    } catch (err) {
      logSigningKeysPageError('Failed to rotate service key:', err);
      showNotification?.('Key rotation failed.', 'error');
    }
  };

  const handleOpenCertDialog = async (service) => {
    setCertData({ cert_pem: '', cert_chain_pem: '', common_name: service.name || '' });
    setCertAction('view');
    certDialog.open(service);
    // Try to load existing cert
    try {
      const existing = await signingKeysApi.getServiceCertificate(service.id, orgRequestParams);
      if (existing?.cert_pem) {
        setCertData((prev) => ({
          ...prev,
          cert_pem: existing.cert_pem || '',
          cert_chain_pem: existing.cert_chain_pem || '',
        }));
      }
    } catch {
      // No existing cert — that's fine
    }
  };

  const handleGenerateCsr = async () => {
    const service = certDialog.data;
    if (!service) return;
    try {
      const result = await signingKeysApi.generateServiceCsr(service.id, {
        ...orgRequestParams,
        common_name: certData.common_name || service.name,
      });
      showNotification?.('CSR generated. Download or copy it to submit to your CA.', 'success');
      setCertData((prev) => ({ ...prev, csr_pem: result?.csr_pem || '' }));
      setCertAction('csr');
    } catch (err) {
      logSigningKeysPageError('Failed to generate CSR:', err);
      showNotification?.('CSR generation failed.', 'error');
    }
  };

  const handleUploadCertificate = async () => {
    const service = certDialog.data;
    if (!service || !certData.cert_pem) return;
    try {
      await signingKeysApi.setServiceCertificate(service.id, {
        ...orgRequestParams,
        cert_pem: certData.cert_pem,
        cert_chain_pem: certData.cert_chain_pem || undefined,
      });
      showNotification?.('Certificate stored successfully.', 'success');
      certDialog.close();
      await reloadAll();
    } catch (err) {
      logSigningKeysPageError('Failed to store certificate:', err);
      showNotification?.('Failed to store certificate.', 'error');
    }
  };

  const handleMakeDefault = async (serviceId) => {
    try {
      await signingKeysApi.updateKeyManagementConfig({
        ...orgRequestParams,
        services,
        default_service_id: serviceId,
      });
      await reloadConfig();
      showNotification?.('Updated the default signing service.', 'success');
    } catch (err) {
      logSigningKeysPageError('Failed to update default signing service:', err);
      showNotification?.('Unable to update the default signing service.', 'error');
    }
  };

  const handleRemoveService = async (serviceId) => {
    if (!window.confirm('Remove this key management service registration?')) {
      return;
    }

    try {
      const remainingServices = services.filter((service) => service.id !== serviceId);
      const nextDefaultServiceId = keyManagementConfig.default_service_id === serviceId
        ? remainingServices[0]?.id || null
        : keyManagementConfig.default_service_id;

      await signingKeysApi.updateKeyManagementConfig({
        ...orgRequestParams,
        services: remainingServices,
        default_service_id: nextDefaultServiceId,
      });
      await reloadConfig();
      showNotification?.('Removed the key management service registration.', 'success');
    } catch (err) {
      logSigningKeysPageError('Failed to remove key management service:', err);
      showNotification?.('Unable to remove the key management service.', 'error');
    }
  };

  const renderServiceRegistry = () => {
    if (services.length === 0) {
      return (
        <EmptyState
          icon={SettingsEthernetIcon}
          title="No key management services registered"
          description="Register a KMS, HSM, or transit-compatible signing service before issuing with your own keys."
          whyItMatters="Elevenidllc does not manage private signing keys natively in this deployment."
          actionLabel="Register key management service"
          onAction={canOpenServiceWizard ? openServiceWizard : undefined}
          docsUrl="https://docs.example.com/signing-keys"
        />
      );
    }

    return (
      <Stack spacing={2}>
        {services.map((service) => (
          <ServiceCard
            key={service.id}
            service={service}
            isDefault={service.id === keyManagementConfig.default_service_id}
            canManage={canManageSigningServices}
            onMakeDefault={handleMakeDefault}
            onRemove={handleRemoveService}
            onRotate={handleRotateService}
            onManageCertificate={handleOpenCertDialog}
          />
        ))}
      </Stack>
    );
  };

  const renderKeysInventory = () => {
    if (loading) {
      return <TableSkeleton rows={5} columns={5} showActions={true} />;
    }

    if (error) {
      return (
        <ErrorState
          error={error}
          onRetry={reloadKeys}
          variant="inline"
          message={isAuthError(error) ? t('deploy.signingKeys.errors.sessionExpired') : undefined}
        />
      );
    }

    if (safeKeys.length === 0) {
      return (
        <EmptyState
          icon={VpnKeyIcon}
          title={services.length > 0 ? 'No signing keys discovered yet' : 'No signing services configured'}
          description={
            services.length > 0 && canCreateKeysThroughIssuerWizard
              ? 'The managed OpenBao signer is configured, but no active issuer keys have been created yet. Create an issuer identity and choose "Create new key in KMS"; the wizard will create the key before publishing the DID.'
              : services.length > 0
                ? 'The registered signing service has not surfaced any usable keys yet. Create or verify the key in the KMS provider, check the service key reference above, then refresh discovered keys.'
              : 'Register a key management service in the section above to expose signing keys for issuance and verification.'
          }
          whyItMatters="Signing keys are required to issue and verify credentials."
          actionLabel={
            services.length > 0 && canCreateKeysThroughIssuerWizard
              ? 'Create issuer identity'
              : services.length > 0
                ? 'Refresh discovered keys'
                : undefined
          }
          actionPath={
            services.length > 0 && canCreateKeysThroughIssuerWizard
              ? '/console/org/deploy/issuer-identity/new?key_source=create'
              : undefined
          }
          onAction={services.length > 0 && !canCreateKeysThroughIssuerWizard ? reloadAll : undefined}
          docsUrl="https://docs.example.com/signing-keys"
        />
      );
    }

    return (
      <TableContainer component={Paper}>
        <Table>
          <TableHead>
            <TableRow>
              <TableCell>{t('deploy.signingKeys.tableHeaders.keyId')}</TableCell>
              <TableCell>{t('deploy.signingKeys.tableHeaders.name')}</TableCell>
              <TableCell>{t('deploy.signingKeys.tableHeaders.purpose', 'Purpose')}</TableCell>
              <TableCell>{t('deploy.signingKeys.tableHeaders.algorithm')}</TableCell>
              <TableCell>{t('deploy.signingKeys.tableHeaders.status')}</TableCell>
              <TableCell>{t('deploy.signingKeys.tableHeaders.expiryDate')}</TableCell>
              <TableCell>{t('deploy.signingKeys.tableHeaders.created')}</TableCell>
              <TableCell align="right">Reporting</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {safeKeys.map((key) => (
              <TableRow key={key.id}>
                <TableCell>
                  <Typography variant="body2" fontFamily="monospace" sx={{ wordBreak: 'break-word' }}>
                    {key.provider_key_name || key.id}
                  </Typography>
                </TableCell>
                <TableCell>
                  <Typography variant="body2">
                    {key.name || t('deploy.signingKeys.unnamedKey')}
                  </Typography>
                  <Typography variant="caption" color="text.secondary" sx={{ display: 'block', mt: 0.5 }}>
                    {key.derived_association}
                  </Typography>
                </TableCell>
                <TableCell>
                  <Chip
                    label={key.derived_purpose || t('deploy.signingKeys.purposes.general', 'General signing')}
                    size="small"
                    variant="outlined"
                  />
                </TableCell>
                <TableCell>{key.algorithm}</TableCell>
                <TableCell>
                  <StatusChip
                    status={key.status}
                    color={getStatusColor(key.status)}
                  />
                </TableCell>
                <TableCell>
                  {key.expiry_date ? (
                    <Box>
                      <Typography variant="body2">
                        {formatDate(key.expiry_date)}
                      </Typography>
                      {isExpiringSoon(key.expiry_date) && (
                        <Typography variant="caption" color="warning.main">
                          {t('deploy.signingKeys.expiringSoon')}
                        </Typography>
                      )}
                    </Box>
                  ) : (
                    '-'
                  )}
                </TableCell>
                <TableCell>
                  {formatDate(key.created_at)}
                </TableCell>
                <TableCell align="right">
                  <Tooltip title="Key lifecycle is managed in your external KMS/HSM or DID identity. Configure service connectivity in the section above.">
                    <Typography variant="body2" color="text.secondary">
                      Monitored only
                    </Typography>
                  </Tooltip>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </TableContainer>
    );
  };

  return (
    <ResourcePage
      title={t('deploy.signingKeys.title')}
      description="Register and manage remote KMS/HSM signing services for credential issuance. Private keys remain in your external KMS/HSM."
      breadcrumbs={getBreadcrumbs(t)}
      icon={<VpnKeyIcon />}
      pageTestId="deploy.signingKeys.page"
    >
      <Stack spacing={3}>
        {keyManagementError && (
          <Alert severity="warning">
            {t('deploy.signingKeys.notifications.loadSettingsError')}
          </Alert>
        )}

        {signingKeyMessage && (
          <Alert severity="warning">
            {signingKeyMessage}
          </Alert>
        )}

        {/* === PRIMARY: Remote KMS Services === */}
        <Paper variant="outlined" sx={{ p: { xs: 2.5, md: 3 } }}>
          <Stack direction={{ xs: 'column', sm: 'row' }} justifyContent="space-between" alignItems={{ sm: 'flex-start' }} spacing={2} sx={{ mb: 2 }}>
            <Box>
              <Typography variant="overline" color="text.secondary" sx={{ display: 'block', mb: 0.5 }}>
                Signing services
              </Typography>
              <Typography variant="h5" sx={{ mb: 0.5 }}>
                Remote key management services
              </Typography>
              <Typography variant="body2" color="text.secondary">
                Register one or more KMS/HSM connectors. Elevenidllc stores connector metadata only — private keys remain in your external provider.
              </Typography>
            </Box>
            <Tooltip title={registerServiceDisabledReason} disableHoverListener={!registerServiceDisabledReason}>
              <span>
                <Button
                  variant="contained"
                  startIcon={<AddIcon />}
                  onClick={openServiceWizard}
                  disabled={!canOpenServiceWizard}
                  data-testid="deploy.signingKeys.registerService.action"
                >
                  Register key management service
                </Button>
              </span>
            </Tooltip>
          </Stack>

          {!canManageSigningServices && !permissionsLoading && (
            <Alert severity="info" sx={{ mb: 2 }}>
              Service registration is available from this page. Updating or removing existing services may still require elevated permissions.
            </Alert>
          )}

          {renderServiceRegistry()}
        </Paper>

        {/* === SECONDARY: Discovered Keys === */}
        <Paper variant="outlined" sx={{ p: { xs: 2.5, md: 3 } }}>
          <Stack direction={{ xs: 'column', sm: 'row' }} justifyContent="space-between" alignItems={{ sm: 'flex-start' }} spacing={2} sx={{ mb: 2 }}>
            <Box>
              <Typography variant="overline" color="text.secondary" sx={{ display: 'block', mb: 0.5 }}>
                Discovered keys
              </Typography>
              <Typography variant="h6" sx={{ mb: 0.5 }}>
                Keys reported by connected services
              </Typography>
              <Typography variant="body2" color="text.secondary">
                Keys are surfaced automatically from registered services and DID-linked signing identities. Manage key lifecycle in your KMS/HSM or DID identity; this table reports state only.
              </Typography>
            </Box>
            <Box />
          </Stack>

          {renderKeysInventory()}

          {!loading && safeKeys.some((k) => k.status === 'invalid' || k.status === 'expired') && (
            <Alert severity="warning" sx={{ mt: 2 }}>
              {t('deploy.signingKeys.invalidKeysWarning')}
            </Alert>
          )}
        </Paper>

        <Dialog open={certDialog.isOpen} onClose={certDialog.close} maxWidth="md" fullWidth>
          <DialogTitle>
            Certificate — {certDialog.data?.name || 'Service'}
          </DialogTitle>
          <DialogContent>
            <Box sx={{ mt: 1, display: 'flex', flexDirection: 'column', gap: 2 }}>
              {certAction === 'csr' && certData.csr_pem ? (
                <>
                  <Alert severity="success">
                    CSR generated. Submit the PEM below to your Certificate Authority, then return here to upload the signed certificate.
                  </Alert>
                  <TextField
                    fullWidth
                    multiline
                    rows={10}
                    label="Certificate Signing Request (PEM)"
                    value={certData.csr_pem}
                    slotProps={{
                      input: { readOnly: true, sx: { fontFamily: 'monospace', fontSize: '0.8rem' } }
                    }}
                  />
                  <Button variant="outlined" onClick={() => setCertAction('upload')}>
                    Upload signed certificate
                  </Button>
                </>
              ) : certAction === 'upload' || !certData.cert_pem ? (
                <>
                  <Alert severity="info">
                    Paste the signed certificate PEM from your CA. Include the full chain if available.
                  </Alert>
                  <TextField
                    fullWidth
                    label="Subject common name (for CSR)"
                    value={certData.common_name || ''}
                    onChange={(e) => setCertData((prev) => ({ ...prev, common_name: e.target.value }))}
                  />
                  <Button variant="outlined" onClick={handleGenerateCsr}>
                    Generate CSR from service public key
                  </Button>
                  <TextField
                    fullWidth
                    multiline
                    rows={8}
                    label="Signed certificate PEM"
                    placeholder="-----BEGIN CERTIFICATE-----\n..."
                    value={certData.cert_pem}
                    onChange={(e) => setCertData((prev) => ({ ...prev, cert_pem: e.target.value }))}
                    slotProps={{
                      input: { sx: { fontFamily: 'monospace', fontSize: '0.8rem' } }
                    }}
                  />
                  <TextField
                    fullWidth
                    multiline
                    rows={4}
                    label="Certificate chain PEM (optional)"
                    placeholder="-----BEGIN CERTIFICATE-----\n..."
                    value={certData.cert_chain_pem}
                    onChange={(e) => setCertData((prev) => ({ ...prev, cert_chain_pem: e.target.value }))}
                    slotProps={{
                      input: { sx: { fontFamily: 'monospace', fontSize: '0.8rem' } }
                    }}
                  />
                </>
              ) : (
                <>
                  <Alert severity="success">Certificate is installed.</Alert>
                  <TextField
                    fullWidth
                    multiline
                    rows={8}
                    label="Certificate PEM"
                    value={certData.cert_pem}
                    slotProps={{
                      input: { readOnly: true, sx: { fontFamily: 'monospace', fontSize: '0.8rem' } }
                    }}
                  />
                  <Button variant="outlined" onClick={() => setCertAction('upload')}>
                    Replace certificate
                  </Button>
                </>
              )}
            </Box>
          </DialogContent>
          <DialogActions>
            <Button onClick={certDialog.close}>Close</Button>
            {(certAction === 'upload' || (!certData.cert_pem && certAction === 'view')) && certData.cert_pem && (
              <Button variant="contained" onClick={handleUploadCertificate} disabled={!certData.cert_pem}>
                Save certificate
              </Button>
            )}
          </DialogActions>
        </Dialog>
      </Stack>
    </ResourcePage>
  );
}

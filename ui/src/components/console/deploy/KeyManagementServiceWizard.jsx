import { useCallback, useEffect, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Alert,
  Box,
  Chip,
  Button,
  Checkbox,
  CircularProgress,
  Container,
  Divider,
  FormControl,
  FormControlLabel,
  FormGroup,
  List,
  ListItem,
  ListItemText,
  InputLabel,
  MenuItem,
  Paper,
  Select,
  Step,
  StepLabel,
  Stepper,
  Stack,
  Switch,
  TextField,
  Typography,
} from '@mui/material';
import ArrowBackIcon from '@mui/icons-material/ArrowBack';
import ArrowForwardIcon from '@mui/icons-material/ArrowForward';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import ContentCopyIcon from '@mui/icons-material/ContentCopy';
import HubIcon from '@mui/icons-material/Hub';
import VerifiedIcon from '@mui/icons-material/Verified';

import signingKeysApi from '../../../services/signingKeysApi';
import { useWizard } from '../../../hooks/useWizard';
import { useAsyncData } from '../../../hooks/useAsyncData';
import { useNotifications } from '../../../hooks/useNotifications';
import { useConsole } from '../../../contexts/ConsoleContext';
import {
  DEFAULT_KEY_MANAGEMENT_CONFIG,
  KEY_MANAGEMENT_ALGORITHM_OPTIONS,
  KEY_MANAGEMENT_PURPOSES,
  PURPOSES_REQUIRING_CERTIFICATE,
  PURPOSES_REQUIRING_AUTHORITY,
  createKeyManagementServicePayload,
  getServiceTypeDefinition,
  isAlgorithmAllowedForPurpose,
  normalizeKeyManagementConfig,
} from './keyManagementServiceCatalog';

const MANAGED_OPENBAO_SERVICE_ID = 'managed-openbao-transit';

const STEPS = [
  'Choose Service',
  'Connection',
  'Key Access',
  'Review',
];

const CONNECTION_LABELS = {
  endpoint: 'Service URL',
  region: 'Region / location',
  mount: 'Transit mount',
  namespace: 'Namespace',
};

function logKeyManagementWizardError(message, error) {
  if (import.meta.env?.DEV && import.meta.env?.MODE !== 'test') {
    console.error(message, error);
  }
}

const getProviderRunbook = (data, definition) => {
  const keyReference = data.key_reference?.trim() || '<key-reference>';
  const region = data.region?.trim() || '<region>';
  const endpoint = data.endpoint?.trim() || '<service-url>';
  const mount = data.mount?.trim() || 'transit';

  switch (definition.provider) {
    case 'aws':
      return {
        docsLabel: 'AWS KMS key creation guide',
        docsUrl: 'https://docs.aws.amazon.com/kms/latest/developerguide/create-keys.html',
        command: [
          'aws kms create-key \\\n  --region ' + region + ' \\\n  --key-spec ECC_NIST_P256 \\\n  --key-usage SIGN_VERIFY',
          '# Optional alias for readability',
          'aws kms create-alias \\\n  --alias-name alias/marty-issuer-signing \\\n  --target-key-id <kms-key-id>',
          '# Use resulting key ARN as key reference in Marty',
        ].join('\n'),
      };
    case 'azure':
      return {
        docsLabel: 'Azure Key Vault key creation guide',
        docsUrl: 'https://learn.microsoft.com/en-us/azure/key-vault/keys/quick-create-portal',
        command: [
          'az keyvault key create \\\n  --vault-name <vault-name> \\\n  --name <marty-signing-key> \\\n  --kty EC \\\n  --curve P-256',
          '# Use key identifier URI as key reference in Marty',
        ].join('\n'),
      };
    case 'gcp':
      return {
        docsLabel: 'Google Cloud KMS key creation guide',
        docsUrl: 'https://docs.cloud.google.com/kms/docs/create-key',
        command: [
          'gcloud kms keys create <marty-signing-key> \\\n  --location=' + region + ' \\\n  --keyring=<key-ring> \\\n  --purpose=asymmetric-signing \\\n  --default-algorithm=ec-sign-p256-sha256',
          '# Use crypto key resource path as key reference in Marty',
        ].join('\n'),
      };
    case 'openbao':
    case 'hashicorp-vault':
    case 'custom':
      return {
        docsLabel: 'Vault/OpenBao transit key guide',
        docsUrl: 'https://developer.hashicorp.com/vault/docs/secrets/transit',
        command: [
          mount === 'transit' ? 'vault secrets enable transit' : 'vault secrets enable -path=' + mount + ' transit',
          'vault write -f ' + mount + '/keys/' + keyReference + ' type=ecdsa-p256',
          'vault read ' + mount + '/keys/' + keyReference,
          '# Ensure Marty can reach ' + endpoint + ' and mount ' + mount,
        ].join('\n'),
      };
    default:
      return {
        docsLabel: 'KMS provider key creation guide',
        docsUrl: 'https://docs.example.com/signing-keys',
        command: '# Create a signing-capable key in your provider and paste its identifier into Key reference.',
      };
  }
};

const authModeLabel = (value) => {
  switch (value) {
    case 'service_token':
      return 'Managed service token';
    case 'token':
      return 'Token';
    case 'approle':
      return 'AppRole';
    case 'mtls':
      return 'mTLS';
    case 'iam_role':
      return 'IAM role';
    case 'access_key':
      return 'Access key';
    case 'assume_role':
      return 'Assume role';
    case 'managed_identity':
      return 'Managed identity';
    case 'client_secret':
      return 'Client secret';
    case 'certificate':
      return 'Certificate';
    case 'workload_identity':
      return 'Workload identity';
    case 'service_account':
      return 'Service account';
    case 'api_key':
      return 'API key';
    default:
      return value || 'Custom';
  }
};

function ServiceTypeCard({ definition, selected, onSelect }) {
  const handleKeyDown = (event) => {
    if (event.key === 'Enter' || event.key === ' ') {
      event.preventDefault();
      onSelect(definition);
    }
  };

  return (
    <Paper
      variant="outlined"
      role="button"
      tabIndex={0}
      aria-pressed={selected}
      aria-label={`${definition.label} key management service`}
      onClick={() => onSelect(definition)}
      onKeyDown={handleKeyDown}
      sx={{
        p: 2.5,
        cursor: 'pointer',
        borderColor: selected ? 'primary.main' : 'divider',
        bgcolor: selected ? 'action.selected' : 'background.paper',
        outline: 'none',
        '&:focus-visible': {
          borderColor: 'primary.main',
          boxShadow: (theme) => `0 0 0 3px ${theme.palette.primary.main}33`,
        },
      }}
    >
      <Typography variant="h6" sx={{ mb: 0.5 }}>
        {definition.label}
      </Typography>
      <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
        {definition.description}
      </Typography>
      <Typography variant="caption" color="text.secondary" display="block">
        Protocol: {definition.protocol}
      </Typography>
      <Typography variant="caption" color="text.secondary" display="block">
        Category: {definition.category}
      </Typography>
    </Paper>
  );
}

const KeyManagementServiceWizard = () => {
  const navigate = useNavigate();
  const { showNotification } = useNotifications();
  const { activeOrgId } = useConsole();
  const orgRequestParams = useMemo(
    () => (activeOrgId ? { organization_id: activeOrgId } : {}),
    [activeOrgId],
  );
  const [preflightLoading, setPreflightLoading] = useState(false);
  const [preflightChecks, setPreflightChecks] = useState([]);
  const [registeredService, setRegisteredService] = useState(null);
  const [defaultSelectionSynced, setDefaultSelectionSynced] = useState(false);

  const {
    data: configData,
    loading: configLoading,
    error: configError,
  } = useAsyncData(
    async () => normalizeKeyManagementConfig(
      await signingKeysApi.getKeyManagementConfig(orgRequestParams)
    ),
    [activeOrgId]
  );

  const currentConfig = normalizeKeyManagementConfig(configData || DEFAULT_KEY_MANAGEMENT_CONFIG);
  const serviceCatalog = currentConfig.service_type_catalog;
  const currentDefaultService = currentConfig.services.find((service) => service.id === currentConfig.default_service_id) || null;

  const validateStep = useCallback((stepIndex, data) => {
    const definition = getServiceTypeDefinition(serviceCatalog, data.service_type);
    switch (stepIndex) {
      case 0:
        return Boolean(data.service_type);
      case 1:
        if (!data.name?.trim()) {
          return false;
        }
        if (definition.connection_fields.includes('endpoint') && !data.endpoint?.trim()) {
          return false;
        }
        if (definition.connection_fields.includes('region') && !data.region?.trim()) {
          return false;
        }
        if (definition.connection_fields.includes('mount') && !data.mount?.trim()) {
          return false;
        }
        return Boolean(data.auth_mode);
      case 2:
        if (!Boolean(data.key_reference?.trim() || data.key_aliases?.trim())) {
          return false;
        }
        {
          const algorithms = Array.isArray(data.algorithms)
            ? data.algorithms.filter((algorithm) => typeof algorithm === 'string' && algorithm)
            : [];
          const purposes = Array.isArray(data.key_purposes)
            ? data.key_purposes.filter((purpose) => typeof purpose === 'string' && purpose)
            : [];
          const hasIncompatiblePurpose = purposes.some(
            (purpose) => !algorithms.some((algorithm) => isAlgorithmAllowedForPurpose(purpose, algorithm)),
          );
          return algorithms.length > 0 && !hasIncompatiblePurpose;
        }
      case 3:
        return true;
      default:
        return false;
    }
  }, [serviceCatalog]);

  const handleSubmit = useCallback(async (data) => {
    const newService = createKeyManagementServicePayload(data, serviceCatalog);
    const nextDefaultServiceId = data.make_default
      ? newService.id
      : (currentConfig.default_service_id || newService.id);

    await signingKeysApi.updateKeyManagementConfig({
      ...orgRequestParams,
      services: [...currentConfig.services, newService],
      default_service_id: nextDefaultServiceId,
    });

    setRegisteredService(newService);
    showNotification?.('Registered key management service.', 'success');
    return newService;
  }, [currentConfig.default_service_id, currentConfig.services, orgRequestParams, serviceCatalog, showNotification]);

  const wizard = useWizard({
    steps: STEPS,
    initialData: {
      service_type: '',
      name: '',
      description: '',
      endpoint: '',
      region: '',
      mount: 'transit',
      namespace: '',
      auth_mode: '',
      auth_reference: '',
      key_reference: '',
      key_aliases: '',
      algorithms: ['ES256'],
      key_purposes: [],
      credential_formats: [],
      rotation_interval_days: '',
      rotation_overlap_days: '7',
      rotation_auto_publish: false,
      country_code: '',
      authority_code: '',
      make_default: !currentConfig.default_service_id,
    },
    validateStep,
    onSubmit: handleSubmit,
    onCancel: () => {
      navigate('/console/org/deploy/key-management/services');
    },
  });

  useEffect(() => {
    if (configLoading || defaultSelectionSynced) {
      return;
    }

    wizard.updateData({ make_default: !currentConfig.default_service_id });
    setDefaultSelectionSynced(true);
  }, [configLoading, currentConfig.default_service_id, defaultSelectionSynced, wizard.updateData]);

  const selectedDefinition = getServiceTypeDefinition(serviceCatalog, wizard.data.service_type);
  const providerRunbook = useMemo(
    () => getProviderRunbook(wizard.data, selectedDefinition),
    [selectedDefinition, wizard.data]
  );
  const postRegistrationDefaultService = wizard.data.make_default
    ? registeredService
    : (currentDefaultService || registeredService);
  const registeredServiceIsManagedOpenBao = registeredService?.id === MANAGED_OPENBAO_SERVICE_ID;
  const currentDefaultIsManagedOpenBao = currentDefaultService?.id === MANAGED_OPENBAO_SERVICE_ID;
  const suggestedIssuerKeyName = wizard.data.key_reference?.trim()
    || wizard.data.name?.trim()
    || 'issuer signing key';
  const issuerIdentityCreateUrl = `/console/org/deploy/issuer-identity/new?key_source=create&signing_service_id=${encodeURIComponent(registeredServiceIsManagedOpenBao ? MANAGED_OPENBAO_SERVICE_ID : (postRegistrationDefaultService?.id || MANAGED_OPENBAO_SERVICE_ID))}&key_name=${encodeURIComponent(suggestedIssuerKeyName)}`;
  const managedIssuerIdentityCreateUrl = `/console/org/deploy/issuer-identity/new?key_source=create&signing_service_id=${encodeURIComponent(MANAGED_OPENBAO_SERVICE_ID)}&key_name=${encodeURIComponent(suggestedIssuerKeyName)}`;

  const copyText = useCallback(async (text) => {
    try {
      await navigator.clipboard.writeText(text);
      showNotification?.('Copied to clipboard.', 'success');
    } catch (error) {
      logKeyManagementWizardError('Failed to copy command:', error);
      showNotification?.('Unable to copy to clipboard.', 'error');
    }
  }, [showNotification]);

  const runPreflightChecks = useCallback(async () => {
    setPreflightLoading(true);
    try {
      const response = await signingKeysApi.validateKeyManagementService({
        ...orgRequestParams,
        service_type: wizard.data.service_type,
        name: wizard.data.name,
        endpoint: wizard.data.endpoint,
        region: wizard.data.region,
        mount: wizard.data.mount,
        namespace: wizard.data.namespace,
        auth_mode: wizard.data.auth_mode,
        auth_reference: wizard.data.auth_reference,
        key_reference: wizard.data.key_reference,
        key_aliases: wizard.data.key_aliases,
        algorithms: wizard.data.algorithms,
      });

      const checks = Array.isArray(response?.checks)
        ? response.checks.filter((entry) => entry && typeof entry.name === 'string')
        : [];

      if (checks.length === 0) {
        setPreflightChecks([
          {
            name: 'Validation status',
            status: 'warning',
            detail: 'No validation results were returned by the gateway.',
          },
        ]);
      } else {
        setPreflightChecks(checks);
      }
    } catch (error) {
      logKeyManagementWizardError('Failed to run preflight checks:', error);
      setPreflightChecks([
        {
          name: 'Validation status',
          status: 'warning',
          detail: 'Gateway validation failed. Verify connectivity and credentials, then try again.',
        },
      ]);
    } finally {
      setPreflightLoading(false);
    }
  }, [orgRequestParams, wizard.data.algorithms, wizard.data.auth_mode, wizard.data.auth_reference, wizard.data.endpoint, wizard.data.key_aliases, wizard.data.key_reference, wizard.data.mount, wizard.data.name, wizard.data.namespace, wizard.data.region, wizard.data.service_type]);

  const handleSelectServiceType = (definition) => {
    setPreflightChecks([]);
    wizard.updateData({
      service_type: definition.id,
      auth_mode: definition.auth_modes[0] || 'custom',
      mount: definition.connection_fields.includes('mount') ? (wizard.data.mount || 'transit') : '',
      namespace: definition.connection_fields.includes('namespace') ? wizard.data.namespace : '',
      endpoint: definition.connection_fields.includes('endpoint') ? wizard.data.endpoint : '',
      region: definition.connection_fields.includes('region') ? wizard.data.region : '',
    });
  };

  const toggleAlgorithm = (algorithm) => {
    const currentAlgorithms = Array.isArray(wizard.data.algorithms) ? wizard.data.algorithms : [];
    const nextAlgorithms = currentAlgorithms.includes(algorithm)
      ? currentAlgorithms.filter((value) => value !== algorithm)
      : [...currentAlgorithms, algorithm]

    const normalizedAlgorithms = nextAlgorithms.length > 0 ? nextAlgorithms : [algorithm]
    const currentPurposes = Array.isArray(wizard.data.key_purposes) ? wizard.data.key_purposes : []
    const compatiblePurposes = currentPurposes.filter((purpose) => (
      normalizedAlgorithms.some((candidateAlgorithm) => isAlgorithmAllowedForPurpose(purpose, candidateAlgorithm))
    ))

    wizard.updateData({
      algorithms: normalizedAlgorithms,
      key_purposes: compatiblePurposes,
    });
  };

  const renderChooseServiceStep = () => (
    <Box>
      <Typography variant="h5" gutterBottom>
        Choose a key management service
      </Typography>
      <Typography color="text.secondary" sx={{ mb: 3 }}>
        Marty expects private signing keys to stay in your KMS, HSM, or transit-compatible signer. This flow registers how we reach that service.
      </Typography>
      <Alert severity="info" sx={{ mb: 3 }}>
        Known providers are listed first, plus a custom transit-compatible option for services that implement the protocol Marty supports.
      </Alert>
      <Box sx={{ display: 'grid', gap: 2, gridTemplateColumns: { xs: '1fr', md: 'repeat(2, minmax(0, 1fr))' } }}>
        {serviceCatalog.map((definition) => (
          <ServiceTypeCard
            key={definition.id}
            definition={definition}
            selected={wizard.data.service_type === definition.id}
            onSelect={handleSelectServiceType}
          />
        ))}
      </Box>
    </Box>
  );

  const renderConnectionField = (fieldName) => {
    const isOptional = fieldName === 'namespace';
    return (
      <TextField
        key={fieldName}
        fullWidth
        label={CONNECTION_LABELS[fieldName] || fieldName}
        value={wizard.data[fieldName] || ''}
        required={!isOptional}
        onChange={(event) => wizard.updateData({ [fieldName]: event.target.value })}
      />
    );
  };

  const renderConnectionStep = () => (
    <Box>
      <Typography variant="h5" gutterBottom>
        Connection details
      </Typography>
      <Typography color="text.secondary" sx={{ mb: 3 }}>
        Tell Marty how to reach {selectedDefinition.label} and which credential reference or workload identity it should use.
      </Typography>
      <Box sx={{ display: 'grid', gap: 2 }}>
        <TextField
          fullWidth
          required
          label="Service name"
          value={wizard.data.name}
          onChange={(event) => wizard.updateData({ name: event.target.value })}
        />
        <TextField
          fullWidth
          multiline
          minRows={2}
          label="Description"
          value={wizard.data.description}
          onChange={(event) => wizard.updateData({ description: event.target.value })}
        />
        {selectedDefinition.connection_fields.map((fieldName) => renderConnectionField(fieldName))}
        <FormControl fullWidth>
          <InputLabel>Authentication mode</InputLabel>
          <Select
            label="Authentication mode"
            value={wizard.data.auth_mode || selectedDefinition.auth_modes[0] || ''}
            onChange={(event) => wizard.updateData({ auth_mode: event.target.value })}
          >
            {selectedDefinition.auth_modes.map((authMode) => (
              <MenuItem key={authMode} value={authMode}>
                {authModeLabel(authMode)}
              </MenuItem>
            ))}
          </Select>
        </FormControl>
        <TextField
          fullWidth
          label="Credential reference"
          helperText="Store secret material outside Marty and reference it here, for example a secret name, policy name, or workload identity."
          value={wizard.data.auth_reference}
          onChange={(event) => wizard.updateData({ auth_reference: event.target.value })}
        />
      </Box>
    </Box>
  );

  const togglePurpose = (purpose) => {
    const current = Array.isArray(wizard.data.key_purposes) ? wizard.data.key_purposes : [];
    const selectedAlgorithms = Array.isArray(wizard.data.algorithms) ? wizard.data.algorithms : [];
    const isCompatible = selectedAlgorithms.some((algorithm) => isAlgorithmAllowedForPurpose(purpose, algorithm));

    if (!current.includes(purpose) && !isCompatible) {
      showNotification?.('This purpose is incompatible with the currently selected algorithms.', 'warning');
      return;
    }

    const next = current.includes(purpose)
      ? current.filter((p) => p !== purpose)
      : [...current, purpose];
    wizard.updateData({ key_purposes: next });
  };

  const selectedAlgorithms = Array.isArray(wizard.data.algorithms) ? wizard.data.algorithms : [];
  const selectedPurposes = Array.isArray(wizard.data.key_purposes) ? wizard.data.key_purposes : [];
  const incompatibleSelectedPurposes = selectedPurposes.filter(
    (purpose) => !selectedAlgorithms.some((algorithm) => isAlgorithmAllowedForPurpose(purpose, algorithm)),
  );
  const showAuthorityFields = selectedPurposes.some((p) => PURPOSES_REQUIRING_AUTHORITY.includes(p));

  const renderKeyAccessStep = () => (
    <Box>
      <Typography variant="h5" gutterBottom>
        Key access
      </Typography>
      <Typography color="text.secondary" sx={{ mb: 3 }}>
        Identify the signing key, its purposes, and optional rotation policy.
      </Typography>
      <Box sx={{ display: 'grid', gap: 2 }}>
        <TextField
          fullWidth
          required
          label={selectedDefinition.key_reference_label}
          value={wizard.data.key_reference}
          onChange={(event) => wizard.updateData({ key_reference: event.target.value })}
        />
        <TextField
          fullWidth
          label="Additional key aliases"
          helperText="Optional comma-separated aliases or secondary references."
          value={wizard.data.key_aliases}
          onChange={(event) => wizard.updateData({ key_aliases: event.target.value })}
        />
        <FormControl component="fieldset">
          <Typography variant="body2" fontWeight="medium" sx={{ mb: 1 }}>
            Supported algorithms
          </Typography>
          <FormGroup row>
            {KEY_MANAGEMENT_ALGORITHM_OPTIONS.map((algorithm) => (
              <FormControlLabel
                key={algorithm}
                control={(
                  <Checkbox
                    checked={(wizard.data.algorithms || []).includes(algorithm)}
                    onChange={() => toggleAlgorithm(algorithm)}
                  />
                )}
                label={algorithm}
              />
            ))}
          </FormGroup>
        </FormControl>

        <FormControl component="fieldset">
          <Typography variant="body2" fontWeight="medium" sx={{ mb: 1 }}>
            Key purposes
          </Typography>
          <Typography variant="caption" color="text.secondary" sx={{ mb: 1, display: 'block' }}>
            Select all purposes this signing key will serve. Marty uses these to automatically select the right key during issuance.
          </Typography>

          {incompatibleSelectedPurposes.length > 0 && (
            <Alert severity="warning" sx={{ mb: 1 }}>
              Update selected algorithms or remove incompatible purposes: {incompatibleSelectedPurposes.join(', ')}.
            </Alert>
          )}

          <FormGroup>
            {KEY_MANAGEMENT_PURPOSES.map((purpose) => {
              const allowedWithSelection = selectedAlgorithms.some((algorithm) => isAlgorithmAllowedForPurpose(purpose.value, algorithm));
              return (
                <FormControlLabel
                  key={purpose.value}
                  control={(
                    <Checkbox
                      checked={selectedPurposes.includes(purpose.value)}
                      disabled={!allowedWithSelection && !selectedPurposes.includes(purpose.value)}
                      onChange={() => togglePurpose(purpose.value)}
                    />
                  )}
                  label={
                    <Box>
                      <Typography variant="body2">{purpose.label}</Typography>
                      {purpose.formats.length > 0 && (
                        <Typography variant="caption" color="text.secondary">
                          Formats: {purpose.formats.join(', ')}
                        </Typography>
                      )}
                      {!allowedWithSelection && (
                        <Typography variant="caption" color="warning.main" sx={{ display: 'block' }}>
                          Select a compatible algorithm first.
                        </Typography>
                      )}
                    </Box>
                  }
                />
              );
            })}
          </FormGroup>
        </FormControl>

        {showAuthorityFields && (
          <>
            <TextField
              fullWidth
              label="Country code (ISO 3166-1 alpha-2)"
              helperText="Required for VDS-NC, CSCA, and mDoc DSC services."
              value={wizard.data.country_code || ''}
              onChange={(event) => wizard.updateData({ country_code: event.target.value.toUpperCase() })}
              slotProps={{
                htmlInput: { maxLength: 2 }
              }}
            />
            <TextField
              fullWidth
              label="Authority code"
              helperText="Optional issuing authority identifier."
              value={wizard.data.authority_code || ''}
              onChange={(event) => wizard.updateData({ authority_code: event.target.value })}
            />
          </>
        )}

        <Divider />
        <Typography variant="body2" fontWeight="medium">
          Rotation policy (optional)
        </Typography>
        <Typography variant="caption" color="text.secondary" sx={{ mt: -1, display: 'block' }}>
          Leave blank to manage rotation manually.
        </Typography>
        <TextField
          fullWidth
          type="number"
          label="Rotation interval (days)"
          helperText="How often to rotate this key. Leave blank for manual rotation."
          value={wizard.data.rotation_interval_days || ''}
          onChange={(event) => wizard.updateData({ rotation_interval_days: event.target.value })}
          slotProps={{
            htmlInput: { min: 1 }
          }}
        />
        {wizard.data.rotation_interval_days && (
          <TextField
            fullWidth
            type="number"
            label="Key overlap period (days)"
            helperText="How long to keep the old key active after rotation for in-flight verifications."
            value={wizard.data.rotation_overlap_days || '7'}
            onChange={(event) => wizard.updateData({ rotation_overlap_days: event.target.value })}
            slotProps={{
              htmlInput: { min: 0 }
            }}
          />
        )}
        <Divider />
        <FormControlLabel
          control={(
            <Switch
              checked={Boolean(wizard.data.make_default)}
              onChange={(event) => wizard.updateData({ make_default: event.target.checked })}
            />
          )}
          label="Use as the default signing service"
        />
        <Alert severity="info">
          This registers the service metadata only. Private keys remain in your external KMS/HSM.
        </Alert>
      </Box>
    </Box>
  );

  const renderReviewStep = () => (
    <Box>
      <Typography variant="h5" gutterBottom>
        Review
      </Typography>
      <Typography color="text.secondary" sx={{ mb: 3 }}>
        Confirm the registration details before saving this signing service.
      </Typography>
      <Paper variant="outlined" sx={{ p: 3 }}>
        <Typography variant="h6" sx={{ mb: 1.5 }}>
          {wizard.data.name || selectedDefinition.label}
        </Typography>
        <Typography variant="body2" sx={{ mb: 0.75 }}>
          Service type: {selectedDefinition.label}
        </Typography>
        <Typography variant="body2" sx={{ mb: 0.75 }}>
          Protocol: {selectedDefinition.protocol}
        </Typography>
        <Typography variant="body2" sx={{ mb: 0.75 }}>
          Endpoint: {wizard.data.endpoint || '-'}
        </Typography>
        <Typography variant="body2" sx={{ mb: 0.75 }}>
          Region: {wizard.data.region || '-'}
        </Typography>
        <Typography variant="body2" sx={{ mb: 0.75 }}>
          Mount: {wizard.data.mount || '-'}
        </Typography>
        <Typography variant="body2" sx={{ mb: 0.75 }}>
          Authentication: {authModeLabel(wizard.data.auth_mode)}
        </Typography>
        <Typography variant="body2" sx={{ mb: 0.75 }}>
          Credential reference: {wizard.data.auth_reference || '-'}
        </Typography>
        <Typography variant="body2" sx={{ mb: 0.75 }}>
          {selectedDefinition.key_reference_label}: {wizard.data.key_reference || '-'}
        </Typography>
        <Typography variant="body2" sx={{ mb: 0.75 }}>
          Additional aliases: {wizard.data.key_aliases || '-'}
        </Typography>
        <Typography variant="body2" sx={{ mb: 0.75 }}>
          Algorithms: {(wizard.data.algorithms || []).join(', ') || '-'}
        </Typography>
        <Typography variant="body2" sx={{ mb: 0.75 }}>
          Key purposes: {(wizard.data.key_purposes || []).join(', ') || 'Not specified'}
        </Typography>
        {wizard.data.country_code && (
          <Typography variant="body2" sx={{ mb: 0.75 }}>
            Country code: {wizard.data.country_code}
            {wizard.data.authority_code ? ` / Authority: ${wizard.data.authority_code}` : ''}
          </Typography>
        )}
        {wizard.data.rotation_interval_days && (
          <Typography variant="body2" sx={{ mb: 0.75 }}>
            Rotation: every {wizard.data.rotation_interval_days} days
            {wizard.data.rotation_overlap_days ? `, ${wizard.data.rotation_overlap_days}d overlap` : ''}
            {wizard.data.rotation_auto_publish ? ', auto-publish' : ''}
          </Typography>
        )}
        <Typography variant="body2">
          Default signer: {wizard.data.make_default ? 'Yes' : 'No'}
        </Typography>
      </Paper>

      <Paper variant="outlined" sx={{ p: 3, mt: 2 }}>
        <Stack direction={{ xs: 'column', md: 'row' }} spacing={2} justifyContent="space-between" sx={{ mb: 2 }}>
          <Box>
            <Typography variant="h6" sx={{ mb: 0.5 }}>
              Validate connection
            </Typography>
            <Typography variant="body2" color="text.secondary">
              Run preflight checks for auth reference, key reference, algorithm coverage, and signer capability before saving.
            </Typography>
          </Box>
          <Button
            variant="outlined"
            startIcon={preflightLoading ? <CircularProgress size={16} /> : <VerifiedIcon />}
            onClick={runPreflightChecks}
            disabled={preflightLoading}
          >
            {preflightLoading ? 'Validating...' : 'Validate connection'}
          </Button>
        </Stack>

        {preflightChecks.length > 0 ? (
          <List dense>
            {preflightChecks.map((entry) => (
              <ListItem key={entry.name} disableGutters>
                <ListItemText
                  primary={entry.name}
                  secondary={entry.detail}
                />
                <Chip
                  size="small"
                  label={entry.status === 'pass' ? 'Pass' : entry.status === 'fail' ? 'Fail' : 'Warning'}
                  color={entry.status === 'pass' ? 'success' : entry.status === 'fail' ? 'error' : 'warning'}
                />
              </ListItem>
            ))}
          </List>
        ) : (
          <Typography variant="body2" color="text.secondary">
            No preflight checks run yet.
          </Typography>
        )}
      </Paper>

      <Paper variant="outlined" sx={{ p: 3, mt: 2 }}>
        <Typography variant="h6" sx={{ mb: 0.5 }}>
          Provider setup shortcut
        </Typography>
        <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
          Use this command to create or reference a signer in your provider, then keep the resulting key identifier in the Key reference field.
        </Typography>

        <Stack direction={{ xs: 'column', md: 'row' }} spacing={1.5} sx={{ mb: 2 }}>
          <Button
            component="a"
            href={providerRunbook.docsUrl}
            target="_blank"
            rel="noopener noreferrer"
            variant="text"
          >
            {providerRunbook.docsLabel}
          </Button>
          <Button
            variant="outlined"
            startIcon={<ContentCopyIcon />}
            onClick={() => copyText(providerRunbook.command)}
          >
            Copy command
          </Button>
        </Stack>

        <Divider sx={{ mb: 2 }} />
        <Box
          component="pre"
          sx={{
            p: 2,
            borderRadius: 1,
            bgcolor: 'grey.100',
            overflowX: 'auto',
            whiteSpace: 'pre-wrap',
            wordBreak: 'break-word',
            fontFamily: 'monospace',
            fontSize: '0.8rem',
            m: 0,
          }}
        >
          {providerRunbook.command}
        </Box>

        <Alert severity="info" sx={{ mt: 2 }}>
          Registering a service does not create a signing key. The issuer identity wizard can create keys only with the
          Marty managed OpenBao service. For registered external KMS services, create the key in the provider first,
          validate the key reference, then choose "Use existing key from KMS" in the issuer identity wizard.
        </Alert>
      </Paper>
    </Box>
  );

  const renderStepContent = () => {
    switch (wizard.activeStep) {
      case 0:
        return renderChooseServiceStep();
      case 1:
        return renderConnectionStep();
      case 2:
        return renderKeyAccessStep();
      case 3:
        return renderReviewStep();
      default:
        return null;
    }
  };

  if (configLoading) {
    return (
      <Container maxWidth="md" sx={{ py: 6 }}>
        <Paper elevation={2} sx={{ p: 4, textAlign: 'center' }}>
          <CircularProgress />
          <Typography sx={{ mt: 2 }}>Loading key management services...</Typography>
        </Paper>
      </Container>
    );
  }

  if (configError) {
    return (
      <Container maxWidth="md" sx={{ py: 6 }}>
        <Paper elevation={2} sx={{ p: 4 }}>
          <Alert severity="error">Unable to load the signing service registry.</Alert>
        </Paper>
      </Container>
    );
  }

  if (wizard.success) {
    return (
      <Container maxWidth="md" sx={{ py: 4 }}>
        <Paper elevation={3} sx={{ p: 4 }}>
          <Stack spacing={3} alignItems="center" textAlign="center">
            <CheckCircleIcon color="success" sx={{ fontSize: 64 }} />
            <Box>
              <Typography variant="h5" gutterBottom>
                Signing service registered
              </Typography>
              <Typography color="text.secondary">
                {wizard.data.name || selectedDefinition.label} has been added to the signing service registry.
              </Typography>
            </Box>
          </Stack>

          <Alert severity={registeredServiceIsManagedOpenBao ? 'success' : 'info'} sx={{ mt: 3 }}>
            {registeredServiceIsManagedOpenBao
              ? 'Next, create an issuer identity and choose "Create new key in KMS". The wizard will call the signing-key create endpoint, refresh the discovered key inventory, and bind the new key to the DID identity.'
              : 'Next, create or verify the signing key in the KMS provider you just registered, then create an issuer identity and choose "Use existing key from KMS". Console key creation is available only for the Marty managed OpenBao transit service.'}
          </Alert>

          {!registeredServiceIsManagedOpenBao && (
            <Paper variant="outlined" sx={{ p: 2, mt: 2 }}>
              <Stack direction={{ xs: 'column', sm: 'row' }} spacing={1.5} justifyContent="space-between" alignItems={{ sm: 'center' }}>
                <Box textAlign="left">
                  <Typography variant="subtitle2">Provider key setup</Typography>
                  <Typography variant="body2" color="text.secondary">
                    Create or verify {wizard.data.key_reference || 'the configured key reference'} before issuer identity setup.
                  </Typography>
                </Box>
                <Button
                  variant="outlined"
                  startIcon={<ContentCopyIcon />}
                  onClick={() => copyText(providerRunbook.command)}
                >
                  Copy command
                </Button>
              </Stack>
            </Paper>
          )}

          <Stack direction={{ xs: 'column', sm: 'row' }} spacing={1.5} justifyContent="center" sx={{ mt: 3 }}>
            <Button
              variant="contained"
              onClick={() => navigate(registeredServiceIsManagedOpenBao ? issuerIdentityCreateUrl : '/console/org/deploy/issuer-identity/new')}
            >
              Create issuer identity
            </Button>
            {!registeredServiceIsManagedOpenBao && currentDefaultIsManagedOpenBao && (
              <Button variant="outlined" onClick={() => navigate(managedIssuerIdentityCreateUrl)}>
                Use managed OpenBao key creation
              </Button>
            )}
            <Button variant="outlined" onClick={() => navigate('/console/org/deploy/key-management/services')}>
              View key management
            </Button>
          </Stack>
        </Paper>
      </Container>
    );
  }

  return (
    <Container maxWidth="lg" sx={{ py: 4 }}>
      <Paper elevation={3} sx={{ p: 4 }}>
        <Box sx={{ mb: 4 }}>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5, mb: 1 }}>
            <HubIcon color="primary" />
            <Typography variant="h4">Register Key Management Service</Typography>
          </Box>
          <Typography color="text.secondary">
            Create a reusable registration for a KMS, HSM, or custom transit-compatible signing service.
          </Typography>
        </Box>

        <Stepper activeStep={wizard.activeStep} sx={{ mb: 4 }}>
          {STEPS.map((label) => (
            <Step key={label}>
              <StepLabel>{label}</StepLabel>
            </Step>
          ))}
        </Stepper>

        {wizard.error && (
          <Alert severity="error" sx={{ mb: 3 }}>
            {wizard.error}
          </Alert>
        )}

        <Box sx={{ minHeight: 420, mb: 4 }}>
          {renderStepContent()}
        </Box>

        <Box sx={{ display: 'flex', justifyContent: 'space-between', pt: 2 }}>
          <Button
            onClick={wizard.isFirstStep ? wizard.cancel : wizard.goBack}
            startIcon={<ArrowBackIcon />}
            disabled={wizard.loading}
          >
            {wizard.isFirstStep ? 'Cancel' : 'Back'}
          </Button>

          {wizard.isLastStep ? (
            <Button
              variant="contained"
              onClick={wizard.submit}
              disabled={!wizard.isStepValid() || wizard.loading}
              startIcon={wizard.loading ? <CircularProgress size={20} /> : <CheckCircleIcon />}
            >
              {wizard.loading ? 'Saving...' : 'Register service'}
            </Button>
          ) : (
            <Button
              variant="contained"
              onClick={wizard.goNext}
              disabled={!wizard.isStepValid() || wizard.loading}
              endIcon={<ArrowForwardIcon />}
            >
              Next
            </Button>
          )}
        </Box>
      </Paper>
    </Container>
  );
};

export default KeyManagementServiceWizard;

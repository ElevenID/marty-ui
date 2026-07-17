import { useCallback, useEffect, useMemo, useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import {
  Alert,
  Box,
  Button,
  Chip,
  CircularProgress,
  Container,
  Divider,
  FormControl,
  InputLabel,
  MenuItem,
  Paper,
  Select,
  Stack,
  Step,
  StepLabel,
  Stepper,
  TextField,
  Typography,
} from '@mui/material';
import ArrowBackIcon from '@mui/icons-material/ArrowBack';
import ArrowForwardIcon from '@mui/icons-material/ArrowForward';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import ContentCopyIcon from '@mui/icons-material/ContentCopy';
import ErrorOutlineIcon from '@mui/icons-material/ErrorOutlined';
import LanguageIcon from '@mui/icons-material/Language';
import SettingsIcon from '@mui/icons-material/Settings';
import VpnKeyIcon from '@mui/icons-material/VpnKey';
import WarningAmberIcon from '@mui/icons-material/WarningAmber';

import signingKeysApi from '../../../services/signingKeysApi';
import { useWizard } from '../../../hooks/useWizard';
import { useAsyncData } from '../../../hooks/useAsyncData';
import { useAuth } from '../../../hooks/useAuth';
import { useNotifications } from '../../../hooks/useNotifications';
import { useConsole } from '../../../contexts/ConsoleContext';
import { getOrganizationLifecycle } from '../../../services/dashboardApi';
import {
  DEFAULT_KEY_MANAGEMENT_CONFIG,
  KEY_MANAGEMENT_PURPOSES,
  normalizeKeyManagementConfig,
  getDefaultKeyManagementService,
  getAllowedAlgorithmsForPurpose,
  getCompatiblePurposesForAlgorithm,
  isAlgorithmAllowedForPurpose,
} from './keyManagementServiceCatalog';
import {
  buildDidIdentities,
  buildDidMethodCatalog,
} from './didIdentityUtils';
import {
  isDidWebX509ChainEligible,
  normalizePlanTier,
} from './kmsEntitlements';

const STEPS = [
  'Choose DID Method',
  'Key Source',
  'Key Configuration',
  'DID Configuration',
  'Review & Publish',
];

const METHOD_OPTIONS = [
  {
    id: 'did:web',
    label: 'did:web',
    description: 'Best fit for production issuers. Hosted DID document on your web domain.',
    resolverMode: 'Hosted document',
    requirements: ['Public domain or issuer base URL', 'KMS-managed signing key'],
  },
  {
    id: 'did:jwk',
    label: 'did:jwk',
    description: 'Portable DID derived directly from a public JWK. No hosting required.',
    resolverMode: 'Self-contained identifier',
    requirements: ['KMS-managed signing key with public JWK'],
  },
  {
    id: 'did:key',
    label: 'did:key',
    description: 'Compact DID from public multibase key material. Useful for local and agent identities.',
    resolverMode: 'Self-derived from multibase key',
    requirements: ['KMS-managed signing key with multibase key material'],
  },
];

const KEY_SOURCE_OPTIONS = [
  {
    id: 'existing',
    label: 'Use existing key from KMS',
    description: 'Select a signing key already managed by your connected key management service.',
  },
  {
    id: 'create',
    label: 'Create new key in KMS',
    description: 'Request your connected KMS to generate a new signing key. The private key stays in the KMS.',
  },
];

const WIZARD_KEY_PURPOSES = ['vc_jwt_issuer', 'mdoc_dsc', 'x509_doc_signer', 'jwks_signing'];
const WIZARD_KEY_PURPOSE_OPTIONS = KEY_MANAGEMENT_PURPOSES.filter((purpose) => WIZARD_KEY_PURPOSES.includes(purpose.value));

const IDENTITY_LABEL_SUFFIX = {
  'did:web': 'web issuer',
  'did:jwk': 'JWK issuer',
  'did:key': 'key issuer',
};

const MANAGED_OPENBAO_SERVICE_ID = 'managed-openbao-transit';
const KEY_REFERENCE_PREFIX = /^cred-(issuer|dsc|key|signer)-/i;

const humanizeKeyLabel = (value) => value
  .split(/[-_]+/)
  .filter(Boolean)
  .map((segment) => {
    const normalized = segment.toLowerCase();
    if (normalized === 'es256' || normalized === 'es384' || normalized === 'rs256' || normalized === 'eddsa') {
      return normalized.toUpperCase();
    }
    return segment.charAt(0).toUpperCase() + segment.slice(1);
  })
  .join(' ');

const deriveKeyHint = (keyReference) => {
  if (typeof keyReference !== 'string') {
    return '';
  }
  const trimmed = keyReference.trim();
  if (!trimmed) {
    return '';
  }
  const compact = trimmed.replace(KEY_REFERENCE_PREFIX, '');
  return humanizeKeyLabel(compact || trimmed);
};

const METHOD_PRIORITY_BY_COMPLIANCE = {
  vc_jwt_issuer: ['did:web', 'did:jwk', 'did:key'],
  jwks_signing: ['did:jwk', 'did:web', 'did:key'],
  mdoc_dsc: ['did:web', 'did:key', 'did:jwk'],
  x509_doc_signer: ['did:web', 'did:key', 'did:jwk'],
};

const getCompatibilityByMethodForKey = ({ key, domainSummary }) => {
  if (!key || !key.id) {
    return {
      'did:web': true,
      'did:jwk': true,
      'did:key': true,
    };
  }

  const derived = buildDidIdentities({ keys: [key], domainSummary });
  const supportedMethods = new Set(derived.map((entry) => entry.method));
  return {
    'did:web': true,
    'did:jwk': supportedMethods.has('did:jwk'),
    'did:key': supportedMethods.has('did:key'),
  };
};

const pickRecommendedMethod = ({ compatibility, complianceTarget, publicDomain }) => {
  const orderedMethods = METHOD_PRIORITY_BY_COMPLIANCE[complianceTarget] || METHOD_PRIORITY_BY_COMPLIANCE.vc_jwt_issuer;

  for (const method of orderedMethods) {
    if (!compatibility[method]) {
      continue;
    }
    if (method === 'did:web' && !publicDomain && orderedMethods[0] !== 'did:web') {
      continue;
    }
    return method;
  }

  return orderedMethods.find((method) => compatibility[method]) || 'did:web';
};

function MethodCard({ method, selected, onSelect, ready, readinessLabel }) {
  return (
    <Paper
      variant="outlined"
      onClick={() => {
        if (!method.disabled) {
          onSelect(method.id);
        }
      }}
      sx={{
        p: 2.5,
        cursor: method.disabled ? 'not-allowed' : 'pointer',
        borderColor: selected ? 'primary.main' : 'divider',
        bgcolor: selected ? 'action.selected' : 'background.paper',
        opacity: method.disabled ? 0.55 : 1,
      }}
    >
      <Stack direction="row" spacing={1} alignItems="center" sx={{ mb: 1 }}>
        <Typography variant="h6">{method.label}</Typography>
        <Chip
          size="small"
          color={ready ? 'success' : 'warning'}
          label={readinessLabel || (ready ? 'Ready' : 'Needs setup')}
        />
        {method.disabled && (
          <Chip size="small" color="default" label="Incompatible with selected key" />
        )}
      </Stack>
      <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
        {method.description}
      </Typography>
      <Typography variant="caption" color="text.secondary" display="block">
        Resolver: {method.resolverMode}
      </Typography>
      <Box component="ul" sx={{ mt: 1, pl: 2, mb: 0 }}>
        {method.requirements.map((req) => (
          <Box component="li" key={req}>
            <Typography variant="caption">{req}</Typography>
          </Box>
        ))}
      </Box>
    </Paper>
  );
}

function KeySourceCard({ option, selected, onSelect, disabled = false, disabledReason = '' }) {
  return (
    <Paper
      variant="outlined"
      onClick={() => {
        if (!disabled) {
          onSelect(option.id);
        }
      }}
      sx={{
        p: 2.5,
        cursor: disabled ? 'not-allowed' : 'pointer',
        borderColor: selected ? 'primary.main' : 'divider',
        bgcolor: selected ? 'action.selected' : 'background.paper',
        opacity: disabled ? 0.58 : 1,
      }}
      aria-disabled={disabled}
    >
      <Typography variant="h6" sx={{ mb: 0.5 }}>{option.label}</Typography>
      <Typography variant="body2" color="text.secondary">{option.description}</Typography>
      {disabled && disabledReason && (
        <Alert severity="warning" sx={{ mt: 1.5 }}>
          {disabledReason}
        </Alert>
      )}
    </Paper>
  );
}

export default function IssuerIdentityWizard() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const prefillKeyId = searchParams.get('prefill_key_id') || '';
  const requestedKeySource = searchParams.get('key_source') === 'create' ? 'create' : '';
  const requestedNewKeyName = searchParams.get('key_name') || '';
  const requestedSigningServiceId = searchParams.get('signing_service_id') || '';
  const { organizationId, organizationName } = useAuth();
  const { activeOrgId, memberships } = useConsole();
  const activeOrganization = useMemo(
    () => (memberships || []).find((organization) => organization.id === activeOrgId) || null,
    [activeOrgId, memberships]
  );
  const effectiveOrganizationId = activeOrgId;
  const effectiveOrganizationName = activeOrganization?.display_name || activeOrganization?.name || organizationName;
  const { showNotification } = useNotifications();
  const [publishResult, setPublishResult] = useState(null);
  const [preflightAcknowledged, setPreflightAcknowledged] = useState(false);

  const {
    data: signingKeysData,
    loading: keysLoading,
  } = useAsyncData(async () => {
    const data = await signingKeysApi.listSigningKeys({ organization_id: effectiveOrganizationId });
    const rawKeys = Array.isArray(data) ? data : data?.keys || [];
    return {
      keys: Array.isArray(rawKeys) ? rawKeys.filter((k) => k && typeof k === 'object') : [],
      domainConfig: data?.domain_config || null,
    };
  }, [effectiveOrganizationId]);

  const {
    data: configData,
    loading: configLoading,
    error: configError,
    reload: reloadConfig,
  } = useAsyncData(
    async () => normalizeKeyManagementConfig(
      await signingKeysApi.getKeyManagementConfig({ organization_id: effectiveOrganizationId })
    ),
    [effectiveOrganizationId],
  );

  const { data: organizationLifecycle } = useAsyncData(async () => {
    if (!effectiveOrganizationId) return null;
    return getOrganizationLifecycle(effectiveOrganizationId);
  }, [effectiveOrganizationId]);

  const keyManagementConfig = normalizeKeyManagementConfig(configData || DEFAULT_KEY_MANAGEMENT_CONFIG);
  const defaultService = getDefaultKeyManagementService(keyManagementConfig);
  const safeKeys = useMemo(
    () => (Array.isArray(signingKeysData?.keys) ? signingKeysData.keys : []),
    [signingKeysData?.keys],
  );
  const domainSummary = keyManagementConfig.domain_config || signingKeysData?.domainConfig || null;
  const planTier = normalizePlanTier(organizationLifecycle?.planTier);
  const x509Eligible = isDidWebX509ChainEligible(planTier);
  const publicDomain = domainSummary?.public_domain || '';
  const managedOpenBaoService = keyManagementConfig.services.find((service) => service.id === MANAGED_OPENBAO_SERVICE_ID) || null;
  const canUseManagedKeyCreation = Boolean(managedOpenBaoService);
  const defaultServiceLabel = defaultService?.name
    || defaultService?.provider_label
    || defaultService?.id
    || 'the default signing service';

  // Derive a URL-safe slug from the org name, falling back to the org ID
  const orgSlug = useMemo(() => {
    if (effectiveOrganizationName) {
      return effectiveOrganizationName
        .trim()
        .toLowerCase()
        .replace(/[^a-z0-9]+/g, '-')
        .replace(/^-|-$/g, '')
        .slice(0, 64) || effectiveOrganizationId || '';
    }
    return effectiveOrganizationId || '';
  }, [effectiveOrganizationName, effectiveOrganizationId]);

  const methodCatalog = useMemo(
    () => buildDidMethodCatalog(safeKeys, domainSummary),
    [safeKeys, domainSummary],
  );

  const resolveIdentityLabel = useCallback((data, derivedDid, keyReference) => {
    const explicitLabel = typeof data.identity_label === 'string' ? data.identity_label.trim() : '';
    if (explicitLabel) {
      return explicitLabel;
    }

    const didMethod = typeof data.did_method === 'string' ? data.did_method : '';
    const organizationLabel = typeof organizationName === 'string' ? organizationName.trim() : '';
    const keyHint = deriveKeyHint(keyReference);
    const withKeyHint = (baseLabel) => (keyHint ? `${baseLabel} (${keyHint})` : baseLabel);

    if (organizationLabel && didMethod) {
      return withKeyHint(`${organizationLabel} ${IDENTITY_LABEL_SUFFIX[didMethod] || 'issuer'}`);
    }

    if (didMethod === 'did:web') {
      const domain = (data.did_web_domain || publicDomain || '').trim();
      const path = typeof data.did_web_path === 'string' ? data.did_web_path.trim() : '';
      if (domain && path) {
        return withKeyHint(`${domain}/${path}`);
      }
      if (domain) {
        return withKeyHint(`${domain} issuer`);
      }
    }

    if (derivedDid) {
      return withKeyHint(derivedDid);
    }

    return withKeyHint(didMethod ? `${didMethod} issuer` : 'Issuer identity');
  }, [organizationName, publicDomain]);

  const derivedIdentities = useMemo(
    () => buildDidIdentities({ keys: safeKeys, domainSummary }),
    [safeKeys, domainSummary],
  );

  const activeKeys = useMemo(
    () => safeKeys.filter((k) => {
      const status = typeof k.status === 'string' ? k.status.toLowerCase() : '';
      return status === 'active' || status === 'valid' || status === 'configured';
    }),
    [safeKeys],
  );

  const getServiceById = useCallback((serviceId) => (
    keyManagementConfig.services.find((service) => service.id === serviceId) || null
  ), [keyManagementConfig.services]);

  const getKeyServiceId = useCallback((key) => (
    key?.service_id
    || key?.signing_service_id
    || key?.service?.id
    || defaultService?.id
    || ''
  ), [defaultService?.id]);

  const getServiceLabel = useCallback((service) => (
    service?.name
    || service?.provider_label
    || service?.id
    || 'Signing service'
  ), []);

  const getCreateServiceForData = useCallback((data) => (
    getServiceById(data?.signing_service_id)
    || managedOpenBaoService
    || null
  ), [getServiceById, managedOpenBaoService]);

  const canCreateKeyForData = useCallback((data) => (
    getCreateServiceForData(data)?.id === MANAGED_OPENBAO_SERVICE_ID
  ), [getCreateServiceForData]);

  const validateStep = useCallback((stepIndex, data) => {
    switch (stepIndex) {
      case 0:
        return Boolean(data.did_method);
      case 1:
        if (data.key_source === 'create') {
          return Boolean(canCreateKeyForData(data));
        }
        return Boolean(data.key_source);
      case 2:
        if (data.key_source === 'existing') {
          return Boolean(data.selected_key_id);
        }
        if (data.key_source === 'create') {
          return Boolean(
            canCreateKeyForData(data)
            && data.new_key_name?.trim()
            && data.new_key_algorithm
            && isAlgorithmAllowedForPurpose(data.new_key_purpose, data.new_key_algorithm),
          );
        }
        return false;
      case 3:
        if (data.did_method === 'did:web') {
          return Boolean(data.did_web_domain?.trim());
        }
        return true;
      case 4:
        return true;
      default:
        return false;
    }
  }, [canCreateKeyForData]);

  const handleSubmit = useCallback(async (data) => {
    const selectedKey = safeKeys.find((k) => k.id === data.selected_key_id);
    const createService = getCreateServiceForData(data);
    let signingServiceId = data.key_source === 'create'
      ? createService?.id
      : (getKeyServiceId(selectedKey) || data.signing_service_id || defaultService?.id);
    let createdKey = null;
    let effectiveKeyReference = selectedKey?.provider_key_name || selectedKey?.id || null;
    const errors = [];
    let identitiesForLookup = derivedIdentities;

    // Hard guard: a signing service is required for every DID method
    if (!signingServiceId) {
      throw new Error(
        'No key management service is registered. Go to Deploy → Key Management and register a signing service before creating an issuer identity.',
      );
    }

    // ── Key creation ("create new in KMS") ────────────────────────────
    if (data.key_source === 'create' && signingServiceId !== MANAGED_OPENBAO_SERVICE_ID) {
      throw new Error(
        'Creating a new key from the console is supported only for the Marty managed OpenBao transit service. Use an existing key from the registered KMS, or choose the managed OpenBao service for this issuer identity.',
      );
    }

    if (data.key_source === 'create') {
      try {
        const createResult = await signingKeysApi.createSigningKey({
          organization_id: effectiveOrganizationId,
          service_id: signingServiceId,
          name: data.new_key_name,
          algorithm: data.new_key_algorithm,
          key_purpose: data.new_key_purpose || 'vc_jwt_issuer',
        });
        createdKey = createResult?.key || createResult || null;
        signingServiceId = createResult?.service_id
          || createdKey?.service_id
          || createdKey?.signing_service_id
          || signingServiceId;
        effectiveKeyReference = createdKey?.provider_key_name || createdKey?.id || effectiveKeyReference;
        if (!effectiveKeyReference) {
          throw new Error('The signing service did not return a usable key reference.');
        }

        // Refresh key inventory so self-contained DID methods can resolve
        // against newly created KMS keys in the same submit operation.
        const latestSigningKeysResponse = await signingKeysApi.listSigningKeys({ organization_id: effectiveOrganizationId });
        const latestRawKeys = Array.isArray(latestSigningKeysResponse)
          ? latestSigningKeysResponse
          : latestSigningKeysResponse?.keys || [];
        if (Array.isArray(latestRawKeys)) {
          const latestKeys = latestRawKeys.filter((entry) => entry && typeof entry === 'object');
          const latestIncludesCreatedKey = latestKeys.some((entry) => (
            (createdKey?.id && entry.id === createdKey.id)
            || (createdKey?.provider_key_name && entry.provider_key_name === createdKey.provider_key_name)
          ));
          if (createdKey && typeof createdKey === 'object' && !latestIncludesCreatedKey) {
            latestKeys.unshift(createdKey);
          }
          identitiesForLookup = buildDidIdentities({ keys: latestKeys, domainSummary });
        }
      } catch (err) {
        throw new Error(
          `Key creation failed: ${err?.response?.data?.detail || err?.message || 'The signing service could not create a new key.'}\n\nMake sure the signing service is running and reachable from the gateway.`,
        );
      }
    }

    // ── DID document publish ──────────────────────────────────────────
    if (data.did_method === 'did:web') {
      const effectiveDomain = data.did_web_domain || publicDomain;
      const effectivePath = data.did_web_path
        ? `:${data.did_web_path.replace(/\//g, ':')}`
        : '';
      const didId = effectiveDomain
        ? `did:web:${effectiveDomain}${effectivePath}`
        : undefined;

      if (!didId) {
        throw new Error('Cannot build a did:web identifier — no domain is configured. Go to Deploy → Key Management and set a public domain.');
      }

      try {
        await Promise.all([
          signingKeysApi.publishServiceToJwks(signingServiceId, effectiveOrganizationId, {
            key_reference: effectiveKeyReference || undefined,
          }),
          signingKeysApi.publishServiceToDidVm(signingServiceId, effectiveOrganizationId, {
            did_id: didId,
            org_slug: orgSlug,
            key_reference: effectiveKeyReference || undefined,
          }),
        ]);
        setPublishResult('published');
      } catch (err) {
        // Publishing can fail non-fatally (self-host without public resolution)
        setPublishResult('manual');
        errors.push(
          `DID document auto-publish failed: ${err?.response?.data?.detail || err?.message || 'Unknown error'}. You can download did.json from the identity detail page and host it manually.`,
        );
      }

      // Persist issuer profile
      if (didId) {
        try {
          await signingKeysApi.createIssuerProfile({
            organization_id: effectiveOrganizationId,
            name: resolveIdentityLabel(data, didId, effectiveKeyReference),
            issuer_did: didId,
            signing_service_id: signingServiceId,
            signing_key_reference: effectiveKeyReference || undefined,
            key_purpose: data.key_source === 'existing' ? data.compliance_target : data.new_key_purpose,
            status: 'active',
          });
        } catch (err) {
          throw new Error(
            `Issuer profile could not be saved: ${err?.response?.data?.detail || err?.message || 'Unknown error'}. Resolve the issuer profile error before using this identity for credential issuance.`,
          );
        }
      }
    } else if (data.did_method) {
      // did:jwk / did:key — self-contained, still needs issuer profile
      const lookupKeyId = createdKey?.id || data.selected_key_id;
      const hasSpecificKeyReference = Boolean(lookupKeyId || effectiveKeyReference);
      const derivedMatch = identitiesForLookup.find(
        (id) => id.method === data.did_method && lookupKeyId && id.backingKeyId === lookupKeyId,
      ) || identitiesForLookup.find(
        (id) => id.method === data.did_method
          && effectiveKeyReference
          && (id.source === effectiveKeyReference || id.source === createdKey?.provider_key_name),
      ) || (!hasSpecificKeyReference ? identitiesForLookup.find((id) => id.method === data.did_method) : null);
      const derivedDid = derivedMatch?.did;
      if (!derivedDid) {
        throw new Error(
          `${data.did_method} could not be derived from the selected key. Ensure the key exposes required public material (${data.did_method === 'did:jwk' ? 'public JWK' : 'public multibase key'}) and try again.`,
        );
      }

      try {
        await signingKeysApi.createIssuerProfile({
          organization_id: effectiveOrganizationId,
          name: resolveIdentityLabel(data, derivedDid, effectiveKeyReference),
          issuer_did: derivedDid,
          signing_service_id: signingServiceId,
          signing_key_reference: effectiveKeyReference || undefined,
          key_purpose: data.key_source === 'existing' ? data.compliance_target : data.new_key_purpose,
          status: 'active',
        });
      } catch (err) {
        throw new Error(
          `Issuer profile could not be saved: ${err?.response?.data?.detail || err?.message || 'Unknown error'}. Resolve the issuer profile error before using this identity for credential issuance.`,
        );
      }

      // Publish JWKS so JWT verifiers can resolve the public key
      try {
        await signingKeysApi.publishServiceToJwks(signingServiceId, effectiveOrganizationId, {
          key_reference: effectiveKeyReference || undefined,
        });
      } catch {
        // Non-fatal: JWKS publication will be retried when the profile is activated
      }

      setPublishResult('self-contained');
    } else {
      setPublishResult('self-contained');
    }

    // Surface non-fatal warnings so the success screen can display them
    if (errors.length) {
      showNotification?.(errors[0], 'warning');
    }

    return { method: data.did_method, key: effectiveKeyReference || selectedKey?.id || data.new_key_name, warnings: errors };
  }, [defaultService?.id, derivedIdentities, domainSummary, effectiveOrganizationId, getCreateServiceForData, getKeyServiceId, orgSlug, publicDomain, resolveIdentityLabel, safeKeys, showNotification]);

  const wizard = useWizard({
    steps: STEPS,
    initialData: {
      did_method: '',
      key_source: prefillKeyId ? 'existing' : requestedKeySource,
      selected_key_id: prefillKeyId,
      compliance_target: 'vc_jwt_issuer',
      new_key_name: requestedNewKeyName,
      new_key_algorithm: 'ES256',
      new_key_purpose: 'vc_jwt_issuer',
      signing_service_id: requestedSigningServiceId || (requestedKeySource === 'create' ? MANAGED_OPENBAO_SERVICE_ID : ''),
      did_web_domain: publicDomain,
      did_web_path: orgSlug ? `orgs/${orgSlug}` : '',
      identity_label: '',
    },
    validateStep,
    onSubmit: handleSubmit,
    onComplete: () => {
      navigate('/console/org/deploy/issuer-identity');
    },
    onCancel: () => {
      navigate('/console/org/deploy/issuer-identity');
    },
  });

  const selectedCreationService = getCreateServiceForData(wizard.data);
  const supportsGatewayManagedKeyCreation = selectedCreationService?.id === MANAGED_OPENBAO_SERVICE_ID;
  const selectedCreationServiceLabel = getServiceLabel(selectedCreationService || managedOpenBaoService);

  const useManagedKeyCreationForIdentity = useCallback(() => {
    if (!managedOpenBaoService) {
      return;
    }

    wizard.updateData({
      key_source: 'create',
      signing_service_id: MANAGED_OPENBAO_SERVICE_ID,
    });
    setPreflightAcknowledged(true);
  }, [managedOpenBaoService, wizard.updateData]);

  // Sync wizard defaults when async data (publicDomain / orgSlug) arrives
  // after the initial render where they were still empty strings.
  useEffect(() => {
    if (publicDomain && !wizard.data.did_web_domain) {
      wizard.updateData({
        did_web_domain: publicDomain,
        did_web_path: orgSlug ? `orgs/${orgSlug}` : wizard.data.did_web_path,
      });
    }
  }, [publicDomain, orgSlug]); // eslint-disable-line react-hooks/exhaustive-deps

  const selectedKey = safeKeys.find((k) => k.id === wizard.data.selected_key_id);
  const selectedExistingKeyService = getServiceById(getKeyServiceId(selectedKey)) || defaultService;

  const selectedExistingKey = useMemo(
    () => (wizard.data.key_source === 'existing' ? safeKeys.find((k) => k.id === wizard.data.selected_key_id) || null : null),
    [safeKeys, wizard.data.key_source, wizard.data.selected_key_id],
  );

  const selectedKeyCompatibility = useMemo(
    () => getCompatibilityByMethodForKey({ key: selectedExistingKey, domainSummary }),
    [selectedExistingKey, domainSummary],
  );

  const recommendedMethodForSelectedKey = useMemo(
    () => pickRecommendedMethod({
      compatibility: selectedKeyCompatibility,
      complianceTarget: wizard.data.compliance_target,
      publicDomain,
    }),
    [selectedKeyCompatibility, wizard.data.compliance_target, publicDomain],
  );

  useEffect(() => {
    if (wizard.data.key_source !== 'existing' || !selectedExistingKey) {
      return;
    }

    const selectedMethod = wizard.data.did_method;
    const isSelectedSupported = selectedKeyCompatibility[selectedMethod];
    if (selectedMethod && isSelectedSupported) {
      return;
    }

    if (recommendedMethodForSelectedKey) {
      wizard.updateData({ did_method: recommendedMethodForSelectedKey });
    }
  }, [
    wizard.data.key_source,
    wizard.data.did_method,
    selectedExistingKey,
    selectedKeyCompatibility,
    recommendedMethodForSelectedKey,
  ]); // eslint-disable-line react-hooks/exhaustive-deps

  const compatibleAlgorithmsForPurpose = useMemo(
    () => getAllowedAlgorithmsForPurpose(wizard.data.new_key_purpose),
    [wizard.data.new_key_purpose],
  );

  const compatiblePurposesForAlgorithm = useMemo(
    () => getCompatiblePurposesForAlgorithm(wizard.data.new_key_algorithm),
    [wizard.data.new_key_algorithm],
  );

  const isSelectedComboCompatible = useMemo(
    () => isAlgorithmAllowedForPurpose(wizard.data.new_key_purpose, wizard.data.new_key_algorithm),
    [wizard.data.new_key_algorithm, wizard.data.new_key_purpose],
  );

  const previewIdentity = useMemo(() => {
    if (!wizard.data.did_method || !wizard.data.selected_key_id) return null;
    return derivedIdentities.find(
      (id) => id.method === wizard.data.did_method && id.backingKeyId === wizard.data.selected_key_id,
    ) || derivedIdentities.find((id) => id.method === wizard.data.did_method) || null;
  }, [derivedIdentities, wizard.data.did_method, wizard.data.selected_key_id]);

  const copyJson = useCallback(async (value) => {
    try {
      await navigator.clipboard.writeText(typeof value === 'string' ? value : JSON.stringify(value, null, 2));
      showNotification?.('Copied to clipboard.', 'success');
    } catch {
      showNotification?.('Unable to copy to clipboard.', 'error');
    }
  }, [showNotification]);

  // Step 1: Choose DID Method
  const renderMethodStep = () => (
    <Box>
      <Typography variant="h5" gutterBottom>Choose a DID method</Typography>
      <Typography color="text.secondary" sx={{ mb: 3 }}>
        Select the DID method for this issuer identity. Method readiness reflects whether your organization has the required infrastructure configured.
      </Typography>
      <FormControl fullWidth sx={{ mb: 2.5 }}>
        <InputLabel>Compliance target</InputLabel>
        <Select
          label="Compliance target"
          value={wizard.data.compliance_target}
          onChange={(e) => wizard.updateData({ compliance_target: e.target.value })}
        >
          {WIZARD_KEY_PURPOSE_OPTIONS.map((purpose) => (
            <MenuItem key={purpose.value} value={purpose.value}>
              {purpose.label}
            </MenuItem>
          ))}
        </Select>
      </FormControl>
      <Alert severity="info" sx={{ mb: 2.5 }}>
        Compliance target helps Marty recommend the best DID method for the selected key and restrict incompatible options.
      </Alert>
      <Box sx={{ display: 'grid', gap: 2, gridTemplateColumns: { xs: '1fr', md: 'repeat(3, 1fr)' } }}>
        {METHOD_OPTIONS.map((method) => {
          const entry = methodCatalog.find((m) => m.method === method.id);
          const methodCompatible = selectedKeyCompatibility[method.id] !== false;
          return (
            <MethodCard
              key={method.id}
              method={{
                ...method,
                disabled: wizard.data.key_source === 'existing' && Boolean(selectedExistingKey) && !methodCompatible,
              }}
              selected={wizard.data.did_method === method.id}
              onSelect={(id) => wizard.updateData({ did_method: id })}
              ready={entry?.ready || false}
              readinessLabel={entry?.readinessLabel}
            />
          );
        })}
      </Box>
      {wizard.data.key_source === 'existing' && selectedExistingKey && recommendedMethodForSelectedKey && (
        <Alert severity="info" sx={{ mt: 2 }}>
          Recommended for this key and compliance target: <strong>{recommendedMethodForSelectedKey}</strong>.
        </Alert>
      )}
      {wizard.data.did_method === 'did:web' && !x509Eligible && (
        <Alert severity="warning" sx={{ mt: 2 }}>
          did:web X.509 chaining requires a premium plan or self-hosted deployment. Basic did:web is available, but trust chain configuration will be limited.
        </Alert>
      )}
    </Box>
  );

  // Step 2: Key Source
  const renderKeySourceStep = () => {
    const hasServices = keyManagementConfig.services.length > 0;
    return (
      <Box>
        <Typography variant="h5" gutterBottom>Key source</Typography>
        <Typography color="text.secondary" sx={{ mb: 3 }}>
          DID identities are backed by signing keys that remain in your external KMS/HSM. Choose how to associate a key with this identity.
        </Typography>

        {!hasServices && (
          <Alert severity="warning" sx={{ mb: 3 }}>
            No key management services registered. <Button size="small" onClick={() => navigate('/console/org/deploy/key-management/services/new')}>Register a service</Button> first, then return here.
          </Alert>
        )}

        <Alert severity="info" sx={{ mb: 3 }}>
          Private keys never enter this portal. With the Marty managed OpenBao signer, this wizard can create a new
          KMS key through the signing-key create endpoint. With registered external KMS services, create the key in
          the provider first, then use the discovered key here.
        </Alert>

        <Box sx={{ display: 'grid', gap: 2, gridTemplateColumns: { xs: '1fr', md: 'repeat(2, 1fr)' } }}>
          {KEY_SOURCE_OPTIONS.map((option) => {
            const createDisabled = option.id === 'create' && !canUseManagedKeyCreation;
            return (
              <KeySourceCard
                key={option.id}
                option={option}
                selected={wizard.data.key_source === option.id}
                onSelect={(id) => wizard.updateData(id === 'create'
                  ? { key_source: id, signing_service_id: MANAGED_OPENBAO_SERVICE_ID }
                  : { key_source: id })}
                disabled={createDisabled}
                disabledReason={createDisabled
                  ? 'Console key creation currently requires the Marty managed OpenBao transit service to be registered. Use an existing key from the registered KMS, or register the managed service.'
                  : ''}
              />
            );
          })}
        </Box>

        {canUseManagedKeyCreation && defaultService?.id !== MANAGED_OPENBAO_SERVICE_ID && (
          <Alert severity="info" sx={{ mt: 3 }}>
            Create new key in KMS will use the Marty managed OpenBao service for this issuer identity only. The org
            default signer remains {defaultServiceLabel}.
          </Alert>
        )}
      </Box>
    );
  };

  // Step 3: Key Configuration
  const renderKeyConfigStep = () => {
    if (wizard.data.key_source === 'existing') {
      return (
        <Box>
          <Typography variant="h5" gutterBottom>Select existing key</Typography>
          <Typography color="text.secondary" sx={{ mb: 3 }}>
            Choose a signing key from your connected KMS inventory to bind to this DID identity.
          </Typography>

          {activeKeys.length === 0 ? (
            <Stack spacing={2}>
              <Alert severity="warning">
                No active signing keys found for {defaultServiceLabel}. Issuer identity setup needs a signing key
                with public material that can be published into the DID document.
              </Alert>
              <Alert severity={canUseManagedKeyCreation ? 'info' : 'warning'}>
                {canUseManagedKeyCreation
                  ? 'Use managed OpenBao key creation for this issuer identity. The wizard will create the key before publishing the issuer profile, without changing the org default signer.'
                  : 'Create the key in your registered KMS provider first, confirm the key reference on the Key Management page, refresh discovered keys, then return here and choose it.'}
              </Alert>
              <Stack direction={{ xs: 'column', sm: 'row' }} spacing={1.5}>
                {canUseManagedKeyCreation && (
                  <Button variant="contained" onClick={useManagedKeyCreationForIdentity}>
                    Use managed key creation
                  </Button>
                )}
                <Button variant="outlined" onClick={() => navigate('/console/org/deploy/key-management')}>
                  Open key management
                </Button>
              </Stack>
            </Stack>
          ) : (
            <Box sx={{ display: 'grid', gap: 1.5 }}>
              {activeKeys.map((key) => (
                <Paper
                  key={key.id}
                  variant="outlined"
                  onClick={() => {
                    const compatibility = getCompatibilityByMethodForKey({ key, domainSummary });
                    const recommendedMethod = pickRecommendedMethod({
                      compatibility,
                      complianceTarget: wizard.data.compliance_target,
                      publicDomain,
                    });
                    const currentMethod = wizard.data.did_method;
                    const shouldKeepCurrentMethod = currentMethod && compatibility[currentMethod];
                    wizard.updateData({
                      selected_key_id: key.id,
                      signing_service_id: getKeyServiceId(key),
                      did_method: shouldKeepCurrentMethod ? currentMethod : recommendedMethod,
                    });
                  }}
                  sx={{
                    p: 2,
                    cursor: 'pointer',
                    borderColor: wizard.data.selected_key_id === key.id ? 'primary.main' : 'divider',
                    bgcolor: wizard.data.selected_key_id === key.id ? 'action.selected' : 'background.paper',
                  }}
                >
                  <Stack direction="row" spacing={1} alignItems="center">
                    <Typography variant="subtitle2">
                      {key.name || key.provider_key_name || key.id}
                    </Typography>
                    <Chip size="small" label={key.algorithm || 'unknown'} variant="outlined" />
                    <Chip size="small" label={key.status} color="success" variant="outlined" />
                  </Stack>
                  <Typography variant="body2" color="text.secondary" sx={{ mt: 0.5 }}>
                    {key.provider_key_name || key.id}
                  </Typography>
                </Paper>
              ))}
            </Box>
          )}

          <Alert severity="info" sx={{ mt: 2 }}>
            The selected key{"'s"} public material will be embedded in or referenced by the DID document. The private key stays in your KMS.
          </Alert>
        </Box>
      );
    }

    if (wizard.data.key_source === 'create' && !supportsGatewayManagedKeyCreation) {
      return (
        <Box>
          <Typography variant="h5" gutterBottom>Create key in KMS</Typography>
          <Alert severity="warning" sx={{ mb: 2 }}>
            Console key creation is supported only for the Marty managed OpenBao transit service. Use an existing key
            from the registered KMS, or register managed OpenBao and choose it for this issuer identity.
          </Alert>
          <Button variant="outlined" onClick={() => wizard.updateData({ key_source: 'existing' })}>
            Use existing key
          </Button>
        </Box>
      );
    }

    if (wizard.data.key_source === 'create') {
      return (
        <Box>
          <Typography variant="h5" gutterBottom>Create key in KMS</Typography>
          <Typography color="text.secondary" sx={{ mb: 3 }}>
            Marty will request your connected KMS to generate a new signing key. The private key never leaves the KMS.
          </Typography>

          <Alert severity="info" sx={{ mb: 2 }}>
            This issuer identity will create the key with {selectedCreationServiceLabel}. The org default signer is not changed.
          </Alert>

          <Box sx={{ display: 'grid', gap: 2 }}>
            <TextField
              fullWidth
              required
              label="Key name"
              helperText="A descriptive name for this key in the KMS."
              value={wizard.data.new_key_name}
              onChange={(e) => wizard.updateData({ new_key_name: e.target.value })}
            />
            <FormControl fullWidth>
              <InputLabel>Compliance target</InputLabel>
              <Select
                label="Compliance target"
                value={wizard.data.new_key_purpose}
                onChange={(e) => {
                  const nextPurpose = e.target.value;
                  const allowedAlgorithms = getAllowedAlgorithmsForPurpose(nextPurpose);
                  const nextAlgorithm = allowedAlgorithms.includes(wizard.data.new_key_algorithm)
                    ? wizard.data.new_key_algorithm
                    : allowedAlgorithms[0] || wizard.data.new_key_algorithm;
                  wizard.updateData({
                    new_key_purpose: nextPurpose,
                    new_key_algorithm: nextAlgorithm,
                  });
                }}
              >
                {WIZARD_KEY_PURPOSE_OPTIONS.map((purpose) => {
                  const compatible = compatiblePurposesForAlgorithm.includes(purpose.value);
                  return (
                    <MenuItem key={purpose.value} value={purpose.value} disabled={!compatible}>
                      {purpose.label}
                    </MenuItem>
                  );
                })}
              </Select>
            </FormControl>
            <FormControl fullWidth>
              <InputLabel>Algorithm</InputLabel>
              <Select
                label="Algorithm"
                value={wizard.data.new_key_algorithm}
                onChange={(e) => wizard.updateData({ new_key_algorithm: e.target.value })}
              >
                <MenuItem value="ES256" disabled={!compatibleAlgorithmsForPurpose.includes('ES256')}>ES256 (ECDSA P-256)</MenuItem>
                <MenuItem value="ES384" disabled={!compatibleAlgorithmsForPurpose.includes('ES384')}>ES384 (ECDSA P-384)</MenuItem>
                <MenuItem value="EdDSA" disabled={!compatibleAlgorithmsForPurpose.includes('EdDSA')}>EdDSA (Ed25519)</MenuItem>
                <MenuItem value="RS256" disabled={!compatibleAlgorithmsForPurpose.includes('RS256')}>RS256 (RSA 2048)</MenuItem>
              </Select>
            </FormControl>

            {!isSelectedComboCompatible && (
              <Alert severity="warning">
                The selected purpose and algorithm are incompatible. Pick one of: {compatibleAlgorithmsForPurpose.join(', ')}.
              </Alert>
            )}

            {isSelectedComboCompatible && (
              <Alert severity="info">
                Allowed algorithms for this purpose: {compatibleAlgorithmsForPurpose.join(', ')}.
              </Alert>
            )}
          </Box>

          {!selectedCreationService && (
            <Alert severity="warning" sx={{ mt: 2 }}>
              No create-capable signing service is configured. <Button size="small" onClick={() => navigate('/console/org/deploy/key-management/services/new')}>Register a service</Button> before creating keys.
            </Alert>
          )}

          <Alert severity="info" sx={{ mt: 2 }}>
            Key generation happens in the managed OpenBao KMS through the signing-key create endpoint. Marty stores only
            the key{"'s"} public metadata and the provider key reference.
          </Alert>
        </Box>
      );
    }

    return (
      <Alert severity="info">
        Go back and select a key source to continue.
      </Alert>
    );
  };

  // Step 4: DID Configuration
  const renderDidConfigStep = () => {
    if (wizard.data.did_method === 'did:web') {
      const effectiveDomain = wizard.data.did_web_domain || publicDomain;
      const effectivePath = wizard.data.did_web_path ? `:${wizard.data.did_web_path.replace(/\//g, ':')}` : '';
      const previewDid = effectiveDomain ? `did:web:${effectiveDomain}${effectivePath}` : '';
      const isDelegatedPath = effectiveDomain === publicDomain && wizard.data.did_web_path.startsWith('orgs/');
      const resolutionUrl = effectiveDomain
        ? `https://${effectiveDomain}/${wizard.data.did_web_path ? `${wizard.data.did_web_path}/` : '.well-known/'}did.json`
        : '';
      const keyHintSource = selectedKey?.provider_key_name || selectedKey?.name || wizard.data.new_key_name || null;
      const suggestedIdentityLabel = resolveIdentityLabel(wizard.data, previewDid || null, keyHintSource);

      return (
        <Box>
          <Typography variant="h5" gutterBottom>did:web configuration</Typography>
          <Typography color="text.secondary" sx={{ mb: 3 }}>
            Confirm the domain and path for your did:web identifier. The DID document (did.json) will be served at the resolved URL.
          </Typography>

          {isDelegatedPath && (
            <Alert severity="info" sx={{ mb: 3 }}>
              Your DID will be hosted on the platform domain. The DID document is automatically published and publicly resolvable — no DNS or web server setup required.
            </Alert>
          )}

          <Box sx={{ display: 'grid', gap: 2 }}>
            <TextField
              fullWidth
              required
              label="Domain"
              helperText={isDelegatedPath
                ? 'Platform domain — your DID document is hosted automatically.'
                : 'Your organization\'s public domain. Must match where did.json will be served.'}
              value={wizard.data.did_web_domain || publicDomain}
              onChange={(e) => wizard.updateData({ did_web_domain: e.target.value })}
            />
            <TextField
              fullWidth
              label="Path"
              helperText={isDelegatedPath
                ? `Org path on the platform domain. Your slug: ${orgSlug}`
                : 'Optional sub-path for multi-tenant or scoped DIDs (e.g., \'orgs/acme\').'}
              value={wizard.data.did_web_path}
              onChange={(e) => wizard.updateData({ did_web_path: e.target.value })}
            />
            {previewDid && (
              <Paper variant="outlined" sx={{ p: 2 }}>
                <Typography variant="subtitle2" sx={{ mb: 0.5 }}>Preview DID</Typography>
                <Typography variant="body2" fontFamily="monospace">{previewDid}</Typography>
                {resolutionUrl && (
                  <Typography variant="caption" color="text.secondary" display="block" sx={{ mt: 0.5 }}>
                    Resolves to: {resolutionUrl}
                  </Typography>
                )}
              </Paper>
            )}

            <TextField
              fullWidth
              label="Identity label (optional)"
              helperText={`Used as the issuer profile name in issuance flows. Defaults to "${suggestedIdentityLabel}".`}
              placeholder={suggestedIdentityLabel}
              value={wizard.data.identity_label}
              onChange={(e) => wizard.updateData({ identity_label: e.target.value })}
            />
          </Box>

          {!x509Eligible && (
            <Alert severity="warning" sx={{ mt: 2 }}>
              X.509 trust chain configuration for did:web requires a premium plan or self-hosted deployment. You can still create the DID, but chain setup will be gated.
            </Alert>
          )}
        </Box>
      );
    }

    // did:jwk and did:key — auto-derived
    const methodLabel = wizard.data.did_method === 'did:jwk' ? 'did:jwk' : 'did:key';
    const keyHintSource = selectedKey?.provider_key_name || selectedKey?.name || wizard.data.new_key_name || null;
    const suggestedIdentityLabel = resolveIdentityLabel(wizard.data, previewIdentity?.did || null, keyHintSource);
    return (
      <Box>
        <Typography variant="h5" gutterBottom>{methodLabel} configuration</Typography>
        <Typography color="text.secondary" sx={{ mb: 3 }}>
          {methodLabel} identifiers are derived automatically from the key material. No additional configuration is needed.
        </Typography>

        {previewIdentity ? (
          <Paper variant="outlined" sx={{ p: 2 }}>
            <Typography variant="subtitle2" sx={{ mb: 0.5 }}>Derived DID</Typography>
            <Typography variant="body2" fontFamily="monospace" sx={{ wordBreak: 'break-all' }}>
              {previewIdentity.did}
            </Typography>
            <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
              Status: {previewIdentity.readinessLabel} · Source: {previewIdentity.source}
            </Typography>
          </Paper>
        ) : (
          <Alert severity="info">
            The DID will be derived after the wizard completes, based on the selected key{"'s"} public material.
          </Alert>
        )}

        <TextField
          fullWidth
          label="Identity label (optional)"
          helperText={`Used as the issuer profile name in issuance flows. Defaults to "${suggestedIdentityLabel}".`}
          placeholder={suggestedIdentityLabel}
          value={wizard.data.identity_label}
          onChange={(e) => wizard.updateData({ identity_label: e.target.value })}
          sx={{ mt: 2 }}
        />
      </Box>
    );
  };

  // Step 5: Review & Publish
  const renderReviewStep = () => {
    const methodLabel = wizard.data.did_method || 'Not selected';
    const keyLabel = wizard.data.key_source === 'existing'
      ? (selectedKey?.name || selectedKey?.provider_key_name || wizard.data.selected_key_id)
      : wizard.data.new_key_name || 'New key';
    const reviewSigningService = wizard.data.key_source === 'create'
      ? selectedCreationService
      : selectedExistingKeyService;
    const effectiveDomain = wizard.data.did_web_domain || publicDomain;
    const effectivePath = wizard.data.did_web_path ? `:${wizard.data.did_web_path.replace(/\//g, ':')}` : '';
    const previewDid = wizard.data.did_method === 'did:web' && effectiveDomain
      ? `did:web:${effectiveDomain}${effectivePath}`
      : (previewIdentity?.did || null);
    const keyHintSource = selectedKey?.provider_key_name || selectedKey?.name || wizard.data.new_key_name || null;
    const resolvedIdentityLabel = resolveIdentityLabel(wizard.data, previewDid, keyHintSource);

    return (
      <Box>
        <Typography variant="h5" gutterBottom>Review & publish</Typography>
        <Typography color="text.secondary" sx={{ mb: 3 }}>
          Confirm the issuer identity configuration before creating.
        </Typography>

        <Paper variant="outlined" sx={{ p: 3, mb: 2 }}>
          <Typography variant="h6" sx={{ mb: 1.5 }}>Summary</Typography>
          <Typography variant="body2" sx={{ mb: 0.75 }}>DID method: {methodLabel}</Typography>
          <Typography variant="body2" sx={{ mb: 0.75 }}>Key source: {wizard.data.key_source === 'existing' ? 'Existing KMS key' : 'Create new in KMS'}</Typography>
          <Typography variant="body2" sx={{ mb: 0.75 }}>Signing service: {getServiceLabel(reviewSigningService)}</Typography>
          <Typography variant="body2" sx={{ mb: 0.75 }}>Key: {keyLabel}</Typography>
          {wizard.data.did_method === 'did:web' && (
            <>
              <Typography variant="body2" sx={{ mb: 0.75 }}>Domain: {wizard.data.did_web_domain}</Typography>
              {wizard.data.did_web_path && (
                <Typography variant="body2" sx={{ mb: 0.75 }}>Path: {wizard.data.did_web_path}</Typography>
              )}
            </>
          )}
          <Typography variant="body2" sx={{ mb: 0.75 }}>Profile name: {resolvedIdentityLabel}</Typography>
        </Paper>

        {previewIdentity && (
          <Paper variant="outlined" sx={{ p: 3, mb: 2 }}>
            <Stack direction="row" justifyContent="space-between" alignItems="center" sx={{ mb: 1 }}>
              <Typography variant="h6">DID Document Preview</Typography>
              <Button
                size="small"
                startIcon={<ContentCopyIcon />}
                onClick={() => copyJson(previewIdentity.document)}
              >
                Copy JSON
              </Button>
            </Stack>
            <Typography
              component="pre"
              sx={{
                p: 2,
                borderRadius: 1,
                overflowX: 'auto',
                bgcolor: 'grey.100',
                fontSize: '0.8125rem',
                lineHeight: 1.5,
                fontFamily: 'Consolas, Monaco, monospace',
                m: 0,
              }}
            >
              {JSON.stringify(previewIdentity.document, null, 2)}
            </Typography>
          </Paper>
        )}

        {wizard.data.did_method === 'did:web' && (
          <Alert severity="info" sx={{ mb: 2 }}>
            On submit, Marty will attempt to publish the DID document verification method via your signing service.
            If auto-publish is not available, you can download the did.json and host it manually.
          </Alert>
        )}

        {wizard.data.did_method !== 'did:web' && (
          <Alert severity="success" sx={{ mb: 2 }}>
            {wizard.data.did_method} identities are self-contained — they will be marked as active immediately.
          </Alert>
        )}
      </Box>
    );
  };

  const renderStepContent = () => {
    switch (wizard.activeStep) {
      case 0: return renderMethodStep();
      case 1: return renderKeySourceStep();
      case 2: return renderKeyConfigStep();
      case 3: return renderDidConfigStep();
      case 4: return renderReviewStep();
      default: return null;
    }
  };

  if (keysLoading || configLoading) {
    return (
      <Container maxWidth="md" sx={{ py: 6 }}>
        <Paper elevation={2} sx={{ p: 4, textAlign: 'center' }}>
          <CircularProgress />
          <Typography sx={{ mt: 2 }}>Loading key management data...</Typography>
        </Paper>
      </Container>
    );
  }

  // ── Config load failure ────────────────────────────────────────────
  if (configError && !configData) {
    const isAuthError = /401|unauthorized|authentication/i.test(configError.message);
    return (
      <Container maxWidth="md" sx={{ py: 4 }}>
        <Paper elevation={3} sx={{ p: 4 }}>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5, mb: 1 }}>
            <ErrorOutlineIcon color="error" sx={{ fontSize: 32 }} />
            <Typography variant="h5">
              {isAuthError ? 'Session expired' : 'Unable to load configuration'}
            </Typography>
          </Box>
          <Typography color="text.secondary" sx={{ mb: 3 }}>
            {isAuthError
              ? 'Your session has expired or is invalid. Please log in again to continue.'
              : `The key management configuration could not be loaded: ${configError.message}`}
          </Typography>
          <Box sx={{ display: 'flex', gap: 2 }}>
            {isAuthError ? (
              <Button variant="contained" onClick={() => navigate('/login')}>
                Log in
              </Button>
            ) : (
              <Button variant="contained" onClick={reloadConfig}>
                Retry
              </Button>
            )}
            <Button onClick={() => navigate('/console/org/deploy/issuer-identity')} startIcon={<ArrowBackIcon />}>
              Back
            </Button>
          </Box>
        </Paper>
      </Container>
    );
  }

  // ── Pre-flight dependency check ────────────────────────────────────
  const preflightIssues = [];

  if (!defaultService) {
    preflightIssues.push({
      severity: 'error',
      icon: <SettingsIcon />,
      title: 'No signing service registered',
      description:
        'A Key Management Service (KMS) must be registered before you can create an issuer identity. The signing service provides the cryptographic keys that back the DID.',
      action: (
        <Button
          variant="contained"
          size="small"
          onClick={() => navigate('/console/org/deploy/key-management/services/new')}
        >
          Register a signing service
        </Button>
      ),
    });
  }

  if (defaultService && safeKeys.length === 0) {
    preflightIssues.push({
      severity: 'warning',
      icon: <VpnKeyIcon />,
      title: 'No signing keys discovered',
      description: canUseManagedKeyCreation
        ? `No active signing keys were discovered for this org. You can create a managed OpenBao key for this issuer identity without changing the org default signer${defaultService ? ` (${defaultServiceLabel})` : ''}.`
        : `The default signer (${defaultServiceLabel}) has no discovered keys yet. Create the key in the KMS provider first, verify the key reference in Key Management, refresh discovered keys, then return to create the issuer identity.`,
      action: (
        canUseManagedKeyCreation ? (
          <Button
            variant="outlined"
            size="small"
            onClick={useManagedKeyCreationForIdentity}
          >
            Use managed key creation
          </Button>
        ) : (
          <Button
            variant="outlined"
            size="small"
            onClick={() => navigate('/console/org/deploy/key-management')}
          >
            Manage keys
          </Button>
        )
      ),
    });
  }

  if (!publicDomain) {
    preflightIssues.push({
      severity: 'warning',
      icon: <WarningAmberIcon />,
      title: 'No public domain configured',
      description:
        'did:web requires a public domain for DID document hosting. Without it, only did:jwk and did:key methods will be available. You can configure a domain in Key Management settings.',
      action: (
        <Button
          variant="outlined"
          size="small"
          onClick={() => navigate('/console/org/deploy/key-management')}
        >
          Configure domain
        </Button>
      ),
    });
  }

  const hasBlockingIssues = preflightIssues.some((i) => i.severity === 'error');

  if (preflightIssues.length > 0 && !preflightAcknowledged) {
    return (
      <Container maxWidth="md" sx={{ py: 4 }}>
        <Paper elevation={3} sx={{ p: 4 }}>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5, mb: 1 }}>
            {hasBlockingIssues
              ? <ErrorOutlineIcon color="error" sx={{ fontSize: 32 }} />
              : <WarningAmberIcon color="warning" sx={{ fontSize: 32 }} />
            }
            <Typography variant="h5">
              {hasBlockingIssues ? 'Setup required' : 'Recommendations'}
            </Typography>
          </Box>
          <Typography color="text.secondary" sx={{ mb: 3 }}>
            {hasBlockingIssues
              ? 'The following prerequisites must be met before creating an issuer identity.'
              : 'You can proceed, but addressing the items below will give you the best experience.'}
          </Typography>

          <Stack spacing={2} sx={{ mb: 4 }}>
            {preflightIssues.map((issue) => (
              <Alert
                key={issue.title}
                severity={issue.severity}
                icon={issue.icon}
                sx={{ alignItems: 'flex-start' }}
              >
                <Box>
                  <Typography variant="subtitle2" sx={{ mb: 0.5 }}>{issue.title}</Typography>
                  <Typography variant="body2" sx={{ mb: 1.5 }}>{issue.description}</Typography>
                  {issue.action}
                </Box>
              </Alert>
            ))}
          </Stack>

          <Box sx={{ display: 'flex', gap: 2, justifyContent: 'flex-end' }}>
            <Button
              onClick={() => navigate('/console/org/deploy/issuer-identity')}
              startIcon={<ArrowBackIcon />}
            >
              Back
            </Button>
            {!hasBlockingIssues && (
              <Button
                variant="contained"
                onClick={() => setPreflightAcknowledged(true)}
                endIcon={<ArrowForwardIcon />}
              >
                Continue anyway
              </Button>
            )}
          </Box>
        </Paper>
      </Container>
    );
  }

  if (wizard.success) {
    return (
      <Container maxWidth="md" sx={{ py: 4 }}>
        <Paper elevation={3} sx={{ p: 4, textAlign: 'center' }}>
          <CheckCircleIcon color="success" sx={{ fontSize: 64, mb: 2 }} />
          <Typography variant="h5" gutterBottom>Issuer identity created</Typography>
          <Typography color="text.secondary" paragraph>
            {publishResult === 'published'
              ? 'The DID document verification method has been published to your signing service.'
              : publishResult === 'manual'
                ? 'Auto-publish was not available. Download the did.json from the identity detail page and host it manually.'
                : 'The identity is ready to use.'}
          </Typography>
          <Typography color="text.secondary" variant="body2">
            Redirecting to issuer identity management...
          </Typography>
        </Paper>
      </Container>
    );
  }

  return (
    <Container maxWidth="lg" sx={{ py: 4 }}>
      <Paper elevation={3} sx={{ p: 4 }}>
        <Box sx={{ mb: 4 }}>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5, mb: 1 }}>
            <LanguageIcon color="primary" />
            <Typography variant="h4">Create Issuer Identity</Typography>
          </Box>
          <Typography color="text.secondary">
            Set up a new DID-based issuer identity backed by a signing key in your external KMS/HSM.
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
          <Alert
            severity="error"
            variant="filled"
            sx={{ mb: 3, whiteSpace: 'pre-line' }}
            action={
              <Button color="inherit" size="small" onClick={wizard.clearError}>
                Dismiss
              </Button>
            }
          >
            {wizard.error}
          </Alert>
        )}

        <Box sx={{ minHeight: 420, mb: 4 }}>
          {renderStepContent()}
        </Box>

        <Divider sx={{ mb: 2 }} />

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
              {wizard.loading ? 'Creating...' : 'Create identity'}
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
}

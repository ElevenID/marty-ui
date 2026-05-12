const DEFAULT_KEY_MANAGEMENT_SERVICE_TYPE_CATALOG = [
  {
    id: 'openbao-transit',
    label: 'OpenBao Transit',
    description: 'Register an OpenBao transit service that exposes signing keys remotely.',
    provider: 'openbao',
    protocol: 'vault-transit',
    category: 'service-hsm',
    auth_modes: ['service_token', 'token', 'approle', 'mtls'],
    connection_fields: ['endpoint', 'mount', 'namespace'],
    key_reference_label: 'Transit key name',
    supports_inventory: true,
  },
  {
    id: 'hashicorp-vault-transit',
    label: 'HashiCorp Vault Transit',
    description: 'Use Vault Transit as the signing backend for issuance keys.',
    provider: 'hashicorp-vault',
    protocol: 'vault-transit',
    category: 'service-hsm',
    auth_modes: ['token', 'approle', 'mtls'],
    connection_fields: ['endpoint', 'mount', 'namespace'],
    key_reference_label: 'Transit key name',
    supports_inventory: true,
  },
  {
    id: 'aws-kms',
    label: 'AWS KMS',
    description: 'Register a customer-managed AWS KMS key for remote signing.',
    provider: 'aws',
    protocol: 'aws-kms',
    category: 'cloud-kms',
    auth_modes: ['iam_role', 'access_key', 'assume_role'],
    connection_fields: ['region'],
    key_reference_label: 'Key ARN',
    supports_inventory: false,
  },
  {
    id: 'azure-key-vault',
    label: 'Azure Key Vault',
    description: 'Register an Azure Key Vault key as a signing source.',
    provider: 'azure',
    protocol: 'azure-key-vault',
    category: 'cloud-kms',
    auth_modes: ['managed_identity', 'client_secret', 'certificate'],
    connection_fields: ['endpoint'],
    key_reference_label: 'Key identifier',
    supports_inventory: false,
  },
  {
    id: 'gcp-cloud-kms',
    label: 'Google Cloud KMS',
    description: 'Register a Google Cloud KMS crypto key version.',
    provider: 'gcp',
    protocol: 'gcp-kms',
    category: 'cloud-kms',
    auth_modes: ['workload_identity', 'service_account'],
    connection_fields: ['region'],
    key_reference_label: 'Crypto key resource',
    supports_inventory: false,
  },
  {
    id: 'custom-transit-compatible',
    label: 'Custom Transit-Compatible Service',
    description: 'Any service that implements the transit-compatible signing protocol Marty supports.',
    provider: 'custom',
    protocol: 'vault-transit-compatible',
    category: 'custom',
    auth_modes: ['token', 'mtls', 'api_key', 'custom'],
    connection_fields: ['endpoint', 'mount', 'namespace'],
    key_reference_label: 'Key reference',
    supports_inventory: false,
  },
]

export const KEY_MANAGEMENT_ALGORITHM_OPTIONS = ['ES256', 'ES384', 'RS256', 'EdDSA']

export const KEY_PURPOSE_ALGORITHM_CONSTRAINTS = {
  vc_jwt_issuer: ['ES256', 'ES384', 'RS256', 'EdDSA'],
  mdoc_dsc: ['ES256', 'ES384', 'EdDSA'],
  x509_doc_signer: ['ES256', 'ES384', 'RS256', 'EdDSA'],
  holder_binding: ['ES256', 'EdDSA'],
  presentation_signing: ['ES256', 'EdDSA'],
  vdsnc_signing: ['ES256', 'ES384', 'EdDSA'],
  csca: ['ES256', 'ES384', 'RS256', 'EdDSA'],
  jwks_signing: ['ES256', 'ES384', 'RS256', 'EdDSA'],
}

export const KEY_MANAGEMENT_PURPOSES = [
  { value: 'vc_jwt_issuer', label: 'VC JWT / SD-JWT issuer', formats: ['jwt_vc_json', 'dc+sd-jwt'] },
  { value: 'mdoc_dsc', label: 'mDoc document signer (DSC)', formats: ['mso_mdoc', 'zk_mdoc'] },
  { value: 'x509_doc_signer', label: 'X.509 document signer', formats: [] },
  { value: 'holder_binding', label: 'Holder binding key', formats: ['mso_mdoc', 'zk_mdoc'] },
  { value: 'presentation_signing', label: 'Presentation signing', formats: [] },
  { value: 'vdsnc_signing', label: 'VDS-NC / travel credential signing', formats: ['vds_nc'] },
  { value: 'jwks_signing', label: 'JWKS endpoint key', formats: ['jwt_vc_json', 'dc+sd-jwt'] },
  { value: 'csca', label: 'CSCA / IACA root authority', formats: [] },
]

export const getAllowedAlgorithmsForPurpose = (purpose) => {
  if (typeof purpose !== 'string' || !purpose) {
    return KEY_MANAGEMENT_ALGORITHM_OPTIONS
  }
  const allowed = KEY_PURPOSE_ALGORITHM_CONSTRAINTS[purpose]
  if (!Array.isArray(allowed) || allowed.length === 0) {
    return KEY_MANAGEMENT_ALGORITHM_OPTIONS
  }
  return KEY_MANAGEMENT_ALGORITHM_OPTIONS.filter((algorithm) => allowed.includes(algorithm))
}

export const isAlgorithmAllowedForPurpose = (purpose, algorithm) => {
  if (typeof algorithm !== 'string' || !algorithm) {
    return false
  }
  return getAllowedAlgorithmsForPurpose(purpose).includes(algorithm)
}

export const getCompatiblePurposesForAlgorithm = (algorithm) => {
  if (typeof algorithm !== 'string' || !algorithm) {
    return KEY_MANAGEMENT_PURPOSES.map((purpose) => purpose.value)
  }
  return KEY_MANAGEMENT_PURPOSES
    .map((purpose) => purpose.value)
    .filter((purpose) => isAlgorithmAllowedForPurpose(purpose, algorithm))
}

/** Purposes that require X.509 certificate management (CSR → CA → install). */
export const PURPOSES_REQUIRING_CERTIFICATE = ['mdoc_dsc', 'x509_doc_signer', 'vdsnc_signing', 'csca']

/** Purposes that require a country/authority code. */
export const PURPOSES_REQUIRING_AUTHORITY = ['vdsnc_signing', 'csca', 'mdoc_dsc']

export const DEFAULT_KEY_MANAGEMENT_CONFIG = {
  hsm_enabled: false,
  hsm_settings: {},
  vault_enabled: false,
  vault_settings: {},
  provider_metadata: null,
  domain_config: null,
  supports_native_key_management: false,
  registration_mode: 'external-only',
  default_service_id: null,
  service_type_catalog: DEFAULT_KEY_MANAGEMENT_SERVICE_TYPE_CATALOG,
  services: [],
}

const normalizeString = (value) => (typeof value === 'string' ? value : '')

export const parseListInput = (value) => {
  const parts = Array.isArray(value) ? value : normalizeString(value).split(',')
  const deduped = []
  const seen = new Set()

  for (const part of parts) {
    if (typeof part !== 'string') {
      continue
    }
    const normalized = part.trim()
    if (!normalized || seen.has(normalized)) {
      continue
    }
    deduped.push(normalized)
    seen.add(normalized)
  }

  return deduped
}

export const normalizeServiceTypeCatalog = (catalog) => {
  const rawCatalog = Array.isArray(catalog) && catalog.length > 0
    ? catalog
    : DEFAULT_KEY_MANAGEMENT_SERVICE_TYPE_CATALOG

  return rawCatalog
    .filter((entry) => entry && typeof entry === 'object' && typeof entry.id === 'string')
    .map((entry) => ({
      id: entry.id,
      label: normalizeString(entry.label) || entry.id,
      description: normalizeString(entry.description),
      provider: normalizeString(entry.provider) || 'custom',
      protocol: normalizeString(entry.protocol) || 'custom',
      category: normalizeString(entry.category) || 'custom',
      auth_modes: parseListInput(entry.auth_modes),
      connection_fields: parseListInput(entry.connection_fields),
      key_reference_label: normalizeString(entry.key_reference_label) || 'Key reference',
      supports_inventory: Boolean(entry.supports_inventory),
    }))
}

export const getServiceTypeDefinition = (catalog, serviceTypeId) => {
  const normalizedCatalog = normalizeServiceTypeCatalog(catalog)
  return normalizedCatalog.find((entry) => entry.id === serviceTypeId)
    || normalizedCatalog.find((entry) => entry.id === 'custom-transit-compatible')
    || normalizedCatalog[0]
}

const createLegacyServiceFromConfig = (normalized, catalog) => {
  if (!normalized.hsm_enabled || !normalized.hsm_settings || typeof normalized.hsm_settings !== 'object') {
    return []
  }

  const managed = Boolean(normalized.hsm_settings.managed_by)
  const serviceType = managed ? 'openbao-transit' : 'custom-transit-compatible'
  const definition = getServiceTypeDefinition(catalog, serviceType)
  const legacyService = normalizeKeyManagementService(
    {
      id: managed ? 'managed-openbao-transit' : 'legacy-signing-service',
      name: managed ? 'Marty managed OpenBao transit' : (normalized.hsm_settings.provider_label || normalized.hsm_settings.provider || 'Registered KMS/HSM'),
      service_type: serviceType,
      provider: normalizeString(normalized.hsm_settings.provider) || definition.provider,
      provider_label: managed ? 'OpenBao Transit' : (normalized.hsm_settings.provider_label || definition.label),
      protocol: definition.protocol,
      endpoint: normalizeString(normalized.hsm_settings.service_url),
      mount: normalizeString(normalized.hsm_settings.mount),
      namespace: normalizeString(normalized.hsm_settings.namespace),
      region: normalizeString(normalized.hsm_settings.region),
      key_reference: normalizeString(normalized.hsm_settings.key_reference),
      key_aliases: parseListInput(normalized.hsm_settings.signing_key_names),
      algorithms: parseListInput(normalized.hsm_settings.algorithms),
      auth_mode: normalizeString(normalized.hsm_settings.auth_mode) || definition.auth_modes[0],
      auth_reference: normalizeString(normalized.hsm_settings.auth_reference),
      status: managed ? 'configured' : 'registered',
      managed,
      read_only: managed,
      managed_by: normalizeString(normalized.hsm_settings.managed_by),
      key_count: Number.isFinite(normalized.hsm_settings.signing_key_count) ? normalized.hsm_settings.signing_key_count : undefined,
    },
    catalog,
  )

  return legacyService ? [legacyService] : []
}

export const normalizeKeyManagementService = (service, catalog) => {
  if (!service || typeof service !== 'object') {
    return null
  }

  const definition = getServiceTypeDefinition(catalog, service.service_type)
  const keyAliases = parseListInput(service.key_aliases || service.signing_key_names)
  const algorithms = parseListInput(service.algorithms || service.algorithm).filter((algorithm) => KEY_MANAGEMENT_ALGORITHM_OPTIONS.includes(algorithm))
  const keyReference = normalizeString(service.key_reference)
  const rotationState = service.rotation_state && typeof service.rotation_state === 'object'
    ? service.rotation_state
    : null
  const lastRotatedAt = normalizeString(
    rotationState?.last_rotated_at
      || service.last_rotated_at
      || service.rotated_at,
  ) || null

  return {
    id: normalizeString(service.id) || `svc-${Math.random().toString(36).slice(2, 10)}`,
    name: normalizeString(service.name) || definition.label,
    description: normalizeString(service.description),
    service_type: definition.id,
    provider: normalizeString(service.provider) || definition.provider,
    provider_label: normalizeString(service.provider_label) || definition.label,
    protocol: normalizeString(service.protocol) || definition.protocol,
    category: normalizeString(service.category) || definition.category,
    endpoint: normalizeString(service.endpoint || service.service_url),
    region: normalizeString(service.region),
    mount: normalizeString(service.mount),
    namespace: normalizeString(service.namespace),
    auth_mode: normalizeString(service.auth_mode) || definition.auth_modes[0] || 'custom',
    auth_reference: normalizeString(service.auth_reference),
    key_reference: keyReference,
    key_aliases: keyAliases,
    algorithms,
    status: normalizeString(service.status) || 'registered',
    managed: Boolean(service.managed),
    read_only: Boolean(service.read_only),
    managed_by: normalizeString(service.managed_by),
    key_count: Number.isFinite(service.key_count)
      ? service.key_count
      : (keyAliases.length > 0 ? keyAliases.length : (keyReference ? 1 : 0)),
    capabilities: service.capabilities && typeof service.capabilities === 'object'
      ? service.capabilities
      : {
          discover_keys: Boolean(definition.supports_inventory),
          sign: true,
          rotate_keys: false,
          upload_public_keys: false,
          delete_keys: false,
          multiple_key_references: true,
        },
    key_purposes: Array.isArray(service.key_purposes) ? service.key_purposes.filter((p) => typeof p === 'string') : [],
    credential_formats: Array.isArray(service.credential_formats) ? service.credential_formats.filter((f) => typeof f === 'string') : [],
    rotation_policy: service.rotation_policy && typeof service.rotation_policy === 'object'
      ? {
          rotation_interval_days: Number.isFinite(service.rotation_policy.rotation_interval_days) ? service.rotation_policy.rotation_interval_days : null,
          overlap_days: Number.isFinite(service.rotation_policy.overlap_days) ? service.rotation_policy.overlap_days : 7,
          auto_publish: Boolean(service.rotation_policy.auto_publish),
        }
      : null,
    rotation_state: rotationState,
    last_rotated_at: lastRotatedAt,
    country_code: normalizeString(service.country_code) || null,
    authority_code: normalizeString(service.authority_code) || null,
    created_at: normalizeString(service.created_at) || null,
    updated_at: normalizeString(service.updated_at) || null,
  }
}

export const normalizeKeyManagementConfig = (data) => {
  const normalized = data && typeof data === 'object' ? data : {}
  const serviceTypeCatalog = normalizeServiceTypeCatalog(normalized.service_type_catalog)
  const rawServices = Array.isArray(normalized.services) ? normalized.services : createLegacyServiceFromConfig(normalized, serviceTypeCatalog)
  const services = rawServices
    .map((service) => normalizeKeyManagementService(service, serviceTypeCatalog))
    .filter(Boolean)

  const defaultServiceId = typeof normalized.default_service_id === 'string' && services.some((service) => service.id === normalized.default_service_id)
    ? normalized.default_service_id
    : services[0]?.id || null

  return {
    hsm_enabled: Boolean(normalized.hsm_enabled || services.length > 0),
    hsm_settings: normalized.hsm_settings && typeof normalized.hsm_settings === 'object'
      ? normalized.hsm_settings
      : {},
    vault_enabled: Boolean(normalized.vault_enabled),
    vault_settings: normalized.vault_settings && typeof normalized.vault_settings === 'object'
      ? normalized.vault_settings
      : {},
    provider_metadata: normalized.provider_metadata && typeof normalized.provider_metadata === 'object'
      ? normalized.provider_metadata
      : null,
    domain_config: normalized.domain_config && typeof normalized.domain_config === 'object'
      ? normalized.domain_config
      : null,
    supports_native_key_management: Boolean(normalized.supports_native_key_management),
    registration_mode: normalizeString(normalized.registration_mode) || 'external-only',
    default_service_id: defaultServiceId,
    service_type_catalog: serviceTypeCatalog,
    services,
  }
}

export const getDefaultKeyManagementService = (config) => {
  const normalizedConfig = normalizeKeyManagementConfig(config)
  return normalizedConfig.services.find((service) => service.id === normalizedConfig.default_service_id) || null
}

const generateServiceId = () => {
  if (globalThis.crypto?.randomUUID) {
    return `svc-${globalThis.crypto.randomUUID()}`
  }
  return `svc-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`
}

export const createKeyManagementServicePayload = (wizardData, catalog) => {
  const definition = getServiceTypeDefinition(catalog, wizardData.service_type)

  const rotationPolicy = wizardData.rotation_interval_days
    ? {
        rotation_interval_days: Number(wizardData.rotation_interval_days) || null,
        overlap_days: Number(wizardData.rotation_overlap_days) || 7,
        auto_publish: Boolean(wizardData.rotation_auto_publish),
      }
    : null

  return normalizeKeyManagementService(
    {
      id: wizardData.id || generateServiceId(),
      name: wizardData.name,
      description: wizardData.description,
      service_type: definition.id,
      provider: definition.provider,
      provider_label: definition.label,
      protocol: definition.protocol,
      endpoint: wizardData.endpoint,
      region: wizardData.region,
      mount: wizardData.mount,
      namespace: wizardData.namespace,
      auth_mode: wizardData.auth_mode,
      auth_reference: wizardData.auth_reference,
      key_reference: wizardData.key_reference,
      key_aliases: parseListInput(wizardData.key_aliases),
      algorithms: parseListInput(wizardData.algorithms),
      key_purposes: Array.isArray(wizardData.key_purposes) ? wizardData.key_purposes : [],
      credential_formats: Array.isArray(wizardData.credential_formats) ? wizardData.credential_formats : [],
      rotation_policy: rotationPolicy,
      country_code: wizardData.country_code || null,
      authority_code: wizardData.authority_code || null,
      status: 'registered',
      managed: false,
      read_only: false,
    },
    catalog,
  )
}

export default {
  DEFAULT_KEY_MANAGEMENT_CONFIG,
  DEFAULT_KEY_MANAGEMENT_SERVICE_TYPE_CATALOG,
  KEY_MANAGEMENT_ALGORITHM_OPTIONS,
  KEY_PURPOSE_ALGORITHM_CONSTRAINTS,
  KEY_MANAGEMENT_PURPOSES,
  PURPOSES_REQUIRING_CERTIFICATE,
  PURPOSES_REQUIRING_AUTHORITY,
  getAllowedAlgorithmsForPurpose,
  isAlgorithmAllowedForPurpose,
  getCompatiblePurposesForAlgorithm,
  normalizeKeyManagementConfig,
  normalizeKeyManagementService,
  normalizeServiceTypeCatalog,
  getServiceTypeDefinition,
  getDefaultKeyManagementService,
  createKeyManagementServicePayload,
  parseListInput,
}

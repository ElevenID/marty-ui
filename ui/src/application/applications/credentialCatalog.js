import PassportIcon from '@mui/icons-material/Flight';
import DLIcon from '@mui/icons-material/DirectionsCar';
import BadgeIcon from '@mui/icons-material/Badge';
import LoginIcon from '@mui/icons-material/Login';
import CredentialIcon from '@mui/icons-material/CardMembership';
import BusinessIcon from '@mui/icons-material/Business';

// Type metadata controls presentation only; protocol requirements come from the API.
export const CREDENTIAL_CATALOG_TYPES = {
  passport: {
    icon: PassportIcon,
    category: 'travel',
  },
  drivers_license: {
    icon: DLIcon,
    category: 'identity',
  },
  travel_visa: {
    icon: PassportIcon,
    category: 'travel',
  },
  access_badge: {
    icon: BusinessIcon,
    category: 'enterprise',
  },
  national_id: {
    icon: CredentialIcon,
    category: 'identity',
  },
  dtc: {
    icon: PassportIcon,
    category: 'travel',
  },
  open_badge: {
    icon: CredentialIcon,
    category: 'identity',
    searchAliases: ['open badge login', 'open badge login credential', 'achievement credential', 'passwordless sign-in', 'membership badge'],
  },
  MemberCredential: {
    icon: LoginIcon,
    category: 'identity',
  },
  'org.iso.18013.5.1.mDL': {
    icon: DLIcon,
    category: 'identity',
  },
  'com.elevenid.member_credential': {
    icon: BadgeIcon,
    category: 'identity',
  },
};

export function getCredentialCatalogCategories(t) {
  return [
    { value: 'all', label: t('catalog.categories.all') },
    { value: 'travel', label: t('catalog.categories.travel') },
    { value: 'identity', label: t('catalog.categories.identity') },
    { value: 'enterprise', label: t('catalog.categories.enterprise') },
    { value: 'education', label: t('catalog.categories.education') },
  ];
}

export function mapCredentialTemplateToCatalogItem(template, organizationName) {
  const meta = CREDENTIAL_CATALOG_TYPES[template?.credential_type] || {};
  const claims = Array.isArray(template?.claims) ? template.claims : [];
  const claimRequirements = claims
    .filter((claim) => claim?.required)
    .map((claim) => claim?.display?.label || claim?.display_name || claim?.name)
    .filter(Boolean);
  const ttlSeconds = template?.validity_rules?.ttl_seconds;
  const validityLabel = typeof ttlSeconds === 'number' && Number.isSafeInteger(ttlSeconds) && ttlSeconds > 0
    ? (ttlSeconds % 86400 === 0
      ? `${ttlSeconds / 86400} ${ttlSeconds === 86400 ? 'day' : 'days'}`
      : `${ttlSeconds} seconds`)
    : null;
  const formatLabels = { SD_JWT_VC: 'SD-JWT VC', MDOC: 'mDoc', VC_JWT: 'VC-JWT', JSON_LD: 'JSON-LD VC' };
  const apiFormat = typeof template.credential_payload_format === 'string' ? template.credential_payload_format.trim() : '';
  const format = apiFormat ? (formatLabels[apiFormat] || apiFormat) : null;
  const issuanceProtocol = typeof template.issuance_protocol === 'string' ? template.issuance_protocol.trim() || null : null;
  const walletIssuance = issuanceProtocol === 'OID4VCI_PRE_AUTH' || issuanceProtocol === 'OID4VCI_AUTH_CODE';

  return {
    id: template.id,
    credentialType: template.credential_type,
    name: template.name,
    description: template.description || template.name,
    icon: meta.icon || CredentialIcon,
    category: meta.category || 'identity',
    validityLabel,
    requirements: claimRequirements,
    requiredFields: claims.filter((claim) => claim?.required).map((claim) => claim?.name).filter(Boolean),
    optionalFields: claims.filter((claim) => !claim?.required).map((claim) => claim?.name).filter(Boolean),
    customFields: [],
    eligibilityCriteria: null,
    submissionInstructions: null,
    available: String(template.status || '').toLowerCase() === 'active',
    vendorName: organizationName || 'Issuer',
    templateVersion: template.version,
    visibility: 'organization',
    format,
    issuanceProtocol,
    standard: null,
    walletRequirements: format && walletIssuance ? `Wallet support required: ${format} with ${issuanceProtocol}.` : null,
    searchAliases: meta.searchAliases || [],
  };
}

export function extractExistingApplicationIds(applications = []) {
  return applications.map((application) => application?.credential_template_id).filter(Boolean);
}

/**
 * Extract per-credential application status and aggregate counts.
 * Returns { statusByCredentialId, counts }.
 */
export function extractApplicationStatusInfo(applications = []) {
  const statusByCredentialId = {};
  const counts = { pending: 0, approved: 0, offered: 0, rejected: 0, credentialed: 0 };

  for (const app of applications) {
    const configId = app?.credential_template_id;
    if (!configId) continue;
    const status = (app.status || '').toLowerCase();
    // Keep the most advanced status per credential
    statusByCredentialId[configId] = status;

    if (['submitted', 'under_review', 'pending_information', 'draft'].includes(status)) {
      counts.pending++;
    } else if (status === 'approved') {
      counts.approved++;
    } else if (status === 'offered') {
      counts.offered++;
    } else if (status === 'rejected') {
      counts.rejected++;
    } else if (['credentialed', 'issued'].includes(status)) {
      counts.credentialed++;
    }
  }

  return { statusByCredentialId, counts };
}

export function filterCredentialCatalogItems(credentials = [], { searchTerm = '', categoryFilter = 'all' } = {}) {
  const normalizedSearch = searchTerm.toLowerCase();

  return credentials.filter((credential) => {
    const aliases = Array.isArray(credential.searchAliases) ? credential.searchAliases : [];
    const searchableText = [
      credential.name,
      credential.description,
      credential.credentialType,
      credential.standard,
      credential.format,
      credential.issuanceProtocol,
      ...aliases,
    ].filter(Boolean).join(' ').toLowerCase();
    const matchesSearch = searchableText.includes(normalizedSearch);
    const matchesCategory = categoryFilter === 'all' || credential.category === categoryFilter;
    return matchesSearch && matchesCategory;
  });
}

export function scopeCredentialCatalogItemsForCanvasLaunch(credentials = [], { credentialTemplateIds = [] } = {}) {
  const allowedTemplateIds = new Set(
    (Array.isArray(credentialTemplateIds) ? credentialTemplateIds : [credentialTemplateIds])
      .filter((value) => value !== null && value !== undefined && String(value).trim() !== '')
      .map((value) => String(value))
  );

  if (allowedTemplateIds.size === 0) {
    return credentials;
  }

  return credentials.filter((credential) => allowedTemplateIds.has(String(credential?.id)));
}

export function resolveCredentialApplicationPath({
  credentialId,
  applicationTemplateId,
  currentPathname = '',
  isPreview = false,
}) {
  if (isPreview) {
    if (typeof applicationTemplateId !== 'string' || !applicationTemplateId.trim()) {
      throw new Error('An Application Template is required to preview this credential application.');
    }
    return `/applicant/preview/applications/${encodeURIComponent(applicationTemplateId)}`;
  }

  if (currentPathname.startsWith('/console/applicant')) {
    return `/console/applicant/apply/${credentialId}`;
  }

  return `/apply/${credentialId}`;
}

function buildCanvasLtiQuery(canvasLtiContext = null) {
  if (!canvasLtiContext || !canvasLtiContext.state) {
    return '';
  }

  const query = new URLSearchParams({ canvas_lti_state: String(canvasLtiContext.state) });
  const optionalParams = {
    canvas_program_binding_id: canvasLtiContext.canvas_program_binding_id,
    canvas_platform_id: canvasLtiContext.canvas_platform_id,
    application_template_id: canvasLtiContext.application_template_id,
    credential_template_id: canvasLtiContext.credential_template_id,
  };

  for (const [key, value] of Object.entries(optionalParams)) {
    if (value !== null && value !== undefined && String(value).trim() !== '') {
      query.set(key, String(value));
    }
  }

  return query.toString();
}

export function buildCredentialApplicationNavigationState(credential, options = {}) {
  const serializableCredential = { ...credential };
  delete serializableCredential.icon;
  const applicationTemplate = serializableCredential.application_template || null;
  delete serializableCredential.application_template;
  if (options.isPreview && (!applicationTemplate?.organization_id
    || applicationTemplate.credential_template_id !== credential.id
    || (credential.application_template_id && credential.application_template_id !== applicationTemplate.id)
    || (options.organizationId && applicationTemplate.organization_id !== options.organizationId))) {
    throw new Error('This Application Template is not available for the selected credential and organization.');
  }
  const basePath = resolveCredentialApplicationPath({
    credentialId: credential.id,
    applicationTemplateId: applicationTemplate?.id,
    currentPathname: options.currentPathname,
    isPreview: options.isPreview,
  });
  const navigationQuery = options.isPreview
    ? new URLSearchParams({ organization_id: applicationTemplate.organization_id }).toString()
    : buildCanvasLtiQuery(options.canvasLtiContext);
  const state = {
    credential: serializableCredential,
  };
  if (applicationTemplate) {
    state.applicationTemplate = applicationTemplate;
  }
  if (!options.isPreview && options.canvasLtiSession) {
    state.canvasLtiSession = options.canvasLtiSession;
  }

  return {
    path: navigationQuery ? `${basePath}?${navigationQuery}` : basePath,
    state,
  };
}

function normalizeOrganizationId(organizationId) {
  if (organizationId === null || organizationId === undefined) {
    return null;
  }

  if (typeof organizationId !== 'string' && typeof organizationId !== 'number') {
    return null;
  }

  const normalized = String(organizationId).trim();
  return normalized === '' ? null : normalized;
}

export async function loadCredentialCatalogItems({ organizationId, organizationName, listCredentialTemplates }) {
  const normalizedOrganizationId = normalizeOrganizationId(organizationId);
  if (!normalizedOrganizationId) {
    return {
      credentials: [],
      error: new Error('Organization context is required to load the credential catalog.'),
      missingOrganization: true,
    };
  }

  try {
    const data = await listCredentialTemplates(normalizedOrganizationId);
    const templates = Array.isArray(data) ? data : (data?.templates || []);

    return {
      credentials: templates
        .filter((template) => (
          String(template?.status || '').toUpperCase() === 'ACTIVE'
          && Boolean(template?.revocation_profile_id)
        ))
        .map((template) => mapCredentialTemplateToCatalogItem(template, organizationName)),
      error: null,
      missingOrganization: false,
    };
  } catch (error) {
    return {
      credentials: [],
      error,
      missingOrganization: false,
    };
  }
}

export async function loadExistingCredentialApplications({ organizationId, userId, getApplicantByUser, listApplicantApplications }) {
  if (!organizationId || !userId) {
    return [];
  }

  try {
    const applicant = await getApplicantByUser(userId);
    if (!applicant?.id) {
      return [];
    }

    const data = await listApplicantApplications(applicant.id);
    return extractExistingApplicationIds(data);
  } catch {
    return [];
  }
}

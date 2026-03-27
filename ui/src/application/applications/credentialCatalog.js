import PassportIcon from '@mui/icons-material/Flight';
import DLIcon from '@mui/icons-material/DirectionsCar';
import BadgeIcon from '@mui/icons-material/Badge';
import LoginIcon from '@mui/icons-material/Login';
import CredentialIcon from '@mui/icons-material/CardMembership';
import SchoolIcon from '@mui/icons-material/School';
import BusinessIcon from '@mui/icons-material/Business';

export const CREDENTIAL_CATALOG_TYPES = {
  passport: {
    description: 'ICAO 9303 compliant digital travel credential with NFC capability',
    icon: PassportIcon,
    category: 'travel',
    processingTime: '5-10 business days',
    requirements: ['Government-issued ID', 'Proof of citizenship', 'Biometric photo'],
  },
  drivers_license: {
    description: 'ISO/IEC 18013-5 compliant mobile driving license',
    icon: DLIcon,
    category: 'identity',
    processingTime: '3-5 business days',
    requirements: ['Current driver\'s license', 'Proof of residence', 'Biometric photo'],
  },
  travel_visa: {
    description: 'Digitally issued travel visa credential for approved applicants',
    icon: PassportIcon,
    category: 'travel',
    processingTime: '5-10 business days',
    requirements: ['Valid passport', 'Proof of travel intent'],
  },
  access_badge: {
    description: 'Corporate access badge — verifiable proof of employment, department, and building access. Issued instantly to your wallet.',
    icon: BusinessIcon,
    category: 'enterprise',
    processingTime: 'Instant upon issuance',
    requirements: ['Active ElevenID account'],
    format: 'vc+sd-jwt',
    standard: 'W3C Verifiable Credential',
    worksWithLabel: 'Web & VC wallets',
  },
  national_id: {
    description: 'National identity credential for verified applicants',
    icon: CredentialIcon,
    category: 'identity',
    processingTime: '5-10 business days',
    requirements: ['Government-issued ID', 'Biometric photo'],
  },
  dtc: {
    description: 'Digital Travel Credential per ICAO DTC specification',
    icon: PassportIcon,
    category: 'travel',
    processingTime: '3-5 business days',
    requirements: ['Valid passport', 'Biometric photo'],
  },
  open_badge: {
    description: 'Open Badge 3.0 professional development certificate — instantly issued, recognized by employers and institutions worldwide.',
    icon: SchoolIcon,
    category: 'education',
    processingTime: 'Instant upon issuance',
    requirements: ['Active ElevenID account'],
    format: 'vc+sd-jwt',
    standard: 'W3C / Open Badge 3.0',
    worksWithLabel: 'Web & VC wallets',
  },
  MemberCredential: {
    description: 'Log in securely using your wallet — no password required. W3C Verifiable Credential in SD-JWT format, compatible with web and VC wallets.',
    icon: LoginIcon,
    category: 'identity',
    processingTime: 'Instant upon issuance',
    requirements: ['Active ElevenID account'],
    format: 'vc+sd-jwt',
    standard: 'W3C / Open Badge 3.0',
    worksWithLabel: 'Web & VC wallets',
  },
  'org.iso.18013.5.1.mDL': {
    description: 'Mobile-first membership identity in mDoc format — compatible with Apple & Google Wallet style experiences. Issued instantly.',
    icon: DLIcon,
    category: 'identity',
    processingTime: 'Instant upon issuance',
    requirements: ['Active ElevenID account'],
    format: 'mDoc (ISO 18013-5)',
    standard: 'ISO/IEC 18013-5',
    worksWithLabel: 'Mobile wallets (Apple / Google)',
  },
  'com.elevenid.member_credential': {
    description: 'Membership ID in mDoc format — same identity data as the Login Credential, packaged for Apple & Google Wallet style experiences.',
    icon: BadgeIcon,
    category: 'identity',
    processingTime: 'Instant upon issuance',
    requirements: ['Active ElevenID account'],
    format: 'mDoc (ISO 18013-5)',
    standard: 'ISO/IEC 18013-5',
    worksWithLabel: 'Mobile wallets (Apple / Google)',
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
    .map((claim) => claim?.display_name || claim?.name)
    .filter(Boolean);
  const processingDays = template?.validity_rules?.default_validity_days;

  return {
    id: template.id,
    credentialType: template.credential_type,
    name: template.name,
    description: template.description || meta.description || template.name,
    icon: meta.icon || CredentialIcon,
    category: meta.category || 'identity',
    processingTime: processingDays
      ? `${processingDays} day validity`
      : (meta.processingTime || '3-5 business days'),
    requirements: claimRequirements.length > 0 ? claimRequirements : (meta.requirements || []),
    requiredFields: claims.filter((claim) => claim?.required).map((claim) => claim?.name).filter(Boolean),
    optionalFields: claims.filter((claim) => !claim?.required).map((claim) => claim?.name).filter(Boolean),
    customFields: [],
    eligibilityCriteria: null,
    submissionInstructions: null,
    processingFee: 0,
    available: template.status === 'active',
    vendorName: organizationName || 'Issuer',
    templateVersion: template.version,
    visibility: 'organization',
    format: meta.format || null,
    standard: meta.standard || null,
    worksWithLabel: meta.worksWithLabel || null,
  };
}

export function extractExistingApplicationIds(applications = []) {
  return applications.map((application) => application?.credential_configuration_id).filter(Boolean);
}

/**
 * Extract per-credential application status and aggregate counts.
 * Returns { statusByCredentialId, counts }.
 */
export function extractApplicationStatusInfo(applications = []) {
  const statusByCredentialId = {};
  const counts = { pending: 0, approved: 0, rejected: 0, credentialed: 0 };

  for (const app of applications) {
    const configId = app?.credential_configuration_id;
    if (!configId) continue;
    const status = (app.status || '').toLowerCase();
    // Keep the most advanced status per credential
    statusByCredentialId[configId] = status;

    if (['submitted', 'under_review', 'pending_information', 'draft'].includes(status)) {
      counts.pending++;
    } else if (status === 'approved') {
      counts.approved++;
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
    const matchesSearch = credential.name.toLowerCase().includes(normalizedSearch)
      || credential.description.toLowerCase().includes(normalizedSearch);
    const matchesCategory = categoryFilter === 'all' || credential.category === categoryFilter;
    return matchesSearch && matchesCategory;
  });
}

export function buildCredentialApplicationNavigationState(credential) {
  const serializableCredential = { ...credential };
  delete serializableCredential.icon;
  return {
    path: `/apply/${credential.id}`,
    state: {
      credential: serializableCredential,
    },
  };
}

export async function loadCredentialCatalogItems({ organizationId, organizationName, listCredentialTemplates }) {
  try {
    const data = await listCredentialTemplates(organizationId);
    const templates = Array.isArray(data) ? data : (data?.templates || []);

    return {
      credentials: templates.map((template) => mapCredentialTemplateToCatalogItem(template, organizationName)),
      error: null,
    };
  } catch (error) {
    return {
      credentials: [],
      error: null,
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
    const applications = Array.isArray(data) ? data : (data?.applications || []);
    return extractExistingApplicationIds(applications);
  } catch {
    return [];
  }
}

/**
 * Marketing Content
 * 
 * Centralized content for marketing pages to ensure consistency
 * across Product, Standards, and Identity Guide pages
 */

// Core value proposition
export const VALUE_PROPOSITION = {
  headline: 'Identity verification is not enough.',
  subheadline: 'Build verifiable identity infrastructure.',
  extendedSubheadline: 'Issue, verify, and govern credentials—built for EUDI Wallets, Open Badges, and enterprise trust.',
  secondaryCTA: {
    label: 'Why Verifiable Identity',
    path: '/from-idv-to-verifiable-identity',
  },
};

// IDV vs ElevenID comparison
export const IDV_COMPARISON = {
  title: 'From IDV to Verifiable Identity',
  takeaway: 'ElevenID replaces repeated verification with reusable trust.',
  traditional: [
    { label: 'One-time document checks', category: 'Traditional IDV' },
    { label: 'Vendor-controlled identity data', category: 'Traditional IDV' },
    { label: 'Biometric decision outputs', category: 'Traditional IDV' },
    { label: 'Closed, proprietary APIs', category: 'Traditional IDV' },
    { label: 'Manual trust configuration', category: 'Traditional IDV' },
    { label: 'Re-verification everywhere', category: 'Traditional IDV' },
  ],
  elevenid: [
    { label: 'Reusable verifiable credentials', category: 'ElevenID' },
    { label: 'Holder-controlled digital wallets', category: 'ElevenID' },
    { label: 'Cryptographic proofs', category: 'ElevenID' },
    { label: 'Open standards (W3C VC, OID4VC, ISO)', category: 'ElevenID' },
    { label: 'Governed trust registries', category: 'ElevenID' },
    { label: 'Identity reuse across ecosystems', category: 'ElevenID' },
  ],
};

// EUDI & Open Badges strategic positioning
export const EUDI_OPEN_BADGES = {
  title: 'Built for EUDI Wallets and Verifiable Credentials',
  points: [
    'Verify Verifiable Credentials—not just documents.',
    'Trust issuers—not databases.',
    'Wallet-first by design—EUDI-ready.',
  ],
  quote: 'IDV platforms stop at a one-time decision. ElevenID produces cryptographically verifiable outcomes that can be reused across wallets, ecosystems, and trust registries.',
};

// Why this matters for organizations
export const ORGANIZATION_OUTCOMES = {
  title: 'Why This Matters for Organizations',
  outcomes: [
    'Reduce repeat KYC costs with reusable credentials',
    'Prepare for EUDI Wallet acceptance',
    'Avoid vendor lock-in with open standards',
    'Support Open Badges, workforce credentials, and government IDs in one system',
  ],
};

// Audience routing - helps different buyer personas find their path
export const AUDIENCE_ROUTING = {
  title: 'Choose Your Path',
  subtitle: 'Pick your entry point—enterprise, government, or developers.',
  paths: [
    {
      id: 'enterprise',
      title: 'Enterprise',
      description: 'Reduce repeat KYC, enable partner interoperability, and govern trust at scale.',
      cta: 'Explore Enterprise',
      path: '/product',
      color: 'primary',
    },
    {
      id: 'government',
      title: 'Government',
      description: 'EUDI-ready infrastructure for ISO credentials, trust lists, and regulated acceptance.',
      cta: 'Explore Government',
      path: '/standards',
      color: 'secondary',
    },
    {
      id: 'developers',
      title: 'Developers',
      description: 'Docs, SDKs, and quickstarts for VC issuance and verification.',
      cta: 'Read Docs',
      path: '/api-docs',
      color: 'info',
    },
  ],
};

// Substantiated proof claims - only include claims we can defend
export const PROOF_STRIP = {
  title: 'Built on Proven Foundations',
  claims: [
    { label: 'W3C VC / SD-JWT / OID4VP', category: 'Interoperability' },
    { label: '72-hour offline cache', category: 'Offline Verification' },
    { label: 'SaaS + Self-hosted', category: 'Deployment' },
    { label: 'HSM / Vault integration', category: 'Key Security' },
    { label: 'Immutable audit logs', category: 'Compliance' },
  ],
};

// Products (from product-catalog)
export const PRODUCTS = [
  {
    id: 'verification-api',
    name: 'Verification API',
    tagline: 'Verify VCs, SD-JWTs, and ISO credentials against governed trust.',
    description: 'ICAO 9303 eMRTD and ISO 18013-5 mDoc verification. PKD trust anchor sync. OID4VP presentation flows.',
    deployment: ['SaaS', 'Self-hosted'],
    capabilities: [
      'ICAO 9303 eMRTD verification',
      'ISO 18013-5 mDL verification',
      'PKD trust anchor sync',
      'Signature validation & policy engine',
      'OID4VP, SD-JWT support',
      'QR/NFC presentation',
    ],
    standards: ['ICAO 9303', 'ISO 18013-5', 'OpenID4VP', 'SD-JWT'],
    pricing: 'Volume tiers (SaaS) or annual license (self-hosted)',
    useCase: 'Border control, DMV, high-assurance identity verification',
    replacesExtends: 'Replaces repeated IDV checks with reusable verification.',
    useWhen: 'Use when verifying EUDI wallets, Open Badges, or ISO credentials.',
  },
  {
    id: 'issuance-api',
    name: 'Issuance API',
    tagline: 'Issue standards-based credentials with lifecycle controls.',
    description: 'OpenID4VCI credential offers, document signing, audit trails, and selective disclosure policies',
    deployment: ['Self-hosted'],
    capabilities: [
      'OpenID4VCI credential issuance',
      'Pre-authorized flows',
      'Document signing',
      'Audit trails & policy engine',
      'Selective disclosure',
      'Batch & API-driven issuance',
    ],
    standards: ['OpenID4VCI', 'SD-JWT', 'W3C VC', 'mDoc (ISO 18013-5)'],
    pricing: 'Annual license per environment',
    useCase: 'DMV, government issuers, enterprise credential programs',
    replacesExtends: 'Replaces proprietary credential silos.',
    useWhen: 'Use when issuing workforce, education, or government credentials.',
  },
  {
    id: 'kiosk',
    name: 'Kiosk',
    tagline: 'Edge/offline verification for facilities and checkpoints.',
    description: 'Offline-first verification with QR/NFC/BLE support and optional biometrics',
    deployment: ['On-site application'],
    capabilities: [
      'Offline-first (72h cache)',
      'QR/NFC/BLE scanning',
      'Biometric verification',
      'TPM-bound licensing',
      'Local policy enforcement',
    ],
    standards: ['ICAO 9303', 'ISO 18013-5', 'BLE', 'NFC'],
    pricing: 'Per-device license with optional hardware bundles',
    useCase: 'Airports, checkpoints, secure facilities',
    replacesExtends: 'Extends EUDI acceptance to edge/offline environments.',
    useWhen: 'Use when connectivity is limited or controlled.',
  },
  {
    id: 'authenticator',
    name: 'Authenticator',
    tagline: 'A wallet for holding and presenting verifiable credentials.',
    description: 'Mobile/desktop wallet for mDoc/mDL/VC credential storage and presentation',
    deployment: ['Mobile (iOS, Android)', 'Desktop'],
    capabilities: [
      'mDoc/mDL/VC storage',
      'QR offline presentations',
      'OpenID4VP flows',
      'Biometric protection',
      'Multi-credential support',
    ],
    standards: ['ISO 18013-5', 'W3C VC', 'OpenID4VP'],
    pricing: 'Free / Community edition',
    useCase: 'End users, citizens, credential holders',
    replacesExtends: 'Wallet-centric alternative to biometric re-verification.',
    useWhen: 'Use when users must present proofs across services.',
  },
];

// Standards information
export const STANDARDS_INFO = {
  whyStandardsMatter: {
    title: 'Why Standards Matter',
    points: [
      {
        title: 'Portability',
        description: 'Credentials work across vendors and jurisdictions',
      },
      {
        title: 'Trust',
        description: 'Cryptographic proof follows established protocols',
      },
      {
        title: 'Longevity',
        description: 'Investment protection through stable, evolving specs',
      },
      {
        title: 'Interoperability',
        description: 'Seamless integration with global identity ecosystems',
      },
    ],
  },
  layers: [
    {
      name: 'Identity Standards',
      description: 'Foundation frameworks for identity systems',
      standards: [
        { name: 'ICAO 9303', description: 'Global travel document verification' },
        { name: 'eIDAS', description: 'EU electronic identification regulation' },
        { name: 'EUDI Wallet', description: 'EU Digital Identity Wallet interoperability' },
      ],
    },
    {
      name: 'Credential Formats',
      description: 'How credentials are structured and encoded',
      standards: [
        { name: 'mDoc (ISO 18013-5)', description: 'Mobile credentials with offline verification' },
        { name: 'SD-JWT', description: 'Selective disclosure for privacy' },
        { name: 'W3C VC', description: 'Portable credentials across ecosystems' },
      ],
    },
    {
      name: 'Transport Protocols',
      description: 'How credentials are exchanged between parties',
      standards: [
        { name: 'OpenID4VP', description: 'Wallet-based presentations across ecosystems' },
        { name: 'OpenID4VCI', description: 'Standards-based credential issuance' },
        { name: 'QR/NFC/BLE', description: 'Physical transport for offline scenarios' },
      ],
    },
    {
      name: 'Trust & Governance',
      description: 'How trust is established and maintained',
      standards: [
        { name: 'PKI + X.509', description: 'Cryptographic trust anchors' },
        { name: 'ICAO PKD', description: 'Global travel document trust' },
        { name: 'Trust Lists', description: 'Authorized issuer registries' },
      ],
    },
  ],
};

// Identity concepts (adapted from Digital_Identity_model.md)
export const IDENTITY_CONCEPTS = {
  whatIs: {
    title: 'What Digital Identity Is',
    tagline: 'Not a database record. Not a login session.',
    definition: 'Digital identity is a cryptographically verifiable set of claims that can be issued, held, and presented under explicit rules of trust and disclosure.',
    problems: [
      "Fragmented identity systems that don't interoperate",
      'Unclear issuer trust across partners and jurisdictions',
      'Privacy compliance pressure (data minimization + selective disclosure)',
      'PKI + revocation complexity at scale',
    ],
  },
  threeQuestions: {
    title: 'Identity Answers Three Questions',
    questions: [
      {
        question: 'Authenticity',
        description: 'Was this claim issued by an authority I trust?',
        detail: 'Verify issuer signatures against known trust anchors and PKI',
      },
      {
        question: 'Binding',
        description: 'Is the presenter the legitimate holder of this credential?',
        detail: 'Proof of possession through cryptographic challenges and biometric binding',
      },
      {
        question: 'Appropriateness',
        description: 'Is the disclosed information sufficient—and no more than necessary?',
        detail: 'Selective disclosure and zero-knowledge proofs for data minimization',
      },
    ],
    conclusion: 'Identity becomes a transaction: request → present → validate → decide',
  },
  fourPrimitives: {
    title: 'The Four Primitives',
    tagline: 'Digital identity management as automatable configuration',
    primitives: [
      {
        name: 'Trust Profile',
        purpose: 'Define who is trusted and how cryptographic validation happens',
        contains: [
          'Trust sources (PKD, Trust Lists, pinned issuers)',
          'Validation rules (algorithms, key usage)',
          'Revocation policy (OCSP, CRL, offline grace)',
          'Supported formats (mDoc, VC, SD-JWT)',
        ],
        stability: 'Changes rarely; owned by security/admin',
      },
      {
        name: 'Credential Template',
        purpose: 'Define what is issued and what it means',
        contains: [
          'Credential type and schema',
          'Claims map and derived attributes',
          'Validity rules (TTL, reissue)',
          'Issuer constraints and keys',
          'Selective disclosure configuration',
        ],
        stability: 'Changes occasionally; owned by program/compliance',
      },
      {
        name: 'Presentation Policy',
        purpose: 'Define what must be shown to satisfy a verifier',
        contains: [
          'Accepted credential types',
          'Required claims or predicates',
          'Holder-binding requirements',
          'Issuer constraints',
          'Freshness and revocation rules',
        ],
        stability: 'Changes frequently; owned by product/ops',
      },
      {
        name: 'Deployment Profile',
        purpose: 'Package trust + policies + runtime for endpoints',
        contains: [
          'Enabled flows and default policies',
          'Network mode (online/offline)',
          'UX configuration',
          'Update channel and versioning',
          'Device groupings (lanes)',
        ],
        stability: 'Changes frequently; owned by operations',
      },
    ],
  },
  flows: {
    title: 'Orchestrated by Flows',
    description: 'Flows tie primitives together into end-to-end journeys',
    stages: ['Apply', 'Approve', 'Issue', 'Present', 'Verify'],
    examples: [
      {
        name: 'Pre-Border Screening',
        description: 'Traveler submits passport → authority issues clearance → present at gate',
      },
      {
        name: 'Age Verification',
        description: 'Customer presents mDL → kiosk checks age_over_21 → approve purchase',
      },
      {
        name: 'Employee Access',
        description: 'Employee presents badge → verify employment status → grant door access',
      },
    ],
  },
};

// Infrastructure value proposition
export const INFRASTRUCTURE_VALUE = {
  title: 'Why Infrastructure Beats Per-Check Pricing',
  points: [
    'Verification becomes a commodity',
    'Trust orchestration compounds in value',
    'Reusable credentials reduce long-term cost',
    'Standards prevent vendor lock-in',
  ],
};

// Standards as strategic advantage
export const STANDARDS_STRATEGIC = {
  header: 'Standards are not integrations. They are the product.',
  categories: [
    {
      name: 'Wallet Interoperability',
      standards: ['W3C VC', 'OpenID4VP', 'SD-JWT'],
    },
    {
      name: 'Government Identity',
      standards: ['ISO 18013-5', 'ICAO 9303'],
    },
    {
      name: 'Trust & Governance',
      standards: ['PKI', 'Trust Lists', 'X.509'],
    },
  ],
};

// Trust and infrastructure messaging
export const TRUST_SIGNALS = {
  security: [
    'Enterprise-grade cryptographic validation',
    'PKI and revocation management',
    'HSM and key vault integration',
  ],
  infrastructure: [
    'Offline-first capability (72h cache)',
    'High-availability SaaS deployment',
    'Self-hosted options for sovereignty',
    'Horizontal scaling and load balancing',
  ],
  compliance: [
    'Implements ICAO 9303',
    'Implements ISO 18013-5 (mDoc)',
    'GDPR and privacy by design',
    'Selective disclosure and data minimization',
  ],
};

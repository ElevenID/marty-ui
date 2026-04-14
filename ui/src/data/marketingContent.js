/**
 * Marketing Content
 * 
 * Centralized content for marketing pages to ensure consistency
 * across Product, Standards, and Identity Guide pages
 */

// Core value proposition
export const VALUE_PROPOSITION = {
  headline: 'Identity verification is not enough.',
  supportingSubheadline: 'Move from one-time checks to reusable, cryptographically verifiable identity.',
  subheadline: 'Build verifiable identity infrastructure.',
  extendedSubheadline: 'Issue, verify, and govern credentials—built for EUDI Wallets, Open Badges, and enterprise trust.',
  primaryCTA: 'Start Verifying Credentials',
  secondaryCTA: {
    label: 'View Verification API',
    path: '/verifiable-credential-api',
  },
  concreteExample: 'A user verifies their age once, then reuses that proof across services—without re-uploading documents.',
};

// IDV vs ElevenID LLC comparison
export const IDV_COMPARISON = {
  title: 'From IDV to Verifiable Identity',
  takeaway: 'ElevenID LLC replaces repeated verification with reusable trust.',
  traditional: [
    { label: 'One-time document checks', category: 'Traditional IDV' },
    { label: 'Vendor-controlled identity data', category: 'Traditional IDV' },
    { label: 'Biometric decision outputs', category: 'Traditional IDV' },
    { label: 'Closed, proprietary APIs', category: 'Traditional IDV' },
    { label: 'Manual trust configuration', category: 'Traditional IDV' },
    { label: 'Re-verification everywhere', category: 'Traditional IDV' },
  ],
  elevenid: [
    { label: 'Reusable verifiable credentials', category: 'ElevenID LLC' },
    { label: 'Holder-controlled digital wallets', category: 'ElevenID LLC' },
    { label: 'Cryptographic proofs', category: 'ElevenID LLC' },
    { label: 'Open standards (W3C VC, OID4VC, ISO)', category: 'ElevenID LLC' },
    { label: 'Governed trust registries', category: 'ElevenID LLC' },
    { label: 'Identity reuse across ecosystems', category: 'ElevenID LLC' },
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
  quote: 'IDV platforms stop at a one-time decision. ElevenID LLC produces cryptographically verifiable outcomes that can be reused across wallets, ecosystems, and trust registries.',
};

// Why this matters for organizations
export const ORGANIZATION_OUTCOMES = {
  title: 'Why This Matters',
  outcomes: [
    { text: 'Reduce repeat KYC costs with reusable credentials', bold: 'cost reduction', metric: 'Up to 80% fewer repeat checks' },
    { text: 'Prepare for EUDI Wallet acceptance', bold: 'compliance', metric: 'EUDI & eIDAS 2.0 ready' },
    { text: 'Avoid vendor lock-in with open standards', bold: 'interoperability', metric: 'W3C, ISO, OpenID native' },
    { text: 'Support Open Badges, workforce credentials, and government IDs in one system', bold: 'unification', metric: 'One platform, all formats' },
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
      benefit: 'Reduce KYC cost by up to 80%',
      cta: 'Explore Solutions',
      path: '/solutions',
      color: 'primary',
      icon: 'Business',
    },
    {
      id: 'government',
      title: 'Government',
      description: 'EUDI-ready infrastructure for ISO credentials, trust lists, and regulated acceptance.',
      benefit: 'EUDI-ready compliance out of the box',
      cta: 'View Architecture',
      path: '/architecture',
      color: 'secondary',
      icon: 'AccountBalance',
    },
    {
      id: 'developers',
      title: 'Developers',
      description: 'Docs, SDKs, and quickstarts for VC issuance and verification.',
      benefit: 'Ship VC flows fast',
      cta: 'Start Verifying',
      path: '/developers',
      color: 'info',
      icon: 'Code',
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

export const ECOSYSTEM_SIGNALS = {
  title: 'Built for the ecosystems reviewers already know',
  categories: [
    {
      label: 'Wallet and VC standards',
      items: ['W3C VC', 'OpenID4VCI', 'OpenID4VP', 'SD-JWT'],
    },
    {
      label: 'Government and regulated credentials',
      items: ['ISO 18013-5', 'ICAO 9303', 'EUDI Wallet', 'Trust lists'],
    },
    {
      label: 'Operational deployment',
      items: ['SaaS', 'Self-hosted', 'Offline kiosks', 'Audit logs'],
    },
  ],
};

export const HERO_INTERACTIVE_DEMO = {
  eyebrow: 'Interactive credential moment',
  title: 'Issue once. Reuse everywhere.',
  description: 'Walk through the reusable identity flow buyers need to understand in under 20 seconds.',
  steps: [
    {
      id: 'issue',
      label: 'Issue the badge',
      moment: 'Onboarding complete',
      headline: 'A signed workforce credential lands in Jamie Lee\'s wallet.',
      summary: 'The platform issues once, binds the credential to the holder, and records the event for audit and lifecycle control.',
      credential: 'Credential template: workforce-access-badge',
      decision: 'Ready for the lobby kiosk, partner portal, and shift check-in flows.',
      highlights: ['Signed credential', 'Wallet-bound', 'Audit logged'],
      reuseNote: 'The first verification event creates a portable proof instead of another document review.',
    },
    {
      id: 'present',
      label: 'Present the proof',
      moment: 'Lobby check-in',
      headline: 'Jamie shares only employment status and access zone.',
      summary: 'A presentation policy asks for the minimum disclosure needed at the door, rather than exposing a raw onboarding record.',
      credential: 'Claims disclosed: employment_active, access_zone_hq_north',
      decision: 'Trust profile, expiry, and revocation checks all pass before approval.',
      highlights: ['Selective disclosure', 'Policy-enforced', 'Trusted issuer'],
      reuseNote: 'The verifier receives governed claims and a decision, not a full identity dossier.',
    },
    {
      id: 'reuse',
      label: 'Reuse at the next checkpoint',
      moment: 'Partner portal and internal app',
      headline: 'The same credential is reused without rescanning source documents.',
      summary: 'The holder presents the existing proof again through QR, browser, or API-assisted verification while each verifier keeps its own policy.',
      credential: 'One wallet credential supports multiple verifier channels.',
      decision: 'Consistent approval, audit evidence, and trust evaluation across checkpoints.',
      highlights: ['Reusable proof', 'QR or API flow', 'No re-enrollment'],
      reuseNote: 'That is the core value proposition: the proof survives the first verification moment.',
    },
  ],
};

export const END_USER_EXPERIENCES = {
  title: 'Make the end-user moment obvious',
  subtitle: 'Protocols matter, but adoption happens when the experience is fast, private, and repeatable.',
  journeys: [
    {
      id: 'building-access',
      label: 'Building access',
      persona: 'Employee',
      environment: 'Lobby kiosk',
      title: 'Tap a workforce badge at the door',
      summary: 'An employee presents a wallet-held workforce credential to enter the right zone without a help-desk checkpoint.',
      steps: [
        { label: 'Request', description: 'The kiosk asks for employment status and access zone only.' },
        { label: 'Present', description: 'The wallet shares the minimum claims required by policy.' },
        { label: 'Decide', description: 'The door unlocks and the event is logged.' },
      ],
      holderView: 'The holder sees exactly what will be shared before confirming.',
      verifierView: 'The kiosk gets governed claims and a pass decision instead of a raw employee file.',
      disclosed: ['employment_active', 'access_zone_hq_north'],
      verifierChecks: ['Trusted issuer', 'Door policy', 'Revocation checked'],
      benefits: ['No help-desk queue', 'No badge reprint'],
      outcome: 'Fast entry with reusable proof instead of repeated onboarding checks.',
    },
    {
      id: 'age-assurance',
      label: 'Age assurance',
      persona: 'Customer',
      environment: 'Retail checkout',
      title: 'Prove eligibility without revealing a birthday',
      summary: 'A shopper proves they are over 21 using selective disclosure or predicate-style claims from a wallet credential.',
      steps: [
        { label: 'Request', description: 'The verifier asks for age_over_21 rather than the full license image.' },
        { label: 'Present', description: 'The wallet shares a minimal proof backed by issuer trust.' },
        { label: 'Decide', description: 'The cashier or kiosk receives a clear pass or fail result.' },
      ],
      holderView: 'The user consents to a minimal proof instead of exposing a full identity document.',
      verifierView: 'The verifier gets a compliant answer tied to policy, trust, and freshness checks.',
      disclosed: ['age_over_21', 'issuer_trust'],
      verifierChecks: ['Policy evaluated', 'Issuer trusted', 'Expiry and revocation checked'],
      benefits: ['Privacy-preserving compliance', 'Less manual inspection'],
      outcome: 'A privacy-first experience that still satisfies regulated verification requirements.',
    },
    {
      id: 'travel-checkpoint',
      label: 'Travel checkpoint',
      persona: 'Traveler',
      environment: 'Gate or border',
      title: 'Reuse travel clearance across checkpoints',
      summary: 'A traveler presents an mDoc or passport-derived credential first at pre-clearance and again at the gate without re-enrollment.',
      steps: [
        { label: 'Request', description: 'The checkpoint asks for document authenticity and journey entitlement.' },
        { label: 'Present', description: 'The wallet or device presents the previously issued travel proof.' },
        { label: 'Decide', description: 'Each verifier applies its own trust rules and records the result.' },
      ],
      holderView: 'The traveler stays in control of the credential between checkpoints.',
      verifierView: 'Each checkpoint can enforce its own policy without asking the traveler to start over.',
      disclosed: ['document_authentic', 'clearance_status', 'journey_entitlement'],
      verifierChecks: ['ICAO or ISO trust', 'Journey policy', 'Reusable clearance proof'],
      benefits: ['Fewer repeated checks', 'Consistent checkpoint logic'],
      outcome: 'One issuance moment supports multiple trusted verifications across the journey.',
    },
  ],
};

export const DEVELOPER_QUICKSTART = {
  title: 'Verify a credential in one request.',
  description: 'Start with the stateless verification endpoint when you already have the credential payload. Move to wallet and QR flows when the holder needs to present interactively.',
  snippet: `curl -X POST "$ELEVENID_API_BASE/v1/credentials/verify" \\
  -H "Authorization: Bearer $ELEVENID_API_KEY" \\
  -H "Content-Type: application/json" \\
  -d '{
    "credential": {
      "id": "cred_employee_42",
      "type": ["VerifiableCredential", "WorkforceAccessBadge"],
      "issuer": "did:web:issuer.example.com"
    },
    "presentation_policy_id": "policy_building_access",
    "trust_profile_id": "trust_workforce_v1"
  }'`,
  response: `{
  "valid": true,
  "verification_result": {
    "signature_valid": true,
    "not_expired": true,
    "not_revoked": true
  }
}`,
  bullets: [
    'POST /v1/credentials/verify for stateless backend validation.',
    'Attach presentation_policy_id and trust_profile_id to enforce governed checks.',
    'Use /flows/verify when the user needs a wallet, QR, or kiosk presentation step.',
  ],
  note: 'The UI verifyCredential client uses this exact request shape against /v1/credentials/verify.',
};

export const INTERACTIVE_PROOF_LAB = {
  eyebrow: 'Code-native proof lab',
  title: 'See the decision surface without a staged demo.',
  subtitle: 'Switch scenarios to inspect the request, the bounded proof, the verifier checks, and the decision that comes back.',
  scenarios: [
    {
      id: 'retail-age',
      label: 'Retail age',
      title: 'Retail age check',
      channel: 'Self-checkout kiosk',
      summary: 'The verifier asks one bounded question: is the shopper over twenty-one?',
      requestPath: 'POST /flows/verify',
      requestSummary: 'Request age_over_21 plus issuer trust, not the full license payload.',
      holderSummary: 'The wallet shows a minimal disclosure request before the customer confirms.',
      disclosed: ['age_over_21', 'issuer_trust'],
      verifierChecks: [
        {
          label: 'Trusted issuer',
          detail: 'The trust profile resolves the approved issuer for the retail lane.',
          status: 'pass',
        },
        {
          label: 'Fresh credential',
          detail: 'Expiry and revocation rules satisfy the current checkout policy.',
          status: 'pass',
        },
        {
          label: 'Minimum disclosure',
          detail: 'No birth date, address, or document image leaves the wallet.',
          status: 'pass',
        },
      ],
      eventLog: [
        'Verifier loads the retail age policy.',
        'Wallet shares one bounded proof.',
        'Checkout receives allow_purchase = true and continues the sale.',
      ],
      outcome: 'The sale proceeds without scanning or storing the full ID.',
      proof: 'Bounded question, bounded answer.',
      slug: 'deploy-age-verification',
      cta: 'Read the retail playbook',
    },
    {
      id: 'enterprise-access',
      label: 'Enterprise access',
      title: 'Employee access check',
      channel: 'Lobby kiosk and internal portal',
      summary: 'One workforce credential is reused at the door and again inside the application stack.',
      requestPath: 'POST /v1/credentials/verify',
      requestSummary: 'Request employment_active and access_zone_hq_north from the existing badge.',
      holderSummary: 'The holder reuses the same credential instead of repeating onboarding or showing a different badge system.',
      disclosed: ['employment_active', 'access_zone_hq_north'],
      verifierChecks: [
        {
          label: 'Issuer trusted',
          detail: 'The enterprise trust profile pins the corporate issuer and signing keys.',
          status: 'pass',
        },
        {
          label: 'Policy matched',
          detail: 'The presentation policy checks zone access and application scope separately.',
          status: 'pass',
        },
        {
          label: 'Audit recorded',
          detail: 'Each approval is logged without forcing a second identity review.',
          status: 'pass',
        },
      ],
      eventLog: [
        'Issuer signs the workforce badge once.',
        'Lobby kiosk verifies status and access zone.',
        'Internal portal reuses the same proof with its own policy.',
      ],
      outcome: 'One governed credential supports multiple checkpoints.',
      proof: 'Reusable credential, separate verifier policies.',
      slug: 'deploy-enterprise-access',
      cta: 'Read the enterprise guide',
    },
    {
      id: 'airline-boarding',
      label: 'Airline boarding',
      title: 'Travel boarding check',
      channel: 'Gate lane',
      summary: 'The lane verifies document authenticity and boarding entitlement under real throughput pressure.',
      requestPath: 'POST /flows/verify',
      requestSummary: 'Check document authenticity, journey entitlement, and clearance status for the active flight.',
      holderSummary: 'The traveler reuses a previously issued travel proof instead of re-enrolling at every checkpoint.',
      disclosed: ['document_authentic', 'journey_entitlement', 'clearance_status'],
      verifierChecks: [
        {
          label: 'ICAO or ISO trust',
          detail: 'The verifier checks the configured travel trust source for the lane.',
          status: 'pass',
        },
        {
          label: 'Offline-ready runtime',
          detail: 'The deployment profile keeps the lane moving during unstable connectivity.',
          status: 'pass',
        },
        {
          label: 'Gate policy satisfied',
          detail: 'The current boarding context still matches the issued journey entitlement.',
          status: 'pass',
        },
      ],
      eventLog: [
        'Pre-clearance issues the reusable travel proof.',
        'Gate verifier validates trust and freshness locally.',
        'Boarding continues with a clear allow or deny result.',
      ],
      outcome: 'Throughput stays high without weakening the assurance model.',
      proof: 'Travel constraints become policy and runtime settings, not bespoke code.',
      slug: 'deploy-airline-boarding',
      cta: 'Read the travel guide',
    },
  ],
};

export const DEPLOYMENT_PLAYBOOKS = {
  title: 'Start from a deployment playbook.',
  subtitle: 'Use real scenario guides already in the site to connect standards language to rollout constraints and operating conditions.',
  items: [
    {
      slug: 'deploy-age-verification',
      title: 'Age Verification in Retail',
      badge: 'Retail privacy',
      proof: 'A verifier can ask one bounded question and still satisfy regulated compliance checks.',
      signals: ['Selective disclosure', 'Minimal data', 'Retail checkout'],
      cta: 'Read the retail guide',
    },
    {
      slug: 'deploy-enterprise-access',
      title: 'Deploying Marty for Enterprise Access',
      badge: 'Employee access',
      proof: 'The same credential can support doors, gateways, and internal applications without copying policy logic everywhere.',
      signals: ['Policy reuse', 'Step-up checks', 'Local enforcement'],
      cta: 'Read the enterprise guide',
    },
    {
      slug: 'deploy-airline-boarding',
      title: 'Deploying Marty for Airline Boarding',
      badge: 'Travel throughput',
      proof: 'High-throughput lanes can keep trust, latency, and offline resilience aligned in one deployment profile.',
      signals: ['ICAO 9303', 'Offline runtime', 'Gate operations'],
      cta: 'Read the travel guide',
    },
    {
      slug: 'deploy-membership-credentials',
      title: 'Membership Credentials',
      badge: 'Ecosystem trust',
      proof: 'Portable credentials only matter when partner trust travels with them instead of falling back to issuer phone-home checks.',
      signals: ['Trust registry', 'Partner verification', 'Portable membership'],
      cta: 'Read the ecosystem guide',
    },
  ],
};

export const DEPLOYMENT_MODELS = {
  title: 'How ElevenID Deploys',
  subtitle: 'ElevenID runs where your identity infrastructure needs to operate-from cloud APIs to offline checkpoints.',
  questions: [
    {
      question: 'Where does this run?',
      answer: 'Across managed APIs, private infrastructure, and checkpoint runtimes with the same trust model and policy surfaces.',
    },
    {
      question: 'What infrastructure do I need?',
      answer: 'Choose SaaS verification, self-hosted services, or edge runtimes based on data-sovereignty, latency, and connectivity requirements.',
    },
    {
      question: 'How does this integrate with my systems?',
      answer: 'Issuer workflows, wallets, kiosks, and relying applications connect through standards-based issuance, verification, and trust-registry interfaces.',
    },
  ],
  modes: [
    {
      id: 'saas-verification',
      badge: 'Hosted runtime',
      title: 'SaaS Verification',
      summary: 'Hosted verification infrastructure for rapid deployment.',
      path: '/product#verification-api',
      cta: 'Open Verification API',
      features: [
        'managed verification API',
        'automatic trust registry updates',
        'high-availability runtime',
      ],
      bestFor: ['startups', 'enterprise pilots', 'API integrations'],
    },
    {
      id: 'self-hosted-infrastructure',
      badge: 'Private environment',
      title: 'Self-Hosted Infrastructure',
      summary: 'Run the verification platform in your own environment.',
      path: '/product#issuance-api',
      cta: 'Review Self-Hosted Issuance',
      features: [
        'full data sovereignty',
        'internal network verification',
        'custom trust policies',
      ],
      bestFor: ['governments', 'regulated industries', 'internal enterprise deployments'],
    },
    {
      id: 'offline-checkpoint-runtime',
      badge: 'Edge verification',
      title: 'Offline Checkpoint Runtime',
      summary: 'Edge verification for locations with unreliable connectivity.',
      path: '/product#kiosk',
      cta: 'See Offline Kiosk Runtime',
      features: [
        '72-hour offline trust cache',
        'QR / NFC / BLE credential exchange',
        'kiosk and facility integration',
      ],
      bestFor: ['airports', 'stadiums', 'building entry systems'],
    },
  ],
  example: {
    title: 'Example: Airport Boarding Gate',
    flow: ['Passenger Wallet', 'Gate Kiosk', 'ElevenID Verifier', 'Trust Registry'],
    summary: 'Verification happens in under one second, even if the network drops.',
  },
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

// Open Protocol (MIP) content
export const PROTOCOL = {
  name: 'Marty Identity Protocol',
  abbreviation: 'MIP',
  version: '0.1.0',
  status: 'Draft',
  license: 'Apache 2.0',
  githubUrl: 'https://github.com/mip-protocol/marty-protocol',
  tagline: 'An open, vendor-neutral specification for cryptographically verifiable digital identity management.',
  description: 'MIP defines the minimum automatable set of primitives required for issuing, holding, presenting, and verifying digital credentials under explicit rules of trust and disclosure.',
  thesis: 'Digital identity management can be represented by Trust Profiles + Credential Templates + Presentation Policies + Deployment Profiles, orchestrated by Flows.',
  primitives: [
    {
      name: 'Trust Profile',
      purpose: 'Who is trusted and how cryptographic validation happens',
      icon: 'VerifiedUser',
    },
    {
      name: 'Credential Template',
      purpose: 'What is issued— schema, compliance, crypto, and validity rules',
      icon: 'Description',
    },
    {
      name: 'Presentation Policy',
      purpose: 'What must be shown— minimum disclosure and ZK predicates',
      icon: 'Policy',
    },
    {
      name: 'Deployment Profile',
      purpose: 'Where it runs— lanes, devices, network mode, and UX',
      icon: 'CloudUpload',
    },
    {
      name: 'Flow',
      purpose: 'How identity moves: apply → approve → issue → present → verify',
      icon: 'AccountTree',
    },
  ],
  standards: [
    { name: 'ISO 18013-5', coverage: 'mDoc format, proximity presentation' },
    { name: 'ICAO 9303 / DTC', coverage: 'Travel document trust, CSCA/DS PKI' },
    { name: 'OpenID4VCI', coverage: 'Issuance protocol (pre-auth + auth code flows)' },
    { name: 'OpenID4VP', coverage: 'Presentation protocol' },
    { name: 'W3C Verifiable Credentials', coverage: 'VC-JWT, JSON-LD' },
    { name: 'SD-JWT-VC', coverage: 'Selective disclosure' },
    { name: 'W3C DID Core', coverage: 'Decentralized identifier resolution' },
    { name: 'EUDI Wallet ARF', coverage: 'EU regulatory alignment' },
    { name: 'AAMVA mDL', coverage: 'North American driver\'s license' },
  ],
  governance: {
    model: 'Vendor-neutral, community-governed',
    contributions: 'Developer Certificate of Origin (DCO)',
    decisions: 'All decisions made publicly on GitHub',
    copyright: 'The MIP Authors',
  },
  components: [
    { name: 'Specification', description: 'Formal definition of all primitives and their relationships' },
    { name: 'JSON Schemas', description: '35 schemas for all protocol entities' },
    { name: 'Cedar Policies', description: 'Deny-by-default authorization using AWS Cedar' },
    { name: 'Compliance Profiles', description: 'ICAO, AAMVA, EUDI, enterprise, and Open Badge mappings' },
    { name: 'Reference Implementations', description: 'Rust, Python, and TypeScript type libraries' },
    { name: 'Conformance Suite', description: 'Validation test fixtures for implementers' },
  ],
};

// AI research personas — domain experts representing curated protocol analysis

// ── Blog content ─────────────────────────────────────────────────────────────
// Moved to @marty/blog. Re-exported here for backward compatibility during migration.
export { BLOG_AUTHORS, BLOG_POSTS, BLOG_ROADMAP, AUTHOR_AVATAR_PROMPTS } from '@marty/blog';

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
    'Built with AI-assisted development workflows to maintain high quality at lower cost.',
  ],
  compliance: [
    'Implements ICAO 9303',
    'Implements ISO 18013-5 (mDoc)',
    'GDPR and privacy by design',
    'Selective disclosure and data minimization',
  ],
};

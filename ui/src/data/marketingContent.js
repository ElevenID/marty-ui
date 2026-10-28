/**
 * Marketing Content
 * 
 * Centralized content for marketing pages to ensure consistency
 * across Product, Standards, and Identity Guide pages
 */

// Core value proposition
export const VALUE_PROPOSITION = {
  headline: 'Marty: identity workflows you operate.',
  supportingSubheadline: 'One product for portable credentials, applicant and document verification, and Travel Trust.',
  subheadline: 'Build trust around your workflow.',
  extendedSubheadline: 'Choose a defined use case, evaluate it with synthetic data, and run the agreed deployment yourself or with your chosen partner.',
  primaryCTA: 'Explore the Developer Docs',
  secondaryCTA: { label: 'View Verification API', path: '/verifiable-credential-api' },
  concreteExample: 'For example, an organization can issue a workforce credential and evaluate how another verifier checks the issuer, the claims, and its own access policy.',
};

// IDV vs ElevenID LLC comparison
export const IDV_COMPARISON = {
  "title": "Plan the Trust Exchange",
  "takeaway": "Start with the questions your workflow must answer, then evaluate the selected implementation.",
  "traditional": [
    {
      "label": "Which claim must be checked?",
      "category": "Questions to Resolve"
    },
    {
      "label": "Who operates the data and keys?",
      "category": "Questions to Resolve"
    },
    {
      "label": "How is the presenter bound to the credential?",
      "category": "Questions to Resolve"
    },
    {
      "label": "Which interfaces and profiles are required?",
      "category": "Questions to Resolve"
    },
    {
      "label": "Which issuers and rules are trusted?",
      "category": "Questions to Resolve"
    },
    {
      "label": "When can a credential be reused?",
      "category": "Questions to Resolve"
    }
  ],
  "elevenid": [
    {
      "label": "Defined credential and document inputs",
      "category": "Marty Evaluation"
    },
    {
      "label": "Customer or selected-partner operations",
      "category": "Marty Evaluation"
    },
    {
      "label": "Profile-specific holder-binding tests",
      "category": "Marty Evaluation"
    },
    {
      "label": "Documented interfaces and tested combinations",
      "category": "Marty Evaluation"
    },
    {
      "label": "Explicit issuer trust and policy configuration",
      "category": "Marty Evaluation"
    },
    {
      "label": "Reuse evaluated within an agreed workflow",
      "category": "Marty Evaluation"
    }
  ]
};

// EUDI & Open Badges strategic positioning
export const EUDI_OPEN_BADGES = {
  title: 'Explore Wallet and Credential Interoperability',
  points: [
    'Define the credential format and presentation profile you need.',
    'Identify trusted issuers and acceptance rules.',
    'Test the chosen wallets and release together.',
  ],
  quote: 'A named standard is a starting point for interoperability testing. Availability and conformance depend on the exact release, profile, and participating systems.',
};

// Why this matters for organizations
export const ORGANIZATION_OUTCOMES = {
  title: 'What You Can Evaluate',
  outcomes: [
    { text: 'Explore credential reuse across an agreed workflow', bold: 'reuse', metric: 'Portable credentials' },
    { text: 'Make applicant and document checks explicit', bold: 'review', metric: 'Defined verification scope' },
    { text: 'Evaluate travel-document trust and journey rules', bold: 'trust', metric: 'Travel Trust' },
    { text: 'Keep production operations with your team or chosen partner', bold: 'control', metric: 'Customer-operated' },
  ],
};

// Audience routing - helps different buyer personas find their path
export const AUDIENCE_ROUTING = {
  title: 'Choose Your Path',
  subtitle: 'Explore Marty directly or through a partner or OEM integration.',
  paths: [
    { id: 'enterprise', title: 'Enterprise', description: 'Define a useful credential or document workflow and the team that will operate it.', benefit: 'Start with a bounded use case', cta: 'Explore Solutions', path: '/solutions', color: 'primary', icon: 'Business' },
    { id: 'government', title: 'Government', description: 'Review trust sources, required credential profiles, and deployment constraints.', benefit: 'Validate the exact profile', cta: 'View Architecture', path: '/architecture', color: 'secondary', icon: 'AccountBalance' },
    { id: 'developers', title: 'Developers and Partners', description: 'Inspect APIs, source, and integration requirements for the selected workflow.', benefit: 'Build against documented interfaces', cta: 'Read Developer Docs', path: '/developers', color: 'info', icon: 'Code' },
  ],
};

// Substantiated proof claims - only include claims we can defend
export const PROOF_STRIP = {
  title: 'A Defined Product and Operating Model',
  claims: [
    { label: 'One Marty product, three use cases', category: 'Scope' },
    { label: 'Synthetic evaluation first', category: 'Evaluation' },
    { label: 'Customer or partner operated', category: 'Operations' },
    { label: 'Explicit trust and key configuration', category: 'Security' },
    { label: 'Release-specific evidence', category: 'Evidence' },
  ],
};

export const ECOSYSTEM_SIGNALS = {
  title: 'Connect the workflow to its requirements',
  categories: [
    { label: 'Portable credentials', items: ['Issuer trust', 'Credential profiles', 'Wallet compatibility'] },
    { label: 'Applicant and document verification', items: ['Document inputs', 'Review rules', 'Recorded decisions'] },
    { label: 'Travel Trust', items: ['Travel-document trust', 'Journey policy', 'Deployment evidence'] },
  ],
};

export const HERO_INTERACTIVE_DEMO = {
  eyebrow: 'Illustrative credential journey',
  title: 'Explore how credential reuse works.',
  description: 'A synthetic example of issuance, presentation, and reuse. The illustrated result is not production or interoperability evidence.',
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
  title: 'Explore the holder experience',
  subtitle: 'Illustrative journeys show the questions a holder and verifier need to answer. Validate the chosen wallet, profile, and workflow before use.',
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
      verifierView: 'The example verifier evaluates the requested claim against its policy and trust requirements.',
      disclosed: ['age_over_21', 'issuer_trust'],
      verifierChecks: ['Policy evaluated', 'Issuer trusted', 'Expiry and revocation checked'],
      benefits: ['Bounded disclosure', 'Explicit review criteria'],
      outcome: 'A design example for evaluating minimal disclosure against the responsible organization’s acceptance requirements.',
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
  description: 'Use the VC-API endpoint with an authorized organization, a presentation policy, and a signed credential. Move to wallet and QR flows when the holder needs to present interactively.',
  snippet: `curl -X POST "$ELEVENID_API_BASE/v1/vc-api/credentials/verify?organization_id=$ELEVENID_ORGANIZATION_ID&presentation_policy_id=$ELEVENID_PRESENTATION_POLICY_ID" \\
  -H "Authorization: Bearer $ELEVENID_API_KEY" \\
  -H "Content-Type: application/json" \\
  -d '{
    "verifiableCredential": "<compact signed VC JWT>"
  }'`,
  response: `{
  "verified": true,
  "results": { "decision": "allow" }
}`,
  bullets: [
    'POST /v1/vc-api/credentials/verify with a signed credential for policy evaluation.',
    'Select organization_id and presentation_policy_id in the query string.',
    'Use /flows/verify when the user needs a wallet, QR, or kiosk presentation step.',
  ],
  note: 'Run against your authorized, configured environment with synthetic test credentials first. The response shown is illustrative.',
};

export const INTERACTIVE_PROOF_LAB = {
  eyebrow: 'Synthetic proof lab',
  title: 'Try a synthetic verification example.',
  subtitle: 'Inspect example requests and predetermined results. This browser demonstration does not execute a production verification service.',
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
      requestPath: 'POST /v1/vc-api/credentials/verify',
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
          label: 'Connectivity requirement',
          detail: 'This synthetic example assumes a defined freshness policy; actual offline behavior needs separate testing.',
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
      outcome: 'The example illustrates a decision; it does not measure throughput or production assurance.',
      proof: 'Travel constraints become policy and runtime settings, not bespoke code.',
      slug: 'deploy-airline-boarding',
      cta: 'Read the travel guide',
    },
  ],
};

export const DEPLOYMENT_PLAYBOOKS = {
  title: 'Explore a scenario guide.',
  subtitle: 'Use these design examples to discuss requirements. A guide is not evidence that its workflow is available or approved for production.',
  items: [
    {
      slug: 'deploy-age-verification',
      title: 'Age Verification in Retail',
      badge: 'Retail privacy',
      proof: 'Explore how a verifier could request a bounded age claim, then confirm the applicable acceptance requirements.',
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
      proof: 'Identify the trust, latency, and connectivity requirements a travel deployment would need to demonstrate.',
      signals: ['Travel-document trust', 'Connectivity tests', 'Gate operations'],
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
  title: 'How You Operate Marty',
  subtitle: 'Production runs with your organization or a partner you select. Agree the workflow, release, and operating responsibilities before deployment.',
  questions: [
    { question: 'Who runs production?', answer: 'Your organization or your chosen partner owns hosting, keys, access, backups, monitoring, and day-to-day operations.' },
    { question: 'What infrastructure do I need?', answer: 'Review the requirements for the selected release. The current installer path targets Linux amd64 with local rootful Docker and Compose; other profiles need their own validation.' },
    { question: 'How do we start?', answer: 'Review a relevant demonstration, define the scope, and evaluate with synthetic data. Real data and production each need their own approval.' },
  ],
  modes: [
    { id: 'customer-operated', badge: 'Your operations team', title: 'Customer-Operated Deployment', summary: 'Run the agreed Marty scope in an environment your team controls.', path: '/product#verification-api', cta: 'Review Verification Scope', features: ['Named workflows and release', 'Customer-managed keys and access', 'Documented operating responsibilities'], bestFor: ['internal platforms', 'API integrations', 'customer-run evaluations'] },
    { id: 'partner-operated', badge: 'Your selected partner', title: 'Partner or OEM Integration', summary: 'Work with your own delivery or platform partner under separately agreed responsibilities.', path: '/product#issuance-api', cta: 'Review Integration Components', features: ['Direct and partner channels', 'Defined integration boundaries', 'Separately scoped custom work'], bestFor: ['platform partners', 'integrators', 'OEM teams'] },
    { id: 'offline-evaluation', badge: 'Profile evaluation', title: 'Offline and Headless Evaluation', summary: 'Evaluate constrained-connectivity or API-only needs against the exact implementation and release.', path: '/product#kiosk', cta: 'Review Checkpoint Scope', features: ['Test freshness and failure behavior', 'Qualify each device and transport', 'Confirm source and installer availability'], bestFor: ['checkpoint research', 'restricted networks', 'API-only integration'] },
  ],
  example: {
    title: 'Example: Travel Trust Evaluation',
    flow: ['Synthetic travel input', 'Customer-run verifier', 'Configured trust policy', 'Recorded result'],
    summary: 'Test document trust, policy decisions, and failure cases in your environment before discussing a production lane.',
  },
};

// Products (from product-catalog)
export const PRODUCTS = [
  {
    id: 'verification-api', name: 'Verification API',
    tagline: 'A Marty component for credential and document checks.',
    description: 'Connect signed credential or document inputs to explicit trust and verification policies. Confirm supported formats, endpoints, and trust sources for the selected release.',
    deployment: ['Customer-operated'],
    capabilities: ['Credential and document verification workflows', 'Explicit issuer and trust configuration', 'Policy decisions and recorded results', 'Release-specific API scope'],
    standards: ['Profile-specific formats', 'Documented API contracts'],
    pricing: 'Included only as defined in the agreed Marty scope; annual software licensing is the default direction.',
    useCase: 'Portable credentials, applicant/document verification, and Travel Trust',
    replacesExtends: 'Connect verification to the acceptance rules your organization owns.',
    useWhen: 'Start when a credential or document check is part of your workflow.',
  },
  {
    id: 'issuance-api', name: 'Issuance API',
    tagline: 'A Marty component for issuing defined credentials.',
    description: 'Configure a credential template, issuer, and lifecycle for the chosen workflow. Validate the specific format and recipient wallet before use.',
    deployment: ['Customer-operated'],
    capabilities: ['Credential templates', 'Issuer and signing-key configuration', 'Documented issuance interfaces', 'Lifecycle rules for the selected scope'],
    standards: ['Profile-specific issuance', 'Tested wallet combinations'],
    pricing: 'Part of the agreed Marty scope, with applicable component rights preserved.',
    useCase: 'Workforce, education, membership, and other defined credential programs',
    replacesExtends: 'Give a defined claim a reusable credential representation.',
    useWhen: 'Use when your organization is authorized to issue the credential.',
  },
  {
    id: 'kiosk', name: 'Checkpoint Components',
    tagline: 'Evaluate the endpoint your workflow needs.',
    description: 'Checkpoint and constrained-connectivity scenarios need device, transport, trust freshness, and failure-behavior testing. Availability is specific to the selected release and configuration.',
    deployment: ['Profile evaluation'],
    capabilities: ['Endpoint and device requirements', 'Connectivity and freshness policy', 'Negative-case testing', 'Operator and integration responsibilities'],
    standards: ['Device-specific transport', 'Profile-specific verification'],
    pricing: 'Scope and third-party hardware costs are agreed separately; no per-device offer is implied.',
    useCase: 'Travel Trust, facilities, and other checkpoint evaluations',
    replacesExtends: 'Bring the same defined trust questions to a specific physical endpoint.',
    useWhen: 'Review when the operating environment has device or connectivity constraints.',
  },
  {
    id: 'authenticator', name: 'Authenticator',
    tagline: 'A holder-facing component to evaluate with your workflow.',
    description: 'Review credential storage and presentation behavior for the exact wallet build, platform, and verifier profile. Device security and interoperability require their own evidence.',
    deployment: ['Build-specific platforms'],
    capabilities: ['Credential storage and presentation workflows', 'Wallet and verifier compatibility testing', 'Holder experience evaluation'],
    standards: ['Build-specific wallet profiles'],
    pricing: 'Existing component and community license terms apply; commercial rights are reviewed for the agreed distribution.',
    useCase: 'Credential holders in a defined portable-credential workflow',
    replacesExtends: 'Let the holder participate in the credential exchange.',
    useWhen: 'Use when the chosen workflow requires a holder wallet.',
  },
];

// Standards information
export const STANDARDS_INFO = {
  whyStandardsMatter: {
    title: 'Why Standards Matter',
    points: [
      {
        title: 'Portability',
        description: 'Common formats create a basis for testing compatibility between selected systems',
      },
      {
        title: 'Trust',
        description: 'Cryptographic proof follows established protocols',
      },
      {
        title: 'Longevity',
        description: 'Versioned specifications make dependencies and migration needs explicit',
      },
      {
        title: 'Interoperability',
        description: 'Interoperability is demonstrated with specific profiles and participants',
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
        detail: 'Evaluate the holder-binding mechanism required by the selected credential and presentation profile',
      },
      {
        question: 'Appropriateness',
        description: 'Is the disclosed information sufficient—and no more than necessary?',
        detail: 'Request only the claims needed, using disclosure mechanisms supported by the selected profile',
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
  title: 'Start with a Useful Workflow',
  points: [
    'Agree the inputs, trust sources, and expected result',
    'Evaluate with synthetic data before real records',
    'Keep production ownership explicit',
    'Expand scope when evidence supports it',
  ],
};

// Standards as strategic advantage
export const STANDARDS_STRATEGIC = {
  header: 'Standards guide the design. Tests establish compatibility.',
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
  version: '0.5.0',
  status: 'Draft',
  license: 'Apache 2.0',
  githubUrl: 'https://github.com/Marty-Protocol/Marty-Protocol',
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
      purpose: 'What must be shown— claims and disclosure requirements',
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
    { name: 'ICAO 9303 / DTC', coverage: 'Draft travel-document mappings; no active conformance claim' },
    { name: 'OpenID4VCI', coverage: 'Issuance protocol (pre-auth + auth code flows)' },
    { name: 'OpenID4VP', coverage: 'Presentation protocol' },
    { name: 'W3C Verifiable Credentials', coverage: 'VC-JWT, JSON-LD' },
    { name: 'SD-JWT-VC', coverage: 'Selective disclosure' },
    { name: 'W3C DID Core', coverage: 'Decentralized identifier resolution' },
    { name: 'EUDI Wallet ARF', coverage: 'Profile mapping to review; not regulatory approval' },
    { name: 'AAMVA mDL', coverage: 'Mobile-license profile references to evaluate' },
  ],
  governance: {
    model: 'Vendor-neutral, community-governed',
    contributions: 'Developer Certificate of Origin (DCO)',
    decisions: 'All decisions made publicly on GitHub',
    copyright: 'The MIP Authors',
  },
  components: [
    { name: 'Specification', description: 'Formal definition of all primitives and their relationships' },
    { name: 'JSON Schemas', description: 'Versioned schemas for protocol entities' },
    { name: 'Cedar Policies', description: 'Deny-by-default authorization using AWS Cedar' },
    { name: 'Profile Mappings', description: 'Draft mappings whose scope and status must be reviewed separately' },
    { name: 'Reference Implementations', description: 'Rust, Python, and TypeScript type libraries' },
    { name: 'Conformance Suite', description: 'Validation test fixtures for implementers' },
  ],
};

// AI research personas — domain experts representing curated protocol analysis

// ── Blog content ─────────────────────────────────────────────────────────────
// Moved to @elevenid/marty-blog. Re-exported here for backward compatibility during migration.
export { BLOG_AUTHORS, BLOG_POSTS, BLOG_ROADMAP, AUTHOR_AVATAR_PROMPTS } from '@elevenid/marty-blog';

// Trust and infrastructure messaging
export const TRUST_SIGNALS = {
  security: ['Configure trusted issuers and keys explicitly', 'Test signature, expiry, and failure handling', 'Review key storage for the selected deployment'],
  infrastructure: ['Customer or selected-partner operations', 'Release-specific installation requirements', 'Offline and headless profiles need validation', 'No included managed production or uptime SLA', 'Issue and vulnerability reporting through documented channels'],
  compliance: ['Define the required standard and profile', 'Review evidence for the exact release', 'Approve real-data handling separately', 'Confirm acceptance requirements with the responsible organization'],
};

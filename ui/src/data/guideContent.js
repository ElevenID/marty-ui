/**
 * Protocol Guide Content
 *
 * Structured learning curriculum for the Marty Identity Protocol.
 * Six chapters, 22 guide articles, ordered for progressive learning.
 */

export const GUIDE_CHAPTERS = [
  { id: 1, slug: 'foundations', title: 'Foundations', color: '#1565c0', icon: 'School' },
  { id: 2, slug: 'core-objects', title: 'Core Objects', color: '#7b1fa2', icon: 'Category' },
  { id: 3, slug: 'trust-governance', title: 'Trust & Governance', color: '#2e7d32', icon: 'Security' },
  { id: 4, slug: 'flows', title: 'Flows', color: '#e65100', icon: 'AccountTree' },
  { id: 5, slug: 'deployments', title: 'Deployments', color: '#00695c', icon: 'CloudUpload' },
  { id: 6, slug: 'implementations', title: 'Implementations', color: '#c62828', icon: 'Code' },
];

export const GUIDE_ARTICLES = [
  // ──────────── Chapter 1: Foundations ──────────────────────────────────────

  {
    slug: 'foundations-identity',
    chapterId: 1,
    order: 1,
    title: 'What is Digital Identity?',
    summary:
      'Identity is the set of machine-readable claims about an entity — cryptographically signed, holder-controlled, and verifiable without calling home.',
    readTime: '6 min read',
    conceptTags: ['foundation', 'identity'],
    content: [
      {
        type: 'paragraph',
        text: 'Digital identity is the set of machine-readable claims that describe an entity: a person, an organization, a device, or even a software service. In the physical world, identity is carried in passports, driver\'s licences, and employee badges. Digital identity solves the same problem — but without the physical document, and without requiring the issuer to be online every time you use it.',
      },
      { type: 'heading', text: 'The Three Parties' },
      {
        type: 'paragraph',
        text: 'Every identity interaction involves three roles. An Issuer (a government, employer, or institution) creates and cryptographically signs a credential. A Holder (a person or organization) stores it in a wallet they control. A Verifier (an airport gate, a website, or an API) checks it to make an access decision. These three parties form the "trust triangle" that underpins all verifiable credential systems.',
      },
      { type: 'heading', text: 'What Makes It Verifiable?' },
      {
        type: 'paragraph',
        text: 'Verifiable means two things: the credential was signed by a trusted issuer, and it was not modified after signing. This is achieved with public-key cryptography. The issuer signs the credential with their private key; the verifier checks the signature using the issuer\'s public key, which they obtained from a trust registry or well-known endpoint. No phone-home required.',
      },
      { type: 'heading', text: 'Why the Old Model Fails' },
      {
        type: 'paragraph',
        text: 'Traditional identity verification calls the issuer every time: "Did you issue this?" This creates a privacy problem (the issuer learns every time the credential is used), a latency problem (requires connectivity), and a lock-in problem (you can only trust credentials from services you have a direct API relationship with). Verifiable credentials eliminate all three by embedding the proof inside the credential.',
      },
      {
        type: 'code',
        label: 'A simple identity claim in JSON-LD',
        lang: 'json',
        code: `{
  "@context": ["https://www.w3.org/2018/credentials/v1"],
  "type": ["VerifiableCredential", "IdentityCredential"],
  "issuer": "did:web:gov.example.com",
  "issuanceDate": "2025-01-15T00:00:00Z",
  "credentialSubject": {
    "id": "did:key:z6Mkk...",
    "given_name": "Jane",
    "family_name": "Doe",
    "age_over_21": true
  },
  "proof": {
    "type": "JsonWebSignature2020",
    "jws": "eyJhbGciOiJFZERTQS..."
  }
}`,
      },
    ],
  },

  {
    slug: 'foundations-credentials',
    chapterId: 1,
    order: 2,
    title: 'What is a Verifiable Credential?',
    summary:
      'A Verifiable Credential is a cryptographically signed, holder-controlled document that proves something about its subject — without requiring the issuer to be online.',
    readTime: '7 min read',
    conceptTags: ['foundation', 'credential'],
    content: [
      {
        type: 'paragraph',
        text: 'A Verifiable Credential (VC) is a structured document that encodes claims about a subject, signed by the issuer using a cryptographic key. The W3C Verifiable Credentials Data Model defines the standard format: a credential has an issuer, a subject, a set of claims, validity dates, and a proof. The proof is what makes it verifiable.',
      },
      { type: 'heading', text: 'Core Components' },
      {
        type: 'paragraph',
        text: 'The issuer DID (Decentralized Identifier) identifies who signed the credential. The credentialSubject block contains the claims being asserted. The proof block contains the cryptographic signature. Validity is bounded by issuanceDate and expirationDate. Optional status information points to a revocation mechanism.',
      },
      { type: 'heading', text: 'Three Major Formats' },
      {
        type: 'paragraph',
        text: 'W3C VC is JSON-LD with JSON Web Signatures (JWS) or Data Integrity proofs — the most widely implemented format on the web. SD-JWT (Selective Disclosure JWT) is a compact format that lets the holder choose which individual claims to reveal. ISO mDoc (used in driver\'s licences and passports) is a CBOR-encoded format with device binding and proximity support.',
      },
      {
        type: 'code',
        label: 'SD-JWT structure — hash-per-claim enables selective disclosure',
        lang: 'json',
        code: `{
  // JWT payload after selective disclosure
  "iss": "https://issuer.example.com",
  "iat": 1737000000,
  "exp": 1768536000,
  "cnf": { "jwk": { "kty": "EC", "crv": "P-256", "x": "...", "y": "..." } },
  "_sd": [
    "sha256:WyJlbHVWNU9...", // given_name
    "sha256:WyJRZ19PNjR...", // family_name
    "sha256:WyJhMWI2Yy4..."  // birth_date
  ],
  "_sd_alg": "sha-256"
  // employment_status always disclosed (not in _sd):
  "employment_status": "active"
}`,
      },
      { type: 'heading', text: 'Holder Binding' },
      {
        type: 'paragraph',
        text: 'A credential without holder binding can be copied and misused by anyone who obtains it. Holder binding ties the credential to a specific key pair controlled by the holder. During presentation, the holder signs a nonce from the verifier with their private key, proving they possess the credential and are its rightful owner — not just someone who found a copy.',
      },
    ],
  },

  {
    slug: 'foundations-verification',
    chapterId: 1,
    order: 3,
    title: 'What is Verification?',
    summary:
      'Verification is the process of confirming a credential is valid, was issued by a trusted authority, and belongs to the presenter — without calling home to the issuer.',
    readTime: '6 min read',
    conceptTags: ['foundation', 'verification'],
    content: [
      {
        type: 'paragraph',
        text: 'Verification in the MIP model is a structured decision process. It does not mean "call the issuer to confirm." It means: check the cryptographic proof, check the trust chain, check revocation status, and evaluate the presentation against the Presentation Policy. All four checks can occur without the issuer being online.',
      },
      { type: 'heading', text: 'The Four Checks' },
      {
        type: 'paragraph',
        text: 'Every verification involves four checks: (1) Cryptographic validity — is the proof signature mathematically correct and has the credential been modified since signing? (2) Trust chain — is the issuer present in an accepted Trust Profile for this credential type? (3) Revocation — is this specific credential still valid, or has it been revoked? (4) Policy compliance — does the presentation satisfy all requirements in the active Presentation Policy?',
      },
      { type: 'heading', text: 'Online vs Offline' },
      {
        type: 'paragraph',
        text: 'Online verification performs all four checks in real time. Offline verification pre-caches trust anchors and revocation data (up to a configurable TTL, e.g. 72 hours) and performs the same four checks without network connectivity. MIP\'s Deployment Profiles configure which mode applies to each environment — and what happens when cached data becomes stale.',
      },
      {
        type: 'code',
        label: 'Verification result structure',
        lang: 'json',
        code: `{
  "valid": true,
  "policy": "employee-building-access-v1",
  "checks": {
    "signature": { "status": "PASS", "algorithm": "ES256" },
    "trust_chain": { "status": "PASS", "trust_profile": "internal-employee-trust-v1" },
    "revocation": { "status": "PASS", "strategy": "status_list", "freshness": "PT2M" },
    "policy": { "status": "PASS", "satisfied_requirements": ["employment_status", "department"] }
  },
  "disclosed_claims": {
    "employment_status": "active",
    "department": "Engineering"
  },
  "verified_at": "2025-09-15T14:23:00Z"
}`,
      },
    ],
  },

  {
    slug: 'centralized-vs-verifiable',
    chapterId: 1,
    order: 4,
    title: 'Centralized vs Verifiable Identity',
    summary:
      'Traditional IDV calls home on every check. Verifiable credentials embed the proof inside the credential — changing the architecture, the privacy model, and the business model.',
    readTime: '7 min read',
    conceptTags: ['foundation', 'identity'],
    content: [
      {
        type: 'paragraph',
        text: 'There are two fundamentally different ways to verify someone\'s identity digitally. The centralized model — used by every traditional IDV vendor — stores identity data in a central database and checks it by calling the issuer\'s API. The verifiable model — used by verifiable credentials — embeds a cryptographic proof inside the credential itself, so verification never requires contacting the issuer.',
      },
      { type: 'heading', text: 'The Centralized Model' },
      {
        type: 'paragraph',
        text: 'Traditional identity verification works like a phone call. The verifier receives a claim ("I am over 21") and calls the issuer\'s API to confirm it. This creates a privacy leak (the issuer learns every transaction), a single point of failure (if the API is down, verification fails), and vendor lock-in (you can only verify credentials from issuers you have a direct integration with). Every check is a billable API call.',
      },
      { type: 'heading', text: 'The Verifiable Model' },
      {
        type: 'paragraph',
        text: 'Verifiable credentials flip this model. The issuer signs the credential once, at issuance time. The holder stores it in their wallet. The verifier checks the signature, trust chain, and revocation status — all without contacting the issuer. The issuer never learns when or where the credential is used. The verifier doesn\'t need an API relationship with the issuer. The credential works offline.',
      },
      { type: 'heading', text: 'Wallet Ecosystems' },
      {
        type: 'paragraph',
        text: 'Digital wallets are the user-facing component of the verifiable model. Apple Wallet, Google Wallet, and EU Digital Identity Wallets store credentials issued by governments, employers, and institutions. The wallet holder controls which credentials to share, with whom, and which specific claims to disclose. This is the holder-controlled model — the person decides, not the platform.',
      },
      {
        type: 'code',
        label: 'Centralized vs Verifiable — architectural comparison',
        lang: 'text',
        code: `Centralized IDV:\n  Verifier → API call → Issuer DB → Response\n  • Issuer sees every verification\n  • Requires connectivity\n  • Per-check pricing\n\nVerifiable Credentials:\n  Issuer → signs credential → Holder wallet\n  Holder → presents proof → Verifier\n  Verifier → checks signature + trust locally\n  • Issuer blind to usage\n  • Works offline\n  • Infrastructure pricing`,
      },
    ],
  },

  // ──────────── Chapter 2: Core Objects ─────────────────────────────────────

  {
    slug: 'trust-profiles',
    chapterId: 2,
    order: 1,
    title: 'Trust Profiles',
    summary:
      'A Trust Profile is the first MIP primitive. It answers: who do you trust to issue credentials, how do you validate their signatures, and what algorithm agility rules apply?',
    readTime: '8 min read',
    conceptTags: ['core-object', 'trust-profile'],
    content: [
      {
        type: 'paragraph',
        text: 'A Trust Profile is a configuration object that defines who an organization trusts to issue credentials and how to validate their cryptographic proofs. Without a Trust Profile, a verifier has no basis for accepting any credential — it\'s the foundation of the entire trust model. Every verification decision begins by selecting the matching Trust Profile.',
      },
      { type: 'heading', text: 'What a Trust Profile Contains' },
      {
        type: 'paragraph',
        text: 'A Trust Profile names an issuer (by DID, X.509 subject, or URL), specifies accepted credential types and schemas, lists signature algorithms the verifier will accept, and configures the trust anchor: the root certificate, DID document, or trust list entry that establishes the chain of trust from the issuer back to a root you control.',
      },
      { type: 'heading', text: 'Algorithm Agnosticism' },
      {
        type: 'paragraph',
        text: 'Trust Profiles separate trust configuration from cryptographic implementation. Adding support for a new algorithm — including post-quantum algorithms like ML-DSA — requires a Trust Profile update, not an application code change. This is essential for long-lived systems that must evolve alongside cryptographic standards without rewriting business logic.',
      },
      {
        type: 'code',
        label: 'Trust Profile schema (simplified)',
        lang: 'json',
        code: `{
  "id": "gov-passport-v1",
  "name": "Government Passport Issuer Trust",
  "credential_types": ["ICAO_MRTD_LDS1"],
  "trust_anchor": {
    "type": "x509_chain",
    "root_cert": "MIIDQDCCAiiggAwIBAgI...",
    "validation_rules": {
      "require_ocsp": false,
      "max_path_length": 3,
      "check_crl": true
    }
  },
  "accepted_algorithms": ["ES256", "EdDSA"],
  "revocation_strategy": "crl",
  "compliance_profile": "icao-9303"
}`,
      },
      { type: 'heading', text: 'Multiple Trust Profiles in One Deployment' },
      {
        type: 'paragraph',
        text: 'A single verification service can hold dozens of Trust Profiles simultaneously — one for each issuer domain it accepts: government passports, corporate employee badges, university degrees. When a credential arrives, MIP selects the matching Trust Profile by credential type and issuer, then applies its specific rules. Compliance decisions live in data, not code.',
      },
    ],
  },

  {
    slug: 'credential-templates',
    chapterId: 2,
    order: 2,
    title: 'Credential Templates',
    summary:
      'Credential Templates define what gets issued: the schema, claims map, validity rules, and selective disclosure configuration that governs every credential type in your system.',
    readTime: '8 min read',
    conceptTags: ['core-object', 'credential-template'],
    content: [
      {
        type: 'paragraph',
        text: 'A Credential Template is the blueprint for a credential type. It says: what claims are included, how they\'re derived from the applicant\'s submitted data, how long the credential is valid, and which claims support selective disclosure. Every credential issued by a MIP deployment is produced from a Credential Template.',
      },
      { type: 'heading', text: 'Template Components' },
      {
        type: 'paragraph',
        text: 'Every template has a type identifier (matching the W3C VC type), a JSON Schema for the claims, a claims map showing how application fields become credential claims, a TTL (time-to-live) and re-issuance window, and selective disclosure configuration that declares which claims are always visible, which can be selectively revealed, and which support zero-knowledge predicates.',
      },
      {
        type: 'code',
        label: 'Credential Template (simplified)',
        lang: 'json',
        code: `{
  "id": "employee-badge-v2",
  "credential_type": "EmployeeBadgeCredential",
  "schema": "$ref:schemas/employee-badge.json",
  "claims_map": {
    "given_name": "application.first_name",
    "family_name": "application.last_name",
    "employee_id": "application.hr_id",
    "department": "application.team",
    "employment_status": "\"active\""
  },
  "validity": {
    "ttl": "P1Y",
    "reissue_window": "P30D"
  },
  "selective_disclosure": {
    "always_disclosed": ["employment_status"],
    "selectively_disclosed": ["department", "given_name", "family_name"],
    "zk_predicates": ["age_over_21"]
  }
}`,
      },
      { type: 'heading', text: 'Privacy by Design' },
      {
        type: 'paragraph',
        text: 'Credential Templates treat privacy as a design constraint, not an afterthought. By declaring which claims are always disclosed, which can be revealed selectively, and which support zero-knowledge predicates, the template author makes privacy decisions at design time — before a single credential is ever issued. This makes data minimization auditable and systematic.',
      },
    ],
  },

  {
    slug: 'presentation-policies',
    chapterId: 2,
    order: 3,
    title: 'Presentation Policies',
    summary:
      'Presentation Policies define what a verifier needs to see — and nothing more. They encode minimum disclosure requirements as machine-readable configuration, not hardcoded logic.',
    readTime: '7 min read',
    conceptTags: ['core-object', 'presentation-policy'],
    content: [
      {
        type: 'paragraph',
        text: 'A Presentation Policy describes what a verifier requires before granting access. It specifies which credential types are accepted, which claims must be disclosed, what logical predicates can substitute for direct claim disclosure, and which Trust Profiles are valid sources. The verifier evaluates an incoming Verifiable Presentation against this policy and returns a binary valid/invalid decision.',
      },
      { type: 'heading', text: 'The Minimum Disclosure Principle' },
      {
        type: 'paragraph',
        text: 'Presentation Policies should be designed around the question: "What is the least information we need to make this decision?" A policy for age-gating content needs "age >= 18." It does not need a birth date. A policy for building access needs employment status and department. It does not need a name. MIP Presentation Policies make these boundary decisions explicit and auditable.',
      },
      {
        type: 'code',
        label: 'Presentation Policy (simplified)',
        lang: 'json',
        code: `{
  "id": "building-access-engineering",
  "name": "Engineering Building Access",
  "requirements": [
    {
      "credential_type": "EmployeeBadgeCredential",
      "trust_profiles": ["internal-employee-trust-v1"],
      "required_claims": [],
      "required_predicates": [
        { "claim": "department", "op": "eq", "value": "Engineering" },
        { "claim": "employment_status", "op": "eq", "value": "active" }
      ]
    }
  ],
  "holder_binding": "required"
}`,
      },
      { type: 'heading', text: 'Policies Decouple Verification from Code' },
      {
        type: 'paragraph',
        text: 'When access requirements change — a new accreditation is added, a credential type is updated, or a policy is tightened — you update the Presentation Policy. The verification code that evaluates it does not change. This makes compliance evolution safe and makes each policy change visible as a data diff rather than a code diff.',
      },
    ],
  },

  {
    slug: 'deployment-profiles',
    chapterId: 2,
    order: 4,
    title: 'Deployment Profiles',
    summary:
      'Deployment Profiles are the fourth MIP primitive. They specify how verification runs in a real environment: online or offline, what cache TTLs apply, how trust updates are delivered.',
    readTime: '7 min read',
    conceptTags: ['core-object', 'deployment-profile'],
    content: [
      {
        type: 'paragraph',
        text: 'A Deployment Profile binds a set of Trust Profiles and Presentation Policies to a real operational environment. It says: this device at this location runs verification in online or offline mode, uses these cache TTLs for trust anchors and revocation data, and receives trust updates on this schedule. It is the operational envelope around the trust decisions.',
      },
      { type: 'heading', text: 'Online vs Offline' },
      {
        type: 'paragraph',
        text: 'Online deployments check revocation in real time and receive trust updates immediately. They handle high-assurance use cases where freshness matters. Offline deployments pre-cache everything and operate air-gapped for hours or days. Border control kiosks, maritime vessels, and field terminals use offline mode — but apply the same Trust Profiles and Presentation Policies as online deployments. Same trust logic, different operational envelope.',
      },
      {
        type: 'code',
        label: 'Deployment Profile (simplified)',
        lang: 'json',
        code: `{
  "id": "airport-gate-offline",
  "name": "Airport Gate Terminal",
  "mode": "offline",
  "trust_profiles": ["icao-passport-trust-v2", "aamva-mdl-trust-v1"],
  "presentation_policies": ["border-control-emrtd-v3"],
  "cache": {
    "trust_anchors_ttl": "P3D",
    "revocation_ttl": "PT72H",
    "grace_period": "PT1H"
  },
  "update_schedule": {
    "interval": "PT6H",
    "channel": "signed-bundle"
  },
  "fallback_on_no_connectivity": "use_cache"
}`,
      },
      { type: 'heading', text: 'One Protocol, Many Environments' },
      {
        type: 'paragraph',
        text: 'The same Trust Profiles and Presentation Policies power web portals, mobile apps, physical kiosks, and API integrations. What differs between these environments is their Deployment Profile. This is what MIP means by "deploy once, run anywhere" — the trust decisions are identical, only the operational constraints change.',
      },
    ],
  },

  // ──────────── Chapter 3: Trust & Governance ───────────────────────────────

  {
    slug: 'trust-anchors',
    chapterId: 3,
    order: 1,
    title: 'Cryptographic Trust Anchors',
    summary:
      'A trust anchor is the root of your trust chain. Understanding X.509 roots, CSCA certificates, and DID documents is essential to configuring Trust Profiles correctly.',
    readTime: '8 min read',
    conceptTags: ['governance', 'cryptography', 'trust-anchor'],
    content: [
      {
        type: 'paragraph',
        text: 'A trust anchor is the root of a certificate or key hierarchy that you decide to trust unconditionally. Everything else in your trust chain is trusted because it chains back to this anchor. Choosing and protecting your trust anchors is the most consequential security decision in any identity deployment.',
      },
      { type: 'heading', text: 'X.509 Certificate Chains' },
      {
        type: 'paragraph',
        text: 'The oldest and most widely deployed trust model uses X.509 certificate chains. For passports, ICAO defines a two-level hierarchy: CSCA (Country Signing Certificate Authority) at the root, and DS (Document Signer) certificates that sign individual passport chips. To trust a passport, you need the CSCA certificate from ICAO\'s PKD (Public Key Directory). MIP Trust Profiles with type "x509_chain" encapsulate this model.',
      },
      { type: 'heading', text: 'DID-Based Trust' },
      {
        type: 'paragraph',
        text: 'Decentralized Identifiers (DIDs) use a different root: a DID document published to a verifiable data registry — a blockchain, a DNS record via did:web, or a key reference via did:key. The trust anchor is the verification key listed in the DID document at the time of issuance. MIP Trust Profiles support did:web and did:key out of the box.',
      },
      { type: 'heading', text: 'EU Trust Lists' },
      {
        type: 'paragraph',
        text: 'The EUDI model introduces trust lists: signed XML documents that enumerate all authorized issuers by type. The European LOTL (List of Trusted Lists) is the root. MIP Trust Profiles with type "trust_list" periodically fetch, verify, and cache these lists. When the EU adds a new authorized wallet issuer, no code changes are needed — the trust list update propagates automatically.',
      },
      {
        type: 'code',
        label: 'Three trust anchor types in Trust Profile config',
        lang: 'json',
        code: `// X.509/CSCA (passport-style)
"trust_anchor": {
  "type": "x509_chain",
  "root_cert": "MIIDQDCCAiiggAwIBAgI...",
  "validation_rules": { "check_crl": true, "max_path_length": 3 }
}

// DID-based (W3C VC style)
"trust_anchor": {
  "type": "did_document",
  "issuer_did": "did:web:issuer.example.com",
  "verification_method": "#key-1"
}

// EU Trust List (EUDI style)
"trust_anchor": {
  "type": "trust_list",
  "list_url": "https://ec.europa.eu/lotl/eu-lotl.xml",
  "list_type": "EU_LOTL",
  "refresh_interval": "PT6H"
}`,
      },
    ],
  },

  {
    slug: 'pki-certificate-chains',
    chapterId: 3,
    order: 2,
    title: 'PKI & Certificate Chains',
    summary:
      'Public key infrastructure is the cryptographic backbone of verifiable credentials. Learn how certificate chains work and why they matter for real-world MIP deployments.',
    readTime: '7 min read',
    conceptTags: ['governance', 'cryptography', 'pki'],
    content: [
      {
        type: 'paragraph',
        text: 'Public Key Infrastructure (PKI) is the system of digital certificates, certificate authorities, and validation procedures that makes it possible to establish trust in public keys belonging to parties you have never met. Without PKI, there is no way to verify that a key presented as "the government\'s signing key" actually belongs to the government.',
      },
      { type: 'heading', text: 'How Certificate Chains Work' },
      {
        type: 'paragraph',
        text: 'A certificate chain is a sequence of certificates from a root CA down to the entity certificate. Each certificate in the chain is signed by the one above it. Validation walks the chain upward until it reaches a trusted root. This allows a single trusted root to bootstrap trust in thousands of signing keys without requiring direct knowledge of each one.',
      },
      { type: 'heading', text: 'Revocation in PKI' },
      {
        type: 'paragraph',
        text: 'Certificates and credentials can be revoked before they expire. For X.509 chains, revocation is signaled via CRLs (Certificate Revocation Lists, batch files of revoked serial numbers) or OCSP responses (real-time per-certificate status checks). MIP Trust Profiles specify which mechanism to apply and how fresh the data must be.',
      },
      { type: 'heading', text: 'Key Lifecycle and HSM Protection' },
      {
        type: 'paragraph',
        text: 'The private keys that sign credentials must be protected with hardware security modules (HSMs) or cloud KMS services (AWS KMS, GCP Cloud HSM, Azure Key Vault). MIP\'s signing architecture integrates with these services so that the signing key never leaves the hardware boundary. Key rotation schedules and signing audit logs are managed through the Deployment Profile configuration.',
      },
    ],
  },

  {
    slug: 'policy-engines',
    chapterId: 3,
    order: 3,
    title: 'Policy Engines with Cedar',
    summary:
      'MIP uses AWS Cedar for authorization decisions. Cedar policies are deny-by-default, human-readable, and designed to be auditable — not just by engineers, but by compliance teams.',
    readTime: '9 min read',
    conceptTags: ['governance', 'policy-engine', 'cedar'],
    content: [
      {
        type: 'paragraph',
        text: 'Cedar is an open-source policy language and evaluation engine originally designed at AWS. In MIP, Cedar governs every authorization decision: who can create Trust Profiles, who can approve credential applications, who can revoke credentials, and who can update Presentation Policies. The Cedar schema defines what entities and actions exist; policies define what is permitted.',
      },
      { type: 'heading', text: 'Deny by Default' },
      {
        type: 'paragraph',
        text: 'Cedar policies are deny-by-default. Unless an explicit permit policy matches an action, it is denied. This is the correct security posture for any authorization system — you enumerate what is allowed, not what is forbidden. Missing a deny doesn\'t create a vulnerability; missing a permit simply means the action cannot be performed.',
      },
      {
        type: 'code',
        label: 'Cedar policy examples',
        lang: 'cedar',
        code: `// Only organization admins can create Trust Profiles
permit(
  principal in Role::"org-admin",
  action == Action::"create",
  resource is TrustProfile
);

// No user can approve their own credential application
forbid(
  principal,
  action == Action::"approve",
  resource is Application
) when {
  resource.applicant == principal
};

// Reviewers can only approve applications in their department
permit(
  principal in Role::"reviewer",
  action == Action::"approve",
  resource is Application
) when {
  resource.department == principal.department
};`,
      },
      { type: 'heading', text: 'Audit-Friendly by Design' },
      {
        type: 'paragraph',
        text: 'Cedar policies are readable text, not code. A compliance auditor can read MIP\'s Cedar policies and understand exactly what each role is permitted to do, without needing to understand a programming language. When a policy changes, the diff is a readable text diff. This is a fundamental improvement over authorization logic scattered across application code, which requires a developer to explain every permission decision.',
      },
    ],
  },

  {
    slug: 'trust-registries',
    chapterId: 3,
    order: 4,
    title: 'Trust Registries',
    summary:
      'A trust registry is the authoritative list of who is permitted to issue which credentials. Learn how MIP models trust registries and integrates them with Trust Profiles.',
    readTime: '7 min read',
    conceptTags: ['governance', 'trust-registry'],
    content: [
      {
        type: 'paragraph',
        text: 'A trust registry answers a simple but critical question: is this issuer authorized to issue this type of credential? Without a trust registry, any party can claim to issue anything — the cryptographic proof tells you the credential wasn\'t tampered with, but not whether the issuer had the authority to create it. Trust registries provide the governance layer.',
      },
      { type: 'heading', text: 'Real-World Trust Registries' },
      {
        type: 'paragraph',
        text: 'ICAO\'s PKD (Public Key Directory) is a trust registry for passport issuers — it lists every country\'s CSCA root certificate. The European LOTL (List of Trusted Lists) governs EUDI wallet issuers across all EU member states. AAMVA maintains a registry of authorized mDL issuers in North America. Each of these is a different format, but all solve the same governance problem.',
      },
      { type: 'heading', text: 'Enterprise Trust Registries' },
      {
        type: 'paragraph',
        text: 'The same concept applies internally. An enterprise trust registry lists which HR systems are authorized to issue employee badge credentials, which IT systems can issue device attestations, and which learning platforms can issue training certifications. MIP models enterprise trust registries as Trust Profiles with explicitly enumerated issuers rather than a chain-of-trust root.',
      },
      { type: 'heading', text: 'Registry Integration in MIP' },
      {
        type: 'paragraph',
        text: 'MIP Trust Profiles reference external trust registries through their trust_anchor configuration. The registry data is fetched, verified, and cached according to the Deployment Profile\'s update schedule. If a credential\'s issuer is not present in the registry at the required assurance level, the credential fails the trust check — even if its cryptographic signature is mathematically valid.',
      },
    ],
  },

  {
    slug: 'privacy-data-minimization',
    chapterId: 3,
    order: 5,
    title: 'Privacy & Data Minimization',
    summary:
      'Privacy is a design constraint, not a feature flag. MIP\'s architecture enforces data minimization at every layer — from Credential Templates to Presentation Policies.',
    readTime: '7 min read',
    conceptTags: ['governance', 'selective-disclosure'],
    content: [
      {
        type: 'paragraph',
        text: 'Data minimization means collecting, processing, and disclosing only the minimum personal data necessary for a given purpose. In identity systems, this means a verifier checking your age should not learn your name, address, or birth date. A door access system confirming your employment status should not receive your salary or start date. MIP enforces this principle at every architectural layer.',
      },
      { type: 'heading', text: 'Privacy by Design in MIP' },
      {
        type: 'paragraph',
        text: 'Credential Templates declare which claims support selective disclosure and which support zero-knowledge predicates — at design time, before any credential is issued. Presentation Policies specify the minimum set of claims or predicates required — verifiers cannot ask for more than what the policy permits. Together, these two primitives create a formal, auditable data minimization boundary.',
      },
      { type: 'heading', text: 'Unlinkability' },
      {
        type: 'paragraph',
        text: 'Unlinkability means a verifier cannot correlate two presentations from the same holder unless the holder explicitly discloses identifying information. SD-JWT achieves this through per-disclosure salts. Zero-knowledge proofs achieve it by design — the verifier learns only whether a predicate is satisfied, not any value that could identify the holder across sessions.',
      },
      { type: 'heading', text: 'The Issuer Blind Spot' },
      {
        type: 'paragraph',
        text: 'In the verifiable credential model, the issuer does not learn when, where, or to whom a credential is presented. This is a fundamental privacy improvement over centralized IDV, where the issuer sees every verification event. MIP\'s architecture preserves this property — no telemetry, no callbacks, no usage analytics flow back to the issuer.',
      },
    ],
  },

  // ──────────── Chapter 4: Flows ────────────────────────────────────────────

  {
    slug: 'issuance-flows',
    chapterId: 4,
    order: 1,
    title: 'Issuance Flows',
    summary:
      'An issuance flow orchestrates the journey from credential application through approval to delivery. MIP\'s Flow primitive ties Trust Profile, Template, Policy, and Deployment together.',
    readTime: '8 min read',
    conceptTags: ['flow', 'issuance'],
    content: [
      {
        type: 'paragraph',
        text: 'Issuance is the process by which an issuer creates and delivers a signed credential to a holder. In MIP, this is orchestrated by a Flow — a configured sequence of states (Submitted → Under Review → Approved → Issued) that models the real-world credential application process. Flows are what users actually interact with; the four primitives are what Flows are built from.',
      },
      { type: 'heading', text: 'OID4VCI: The Standard Protocol' },
      {
        type: 'paragraph',
        text: 'Over-the-internet issuance uses OpenID for Verifiable Credential Issuance (OID4VCI). The issuer publishes a credential offer as a QR code or deep link. The holder\'s wallet initiates the authorization code or pre-authorized code flow. After authentication and approval, the wallet receives a signed credential in the holder\'s chosen format (SD-JWT-VC, mDoc, or W3C VC).',
      },
      {
        type: 'code',
        label: 'Credential offer structure (OID4VCI)',
        lang: 'json',
        code: `{
  "credential_issuer": "https://issuer.example.com",
  "credential_configuration_ids": ["EmployeeBadgeCredential"],
  "grants": {
    "authorization_code": {
      "issuer_state": "eyJhbGciOiJFZER...",
      "authorization_server": "https://auth.example.com"
    },
    "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
      "pre-authorized_code": "SplxlOBeZQQYbYS6WxSbIA",
      "tx_code": { "length": 6, "input_mode": "numeric" }
    }
  }
}`,
      },
      { type: 'heading', text: 'Flow States and Human Approval' },
      {
        type: 'paragraph',
        text: 'Complex credential types require human review before issuance. A professional licence credential might require a completed application, document uploads, and a reviewer\'s sign-off. MIP Flows model this with named states and transition rules. Cedar policies govern who can approve each state transition — so the same flow definition works for self-service issuance and human-reviewed issuance by simply changing the policy that guards the Approved transition.',
      },
    ],
  },

  {
    slug: 'presentation-flows',
    chapterId: 4,
    order: 2,
    title: 'Presentation Flows',
    summary:
      'Presentation is how a holder shares credentials with a verifier. OID4VP is MIP\'s standard protocol — with support for selective disclosure, ZK predicates, and both same-device and cross-device flows.',
    readTime: '7 min read',
    conceptTags: ['flow', 'presentation'],
    content: [
      {
        type: 'paragraph',
        text: 'A presentation flow is the sequence of steps by which a holder selects credentials from their wallet and presents them to a verifier in response to a presentation request. The verifier\'s Presentation Policy describes what is needed; the wallet constructs a Verifiable Presentation that satisfies it — disclosing only the required claims.',
      },
      { type: 'heading', text: 'OID4VP: The Standard Protocol' },
      {
        type: 'paragraph',
        text: 'OpenID for Verifiable Presentations (OID4VP) is the standard protocol for credential presentation over the internet. The verifier creates an Authorization Request containing a Presentation Definition (a DIF-format policy description). The wallet selects matching credentials, applies selective disclosure, and returns a Verifiable Presentation. Both same-device flows (wallet on the browser device) and cross-device flows (scan a QR code on your phone) are supported.',
      },
      {
        type: 'code',
        label: 'OID4VP Authorization Request (simplified)',
        lang: 'json',
        code: `{
  "response_type": "vp_token",
  "client_id": "https://verifier.example.com",
  "nonce": "n-0S6_WzA2Mj",
  "presentation_definition": {
    "id": "building-access-check",
    "input_descriptors": [{
      "id": "employee-badge",
      "format": { "jwt_vc_json": {} },
      "constraints": {
        "fields": [
          {
            "path": ["$.vc.type"],
            "filter": { "type": "array", "contains": { "const": "EmployeeBadgeCredential" } }
          },
          {
            "path": ["$.vc.credentialSubject.employment_status"],
            "filter": { "const": "active" }
          }
        ]
      }
    }]
  }
}`,
      },
      { type: 'heading', text: 'Response Binding' },
      {
        type: 'paragraph',
        text: 'In MIP\'s OID4VP implementation, presentations are bound to a nonce provided by the verifier. The holder\'s wallet signs a proof-of-possession using the holder\'s key along with the nonce. This prevents replay attacks — a captured presentation from yesterday cannot be reused today because the nonce has changed.',
      },
    ],
  },

  {
    slug: 'revocation-flows',
    chapterId: 4,
    order: 3,
    title: 'Revocation',
    summary:
      'Credentials must be revocable before they expire. MIP supports four revocation strategies, each with different privacy, latency, and offline trade-offs.',
    readTime: '7 min read',
    conceptTags: ['flow', 'revocation'],
    content: [
      {
        type: 'paragraph',
        text: 'Revocation is the ability to invalidate a credential before its natural expiry date. An employee who leaves the company should not keep using their employee badge credential. A driver\'s licence that is suspended should fail verification. A professional licence that is stripped should be immediately unusable. Revocation mechanisms make this enforceable.',
      },
      { type: 'heading', text: 'The Four Strategies' },
      {
        type: 'paragraph',
        text: 'CRLs (Certificate Revocation Lists) are batch files listing revoked credential IDs — good offline support, preserves holder privacy, but updated in batches with inherent latency. OCSP (Online Certificate Status Protocol) checks individual credential status in real time — low latency but requires connectivity and can leak usage patterns to the status server. StatusList2021 is a W3C bitstring-based approach — compact, privacy-preserving, and cacheable. Cryptographic accumulators provide zero-knowledge revocation proofs — maximum privacy but highest computational cost.',
      },
      { type: 'heading', text: 'Choosing a Strategy in MIP' },
      {
        type: 'paragraph',
        text: 'Trust Profiles specify which revocation strategies they accept for incoming credentials. Credential Templates specify which strategy was used at issuance. Deployment Profiles configure cache TTLs and refresh intervals for offline operation. This layered approach lets a single ecosystem simultaneously support high-privacy offline verification at a border crossing and real-time online checking at a web portal — using the same credential type.',
      },
    ],
  },

  {
    slug: 'selective-disclosure',
    chapterId: 4,
    order: 4,
    title: 'Selective Disclosure',
    summary:
      'Selective disclosure lets a holder share only the claims a verifier needs — without leaking the rest. SD-JWT and zero-knowledge predicates are the two primary mechanisms in MIP.',
    readTime: '8 min read',
    conceptTags: ['flow', 'selective-disclosure', 'cryptography'],
    content: [
      {
        type: 'paragraph',
        text: 'Selective disclosure is the ability for a holder to reveal only a subset of the claims in a credential, while still proving the unrevealed claims exist and were signed by the original issuer. It is the practical implementation of the minimum disclosure principle: share what\'s needed, protect everything else.',
      },
      { type: 'heading', text: 'SD-JWT: Selective Disclosure Without ZK' },
      {
        type: 'paragraph',
        text: 'SD-JWT hashes each claim individually with a random salt and embeds the hashes in the JWT payload. At presentation time, the holder includes only the salt+value pairs for the claims they choose to disclose. The verifier checks that the disclosed value hashes match the committed hash in the payload — but unrevealed claims leave no trace in the presentation.',
      },
      { type: 'heading', text: 'Zero-Knowledge Predicates' },
      {
        type: 'paragraph',
        text: 'Zero-knowledge predicates go further: they let a holder prove a logical statement about a claim without revealing the claim\'s value at all. "My birth_date satisfies age >= 18" can be proven cryptographically — the verifier learns only whether the predicate is satisfied, not the actual birth date. MIP Credential Templates declare which claims support ZK predicates; Presentation Policies can require them.',
      },
      {
        type: 'code',
        label: 'SD-JWT disclosure — only selected claims are revealed',
        lang: 'text',
        code: `// Credential has: given_name, family_name, birth_date, department, employment_status
// Verifier needs: employment_status = active, department = Engineering (as predicates)
// Holder discloses: only employment_status and department

Presentation = [compact-sd-jwt]
  . [issuer-signature]
  ~ WyJlbHVWNU9nM2dTTklJOHFBIiwgImVtcGxveW1lbnRfc3RhdHVzIiwgImFjdGl2ZSJd
  ~ WyJRZ19PNjR6cUF4ZTlyNlF4IiwgImRlcGFydG1lbnQiLCAiRW5naW5lZXJpbmciXQ

// given_name, family_name, birth_date are NOT included
// Verifier cannot infer or reconstruct them`,
      },
    ],
  },

  // ──────────── Chapter 5: Deployments ─────────────────────────────────────

  {
    slug: 'deployment-profiles-in-practice',
    chapterId: 5,
    order: 1,
    title: 'Deployment Profiles in Practice',
    summary:
      'From cloud API to air-gapped kiosk, Deployment Profiles let you run the same trust model in any environment. This guide covers the key configuration decisions.',
    readTime: '7 min read',
    conceptTags: ['deployment'],
    content: [
      {
        type: 'paragraph',
        text: 'A Deployment Profile is the operational envelope for a verification instance. It bundles the Trust Profiles and Presentation Policies that apply in this environment, specifies online or offline mode, configures cache TTLs and update schedules, and defines failure behavior when connectivity is unavailable.',
      },
      { type: 'heading', text: 'Key Configuration Decisions' },
      {
        type: 'paragraph',
        text: 'Online or offline: choose based on connectivity guarantees and assurance requirements. Cache TTLs: balance freshness against offline resilience — 72-hour trust anchor caches are common for airport deployments. Update channel: signed bundles for air-gapped terminals, real-time API polling for cloud services. Failure behavior: deny-on-stale for high-assurance scenarios, allow-on-stale for convenience-first contexts.',
      },
      { type: 'heading', text: 'Multi-Profile Deployments' },
      {
        type: 'paragraph',
        text: 'A single device can apply multiple Deployment Profiles for different verification contexts. An airport kiosk might use one profile for domestic travel (accepting only national mDLs) and another for international arrivals (accepting ICAO passports and EUDI PIDs). MIP selects the correct profile based on the credential type and issuer of the presented document.',
      },
      { type: 'heading', text: 'Staging and Production Profiles' },
      {
        type: 'paragraph',
        text: 'Deployment Profiles support environment-specific configuration. A staging profile points to test issuer roots and accepts test credentials. A production profile restricts to audited issuers and requires full revocation checking. Promoting from staging to production means updating a single Deployment Profile field — the Trust Profiles and Presentation Policies are shared between environments.',
      },
    ],
  },

  {
    slug: 'offline-verification-guide',
    chapterId: 5,
    order: 2,
    title: 'Offline Verification',
    summary:
      'Designing for offline verification requires careful thought about cache freshness, revocation strategies, and failure modes. MIP\'s architecture handles these by design.',
    readTime: '7 min read',
    conceptTags: ['deployment', 'offline'],
    content: [
      {
        type: 'paragraph',
        text: 'Many high-security identity verification scenarios occur in environments with limited or no connectivity: border crossings, aircraft, maritime vessels, remote facilities, underground transport hubs, and field operations. These use cases require that verification work offline for hours or days at a time — with no degradation in security posture.',
      },
      { type: 'heading', text: 'What Must Be Pre-Cached' },
      {
        type: 'paragraph',
        text: 'For offline verification to work correctly, the following must be pre-cached and kept fresh: trust anchor certificates or keys (from CSCA roots, trust lists, or DID documents), revocation data (CRLs, StatusList bitstrings, or accumulator witnesses), and the active Presentation Policy definitions. MIP\'s Deployment Profile specifies what to cache, how often to refresh, and from what source.',
      },
      { type: 'heading', text: 'Grace Periods and Failure Modes' },
      {
        type: 'paragraph',
        text: 'What happens when cached revocation data expires and connectivity cannot be restored? Deployment Profiles specify a grace period (the additional time verification is allowed to proceed on stale data) and a failure mode (deny-on-stale or allow-on-stale). For high-assurance use cases like border control, deny-on-stale is the correct default. For lower-assurance scenarios like office building access, a short grace period with allow-on-stale may be acceptable.',
      },
    ],
  },

  {
    slug: 'compliance-profiles-in-practice',
    chapterId: 5,
    order: 3,
    title: 'Compliance Profiles',
    summary:
      'Compliance Profiles map specific regulated standards (ICAO 9303, eIDAS 2.0, AAMVA) to MIP primitives — adopt entire credential ecosystems as code, not custom integrations.',
    readTime: '6 min read',
    conceptTags: ['deployment', 'compliance'],
    content: [
      {
        type: 'paragraph',
        text: 'A Compliance Profile is a named, versioned bundle of Trust Profiles, Credential Templates, and Presentation Policies that together implement a regulated standard. Rather than building ICAO passport verification from scratch, you install the ICAO 9303 Compliance Profile and configure your Deployment Profile to use it.',
      },
      { type: 'heading', text: 'Compliance as Configuration' },
      {
        type: 'paragraph',
        text: 'MIP v0.1.0 ships compliance profiles for ICAO 9303 (travel documents including ePassports and eNIDs), AAMVA mDL (ISO 18013-5 driver\'s licences in North America), EUDI/eIDAS 2.0 (European digital identity wallets), Open Badges 3.0 (education credentials), and DIF Presentation Exchange (cross-ecosystem interoperability). Each profile is versioned alongside the relevant specification.',
      },
      { type: 'heading', text: 'Regulatory Updates as Protocol Updates' },
      {
        type: 'paragraph',
        text: 'When eIDAS 2.0 adds a new credential format or AAMVA updates its mDL schema, the corresponding Compliance Profile is updated in the MIP protocol repository. Deployments using that profile automatically adopt the updated rules on their next synchronization cycle. Compliance evolution becomes a data update, not an engineering sprint — and the entire ecosystem moves together.',
      },
    ],
  },

  {
    slug: 'deploy-airline-boarding',
    chapterId: 5,
    order: 4,
    title: 'Airline Pre-Boarding Credentials',
    summary:
      'From ticket purchase to gate scan — how MIP orchestrates passport verification, pre-boarding credential issuance, and offline gate verification.',
    readTime: '7 min read',
    conceptTags: ['deployment', 'flow'],
    content: [
      {
        type: 'paragraph',
        text: 'Airline boarding is one of the highest-throughput identity verification scenarios in the world. Passengers present passports, boarding passes, and sometimes visas — at check-in counters, bag drops, security checkpoints, and gates. Each touchpoint today requires a different verification system. MIP unifies this with a single issuance-and-verification flow built from standard primitives.',
      },
      { type: 'heading', text: 'The Flow' },
      {
        type: 'paragraph',
        text: 'At ticket purchase, the airline captures basic booking data. At check-in, the passenger\'s passport is scanned and verified against ICAO Trust Profiles. Upon successful verification, a Pre-Boarding Credential is issued to the passenger\'s wallet — a lightweight signed attestation that the airline has verified their identity and travel authorization. At the gate, the Pre-Boarding Credential is presented and verified offline in under one second.',
      },
      {
        type: 'code',
        label: 'Pre-boarding flow',
        lang: 'text',
        code: `1. Ticket Purchase → Booking reference\n2. Check-in → Passport scan → ICAO Trust Profile verification\n3. Issuance → Pre-Boarding Credential → Passenger wallet\n4. Gate → Offline verification → Board`,
      },
      { type: 'heading', text: 'Why MIP' },
      {
        type: 'paragraph',
        text: 'The gate verification uses a Deployment Profile configured for offline mode with a 6-hour trust anchor cache. The Presentation Policy requires only the Pre-Boarding Credential — not the passport itself. The gate device never handles PII. The entire verification takes under one second, even without connectivity.',
      },
    ],
  },

  {
    slug: 'deploy-age-verification',
    chapterId: 5,
    order: 5,
    title: 'Age Verification in Retail',
    summary:
      'Verify a customer is over 21 without ever seeing their name, birth date, or address. Zero-knowledge predicates make privacy-preserving age checks practical.',
    readTime: '6 min read',
    conceptTags: ['deployment', 'selective-disclosure'],
    content: [
      {
        type: 'paragraph',
        text: 'Retail age verification today requires a cashier to look at a driver\'s licence — exposing the customer\'s full name, home address, date of birth, and licence number just to confirm they are over 21. Verifiable credentials with zero-knowledge predicates eliminate this entirely. The customer proves age >= 21 without revealing any other personal information.',
      },
      { type: 'heading', text: 'The Setup' },
      {
        type: 'paragraph',
        text: 'The retailer configures a Presentation Policy that requires a single predicate: age_over_21 == true, from a credential type matching mDL or government-issued ID, from issuers present in the AAMVA Trust Profile. The customer\'s wallet app receives the request, finds a matching mDL credential, and generates a zero-knowledge proof that the predicate is satisfied.',
      },
      {
        type: 'code',
        label: 'Age verification Presentation Policy',
        lang: 'json',
        code: `{\n  "id": "retail-age-check-v1",\n  "requirements": [{\n    "credential_type": "mDL",\n    "trust_profiles": ["aamva-mdl-trust-v1"],\n    "required_predicates": [\n      { "claim": "age_over_21", "op": "eq", "value": true }\n    ],\n    "required_claims": []\n  }],\n  "holder_binding": "required"\n}`,
      },
      { type: 'heading', text: 'No PII Transmitted' },
      {
        type: 'paragraph',
        text: 'The verifier receives a cryptographic proof that the predicate is true — and nothing else. No name, no address, no birth date, no licence number. The proof is bound to a one-time nonce, so it cannot be replayed. The entire interaction takes less than two seconds on a phone tap.',
      },
    ],
  },

  {
    slug: 'deploy-enterprise-access',
    chapterId: 5,
    order: 6,
    title: 'Enterprise Employee Access',
    summary:
      'Replace badge readers and LDAP lookups with verifiable employee credentials. Same identity for door access, VPN login, and application authorization.',
    readTime: '6 min read',
    conceptTags: ['deployment', 'flow'],
    content: [
      {
        type: 'paragraph',
        text: 'Enterprise identity today is fragmented: badge readers check physical cards, VPNs check LDAP, and applications check SAML or OIDC tokens — three separate identity systems for the same employee. Verifiable employee credentials unify all three. The employee holds a single credential that works at doors, on VPNs, and in applications.',
      },
      { type: 'heading', text: 'Issuance' },
      {
        type: 'paragraph',
        text: 'HR issues an EmployeeBadgeCredential through a MIP Flow. The credential includes employment status, department, role, and optionally an access-level claim. The Credential Template declares employment_status as always disclosed and department as selectively disclosed. The credential is delivered to the employee\'s corporate wallet.',
      },
      { type: 'heading', text: 'Verification Scenarios' },
      {
        type: 'paragraph',
        text: 'Door access: the door reader\'s Presentation Policy requires employment_status = active and department matching the building zone. VPN login: the VPN gateway\'s policy requires employment_status = active. Application authorization: the app\'s policy requests role and department for RBAC decisions. Each verifier sees only the claims its policy requires.',
      },
    ],
  },

  {
    slug: 'deploy-membership-credentials',
    chapterId: 5,
    order: 7,
    title: 'Membership Credentials',
    summary:
      'Gym memberships, professional associations, and conference badges — lightweight credential types that demonstrate MIP\'s flexibility beyond government identity.',
    readTime: '5 min read',
    conceptTags: ['deployment', 'credential-template'],
    content: [
      {
        type: 'paragraph',
        text: 'Not every credential needs the assurance level of a passport. Memberships — gym passes, professional association cards, conference badges, library cards — are lightweight identity assertions that benefit from verifiability without requiring PKI infrastructure. MIP handles these with the same primitives used for government credentials, just with simpler Trust Profiles.',
      },
      { type: 'heading', text: 'Example: Conference Badge' },
      {
        type: 'paragraph',
        text: 'A conference organizer issues a ConferenceBadgeCredential with attendee name, ticket type, and session access. The Credential Template uses a short TTL matching the conference duration. Presentation Policies at session entrances require only the ticket type claim. The verifier is a smartphone app scanning a QR code — no custom hardware, no badge printers, no lost-badge desk.',
      },
      {
        type: 'code',
        label: 'Membership Credential Template',
        lang: 'json',
        code: `{\n  "id": "gym-membership-v1",\n  "credential_type": "MembershipCredential",\n  "claims_map": {\n    "member_name": "application.name",\n    "member_id": "application.member_id",\n    "organization": "\\"Ironside Fitness\\"",\n    "membership_tier": "application.tier",\n    "valid_until": "application.expiry"\n  },\n  "validity": { "ttl": "P1Y" },\n  "selective_disclosure": {\n    "always_disclosed": ["organization", "membership_tier"],\n    "selectively_disclosed": ["member_name", "member_id"]\n  }\n}`,
      },
    ],
  },

  {
    slug: 'deploy-future-identity',
    chapterId: 5,
    order: 8,
    title: 'The Future of Digital Identity',
    summary:
      'Digital wallets, post-quantum cryptography, and global interoperability — where verifiable identity is headed and how MIP is designed to evolve with it.',
    readTime: '6 min read',
    conceptTags: ['deployment', 'foundation'],
    content: [
      {
        type: 'paragraph',
        text: 'Verifiable credentials are moving from pilot to production. The EU mandates digital identity wallets by 2026. Apple and Google integrate mDL support into their wallet platforms. ICAO is standardizing Digital Travel Credentials for passports. The next five years will see verifiable credentials become the default model for digital identity — not the alternative.',
      },
      { type: 'heading', text: 'Digital Wallet Convergence' },
      {
        type: 'paragraph',
        text: 'Apple Wallet, Google Wallet, and EU-mandated national wallets will all support verifiable credentials. The distinction between "identity wallet" and "payment wallet" will disappear. MIP\'s multi-format support (SD-JWT, mDoc, W3C VC) ensures credentials work across all wallet platforms without format conversion or vendor-specific integrations.',
      },
      { type: 'heading', text: 'Post-Quantum Transition' },
      {
        type: 'paragraph',
        text: 'Quantum computers capable of breaking RSA and ECDSA signatures will exist within the next decade. MIP\'s Trust Profiles specify accepted algorithms as configuration, so adding post-quantum algorithms (ML-DSA, SPHINCS+) is a Trust Profile update — not an application rewrite. Credential Templates can specify hybrid signatures (classical + PQC) during the transition period.',
      },
      { type: 'heading', text: 'Global Interoperability' },
      {
        type: 'paragraph',
        text: 'A Japanese passport should be verifiable at a European border crossing. An American mDL should work at an Australian age-gated venue. MIP\'s Compliance Profiles map regional standards to shared protocol primitives, so a verifier can accept credentials from any compliant ecosystem without per-issuer integrations. This is the end state: one protocol, many issuers, global verification.',
      },
    ],
  },

  // ──────────── Chapter 6: Implementations ──────────────────────────────────

  {
    slug: 'impl-oid4vci',
    chapterId: 6,
    order: 1,
    title: 'OID4VCI: The Issuance Standard',
    summary:
      'OpenID for Verifiable Credential Issuance (OID4VCI) is the IETF standard for delivering credentials from issuer to wallet. Here\'s how MIP implements both the authorization code and pre-authorized code flows.',
    readTime: '9 min read',
    conceptTags: ['implementation', 'oid4vci'],
    content: [
      {
        type: 'paragraph',
        text: 'OID4VCI is an IETF draft standard that extends OAuth 2.0 to support verifiable credential issuance. It defines how a holder\'s wallet discovers what credentials an issuer offers, how the holder authenticates, and how the credential is securely delivered. MIP implements OID4VCI as the standard issuance protocol for all credential types.',
      },
      { type: 'heading', text: 'Two Grant Types' },
      {
        type: 'paragraph',
        text: 'The authorization code flow provides the highest security: the user authenticates with the issuer\'s OAuth authorization server before the credential is generated. This is the correct flow for online issuance scenarios. The pre-authorized code flow is used when the user has already been authenticated out-of-band — for example, during in-person onboarding where the issuer generates a PIN-protected offer code.',
      },
      {
        type: 'code',
        label: 'Credential request to OID4VCI /credential endpoint',
        lang: 'http',
        code: `POST /credential HTTP/1.1
Host: issuer.example.com
Authorization: Bearer czZCaGRSa3F0MzpnWDFmQ...
Content-Type: application/json

{
  "credential_configuration_id": "EmployeeBadgeCredential",
  "proof": {
    "proof_type": "jwt",
    "jwt": "eyJhbGciOiJFZERTQSIsImtpZCI6ImRpZDprZXk6..."
  }
}

// Response:
{
  "credential": "eyJhbGciOiJFUzI1NiJ9...",
  "c_nonce": "fGFF7UkhLa",
  "c_nonce_expires_in": 86400
}`,
      },
      { type: 'heading', text: 'Credential Format Negotiation' },
      {
        type: 'paragraph',
        text: 'OID4VCI supports format negotiation — the wallet requests its preferred format (SD-JWT-VC, mDoc, or W3C VC) and the issuer delivers accordingly. MIP\'s Credential Template system supports multiple output formats from the same template definition, so a single template can issue an SD-JWT for web use cases and an mDoc for proximity use cases.',
      },
    ],
  },

  {
    slug: 'impl-oid4vp',
    chapterId: 6,
    order: 2,
    title: 'OID4VP: The Presentation Standard',
    summary:
      'OpenID for Verifiable Presentations (OID4VP) is the standard for presenting credentials to a verifier — supporting selective disclosure, ZK predicates, and both same-device and cross-device flows.',
    readTime: '8 min read',
    conceptTags: ['implementation', 'oid4vp'],
    content: [
      {
        type: 'paragraph',
        text: 'OID4VP extends OID4VCI\'s authorization model with a presentation request/response protocol. The verifier sends an Authorization Request containing a Presentation Definition. The holder\'s wallet selects matching credentials, applies selective disclosure per the policy, and returns a Verifiable Presentation in the Authorization Response.',
      },
      { type: 'heading', text: 'Same-Device vs Cross-Device' },
      {
        type: 'paragraph',
        text: 'In same-device flows, the wallet is on the same device as the verifier\'s browser or app. The request is delivered via a custom URI scheme or redirect. In cross-device flows — a verifier website on a desktop computer, wallet on a phone — the request is delivered as a QR code encoded as an OID4VP authorization request URI. The wallet scans, processes the request, and the response is sent directly to the verifier\'s redirect_uri.',
      },
      {
        type: 'code',
        label: 'Verifiable Presentation Token response',
        lang: 'json',
        code: `{
  "vp_token": "eyJhbGciOiJFUzI1NiJ9...",
  "presentation_submission": {
    "id": "a30e3b91-fb77-4d22-9f92",
    "definition_id": "building-access-check",
    "descriptor_map": [
      {
        "id": "employee-badge",
        "format": "jwt_vc_json",
        "path": "$.vp.verifiableCredential[0]"
      }
    ]
  }
}`,
      },
      { type: 'heading', text: 'HAIP and ARF Compliance' },
      {
        type: 'paragraph',
        text: 'The High Assurance Interoperability Profile (HAIP) and the EU Architecture Reference Framework (ARF) both use OID4VP as the presentation protocol. MIP\'s OID4VP implementation satisfies both profiles out of the box. For EUDI deployments, MIP adds the ARF-required wallet attestation validation and cross-device flow security requirements.',
      },
    ],
  },

  {
    slug: 'impl-mdoc',
    chapterId: 6,
    order: 3,
    title: 'mDoc / ISO 18013-5',
    summary:
      'ISO 18013-5 defines the mDoc format for government credentials. CBOR-encoded, device-bound, and built for proximity — here\'s how mDocs work and how MIP supports them.',
    readTime: '8 min read',
    conceptTags: ['implementation', 'mdoc', 'iso-18013'],
    content: [
      {
        type: 'paragraph',
        text: 'ISO 18013-5 defines the mDoc (mobile Document) format, the global standard for mobile driver\'s licences (mDLs) and, increasingly, other government credentials. Unlike W3C VCs, mDocs use CBOR binary encoding (not JSON), are specifically designed for device-held use cases, and include built-in proximity presentation via NFC or BLE — enabling in-person verification without internet connectivity.',
      },
      { type: 'heading', text: 'CBOR and Namespaced Data Elements' },
      {
        type: 'paragraph',
        text: 'mDocs store namespaced data elements: the org.iso.18013.5.1 namespace contains standard mDL fields (family_name, given_name, birth_date, portrait, driving_privileges). Extension namespaces hold jurisdiction-specific fields. The entire document is CBOR-encoded and signed using COSE (CBOR Object Signing and Encryption), which is the binary equivalent of JWS.',
      },
      { type: 'heading', text: 'Device Binding and Proximity Presentation' },
      {
        type: 'paragraph',
        text: 'Every mDoc includes a device-bound key pair. At presentation time, the device signs a session transcript using this key, proving the credential is held by the device presenting it (not just a screenshot or copy). Proximity presentation uses BLE discovery or NFC channel establishment between the mDoc reader and the wallet device.',
      },
      {
        type: 'code',
        label: 'mDoc selective disclosure request (namespaced elements)',
        lang: 'json',
        code: `// DeviceRequest from verifier specifying which elements to disclose
{
  "version": "1.0",
  "docRequests": [{
    "itemsRequest": {
      "docType": "org.iso.18013.5.1.mDL",
      "nameSpaces": {
        "org.iso.18013.5.1": {
          "family_name": false,
          "given_name": false,
          "age_over_21": true     // intent_to_retain = true
        }
      }
    }
  }]
}`,
      },
    ],
  },

  {
    slug: 'impl-open-badges',
    chapterId: 6,
    order: 4,
    title: 'Open Badges 3.0',
    summary:
      'Open Badges 3.0 aligns the education credential standard with W3C VCs. MIP adds trust governance to Open Badges — enabling verifier-side validation of issuing institutions.',
    readTime: '7 min read',
    conceptTags: ['implementation', 'open-badges'],
    content: [
      {
        type: 'paragraph',
        text: 'Open Badges 3.0 is the 1EdTech (formerly IMS Global) standard for digital credentials in education and workforce development. It extends the W3C Verifiable Credentials data model with badge-specific types: OpenBadgeCredential (the issued instance) and Achievement (the accomplishment being recognized). Version 3.0, released in 2022, makes Open Badges fully compatible with the broader VC ecosystem.',
      },
      { type: 'heading', text: 'What Open Badges Does Not Solve' },
      {
        type: 'paragraph',
        text: 'Open Badges defines the credential format but not the trust governance framework. Anyone can issue an "MIT Certified Kubernetes Administrator" badge — the format provides no mechanism for a verifier to confirm whether an issuer is actually accredited by MIT or any other institution. MIP\'s Trust Profiles fill this gap with configurable trust registries for educational institutions and accreditation bodies.',
      },
      {
        type: 'code',
        label: 'Open Badge Credential (simplified)',
        lang: 'json',
        code: `{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.2.json"
  ],
  "type": ["VerifiableCredential", "OpenBadgeCredential"],
  "issuer": {
    "id": "https://university.example.edu",
    "type": "Profile",
    "name": "Example University"
  },
  "credentialSubject": {
    "type": "AchievementSubject",
    "achievement": {
      "type": "Achievement",
      "name": "Introduction to Cryptography",
      "criteria": { "narrative": "Completed 12-week course with 85%+ score." },
      "achievementType": "Certificate"
    }
  }
}`,
      },
      { type: 'heading', text: 'MIP\'s Open Badges Compliance Profile' },
      {
        type: 'paragraph',
        text: 'MIP\'s Open Badges 3.0 Compliance Profile bundles a Trust Profile that validates against 1EdTech\'s well-known endpoint, a Credential Template for the OpenBadgeCredential type with standard claims mapping, and a Presentation Policy for employer verification flows. An organization adopting MIP gets compliant Open Badges issuance and verification without implementing the standard from scratch.',
      },
    ],
  },

  {
    slug: 'impl-icao-dtc',
    chapterId: 6,
    order: 5,
    title: 'ICAO Digital Travel Credentials',
    summary:
      'ICAO\'s Digital Travel Credential (DTC) standard brings passport verification to smartphones. MIP\'s ICAO Compliance Profile supports Virtual DTC, cloud-attested DTC, and hardware-bound DTC variants.',
    readTime: '8 min read',
    conceptTags: ['implementation', 'icao'],
    content: [
      {
        type: 'paragraph',
        text: 'The International Civil Aviation Organization (ICAO) is extending its 9303 standard to support digital travel credentials stored on smartphones — not just physical passport chips. There are three variants: Type 1 (Virtual DTC, a signed copy of the passport data), Type 2 (cloud-attested DTC with issuing-state attestation), and Type 3 (hardware-bound DTC using secure element or TEE). Each variant has different security and privacy properties.',
      },
      { type: 'heading', text: 'How MIP Models DTCs' },
      {
        type: 'paragraph',
        text: 'MIP\'s ICAO 9303 Compliance Profile maps all three DTC types to MIP primitives. The Trust Profile specifies accepted CSCA roots from ICAO\'s PKD. Credential Templates define the data group structure (DG1–DG16) and which fields support selective disclosure. Presentation Policies for border control specify which data groups are required versus optional. Deployment Profiles configure offline verification with appropriate cache TTLs.',
      },
      {
        type: 'code',
        label: 'DTC types — security properties comparison',
        lang: 'text',
        code: `Type 1 (Virtual):\n  Signed copy of MRZ + photo + fingerprint data\n  Verification: signature check against CSCA\n  Offline: yes (with cached CSCA roots)\n  Device binding: none\n\nType 2 (Cloud-Attested):\n  Issuing-state attestation via backchannel\n  Verification: online attestation + signature check\n  Offline: partial (signature only)\n  Device binding: weak (app-level)\n\nType 3 (Hardware-Bound):\n  Secure element or TEE key storage\n  Verification: device authentication + signature check\n  Offline: yes (full)\n  Device binding: strong (hardware)`,
      },
      { type: 'heading', text: 'Border Crossing Integration' },
      {
        type: 'paragraph',
        text: 'At a border crossing, the traveler presents their DTC via NFC or QR code. The border control kiosk runs MIP verification: check the ICAO signature chain, validate the DTC against the ICAO Trust Profile, apply the border-control Presentation Policy (requiring DG1 + DG2 at minimum), and confirm the DTC has not been revoked via the ICAO CRL. All of this can operate offline with pre-cached trust anchors.',
      },
    ],
  },
];

// ── Derived lookups ────────────────────────────────────────────────────────────

/** Flat ordered list for prev/next navigation */
export const GUIDE_ARTICLE_SLUGS = GUIDE_ARTICLES.map((a) => a.slug);

/** O(1) slug → article lookup */
export const GUIDE_ARTICLE_MAP = Object.fromEntries(
  GUIDE_ARTICLES.map((a) => [a.slug, a]),
);

/** Articles grouped by chapter id */
export const GUIDE_ARTICLES_BY_CHAPTER = Object.fromEntries(
  GUIDE_CHAPTERS.map((ch) => [
    ch.id,
    GUIDE_ARTICLES.filter((a) => a.chapterId === ch.id).sort((a, b) => a.order - b.order),
  ]),
);

// ── Blog post concept tags (separate from guide articles) ─────────────────────

export const BLOG_POST_CONCEPT_TAGS = {
  'why-identity-needs-a-protocol': ['foundation', 'business'],
  'trust-profiles-explained': ['core-object', 'trust-profile'],
  'business-case-for-credential-portability': ['business', 'deployment'],
  'cryptographic-trust-anchors-primer': ['governance', 'cryptography', 'trust-anchor'],
  'credential-templates-designing-what-gets-issued': ['core-object', 'credential-template'],
  'presentation-policies-minimum-disclosure': ['core-object', 'presentation-policy'],
  'eudi-wallet-readiness': ['compliance', 'deployment', 'business'],
  'deployment-profiles-from-design-to-production': ['core-object', 'deployment-profile'],
  'zero-knowledge-predicates-identity': ['cryptography', 'selective-disclosure'],
  'flows-orchestrating-identity-lifecycle': ['flow'],
  'compliance-profiles-bridging-regulation': ['compliance', 'deployment'],
  'sd-jwt-selective-disclosure-deep-dive': ['cryptography', 'selective-disclosure'],
  'cedar-policies-for-identity-governance': ['governance', 'cedar', 'policy-engine'],
  'introducing-mip': ['announcement'],
  'mip-json-schemas-walkthrough': ['implementation'],
  'post-quantum-readiness-in-identity': ['cryptography', 'trust-anchor'],
  'building-trust-registries-at-scale': ['governance', 'trust-registry'],
  'offline-verification-design-patterns': ['deployment', 'offline'],
  'holder-binding-beyond-biometrics': ['cryptography', 'foundation'],
  'mip-and-open-badges-education-credentials': ['implementation', 'open-badges'],
  'conformance-testing-for-implementers': ['implementation'],
  'revocation-strategies-compared': ['cryptography', 'revocation'],
};

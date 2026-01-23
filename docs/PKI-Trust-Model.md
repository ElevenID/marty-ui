Designing a PKI Trust Model for mDLs and Passport-Grade Credentials
Understanding the PKI Terminology in Government IDs: In the world of ePassports and mobile IDs (like mDLs or mobile driver’s licenses), trust is established via a Public Key Infrastructure (PKI). Each issuing authority (e.g. a government agency or accredited organization) has a public–private key pair and a corresponding digital certificate. The certificate binds the issuer’s identity to its public key and is often signed by a higher authority. For example, an electronic passport uses a Country Signing Certificate Authority (CSCA) as the root of trust, which issues Document Signer Certificates (DSCs) for each batch of passports. The DSC (with its public key) is stored on the passport’s chip and is used to verify that the data on the chip hasn’t been tampered with【10†L175-183】. The CSCA’s own certificate (the root certificate) isn’t on the chip; instead, border authorities maintain a trust list of all trusted CSCA certificates. This forms a chain of trust: if the inspection system trusts the CSCA’s public key, it can trust any DSC that was signed by that CSCA, and in turn trust the data signed by the DSC. The same principle applies to mDL (ISO 18013-5 mobile license) credentials – an Issuing Authority has a root certificate (sometimes called an Issuing Authority CA or IACA) which signs the document or an intermediate certificate, and verifiers must trust that root key via a distributed list or other mechanism[1][2].
Illustration of a PKI chain of trust for government IDs: a country’s root Certificate Authority signs subordinate Document Signer certificates, which then sign the digital contents of IDs (e.g. passport chip data). Verifiers trust the root certificate (kept in a trust list) to authenticate all documents issued under it.[1]
Key PKI Components (and User-Friendly Labels): To design a user interface for non-technical users, you’ll want to use familiar or simplified terminology for these PKI components. Here are the key terms in this context and how to present them:
	•	Issuing Authority / Certificate Authority – In technical terms, this is the organization that issues digital credentials and holds the root signing key (e.g. a state DMV for driver’s licenses or a country’s passport authority). In the UI, you might call this the “Issuing Organization” or simply “Your Organization’s Authority.” It represents the top-level trust identity for the org. For example, in ISO 18013-5 mDL, the issuing authority’s root certificate is sometimes called the IACA (Issuing Authority CA)[3], which is essentially an X.509 certificate identifying the issuer. To a business user, this can be described as “Your organization’s digital identity certificate.”
	•	Public Key Certificate – This is the X.509 certificate file (often in PEM format) containing the public key and information about the issuer. Rather than using the term “X.509 certificate” with non-technical folks, you can label it as a “Digital Certificate” or “Trust Certificate.” For example, an mDL or passport issuer’s public key is distributed to verifiers via a certificate. Verifiers need the issuer’s certificate to check credentials’ signatures. The UI might say: “Upload or select the certificate of the authority you trust/represent.” This avoids acronyms but still uses a term (“certificate”) that many have heard in contexts like SSL or email.
	•	Trust Anchor / Root Certificate – This refers to the top-level certificate that verifiers trust directly (often self-signed by the issuer). In ePassport terms, the CSCA certificate is the trust anchor; in mDL, the IACA certificate serves that role[3][4]. You can refer to this in UI as the “Trusted root certificate” or “Root of Trust.” For instance, you might say: “Add a trusted root certificate for any issuer whose credentials you will accept.” This communicates that the certificate is a top-level authority to be trusted. If your system will hide even that complexity, you could simply say “Trusted Issuers” and let users select from known issuers or upload a certificate for an issuer. Under the hood, those entries correspond to root certificates/public keys.
	•	Trusted Issuer List (Trust List) – Instead of exposing the term VICAL (Verified Issuer CA List) or trust list directly, you can present this concept as “Trusted Issuers” or “Trusted Authorities.” In practice, mDL verifiers use a trust list of issuer public keys to know which issuers are bona fide[2]. For example, AAMVA (in North America) provides a Digital Trust Service (DTS) that aggregates all valid issuer public keys into one list[2]. In the UI, a user might simply choose “Use the official list of government issuers” as an option. Alternatively, if they have a custom set of issuers to trust, they could choose “Manually configure trusted issuers” and add entries. Each entry could be labeled by issuer name and have an attached certificate or identifier. The goal is to spare non-technical users from thinking about certificate chains – they just decide “who do I trust to issue valid credentials?” and the system takes care of the rest (verifying signatures against those trusted certificates).
	•	Certificate Chain / Chain of Trust – This is the hierarchical relationship of certificates (root -> intermediate -> end-entity). Government credential systems usually have at most two levels: a root CA and an end-entity certificate (DSC)[3][4]. In your UI, you don’t need to expose the chain explicitly; the system can automatically check that an incoming credential’s signing certificate chains up to one of the trusted roots. However, it’s useful for you (as the designer) to understand that behind the scenes. You might provide information in an advanced view, but for basic users it can be implicit. For example, if a user adds “State of X Digital ID Certificate” as trusted, your verification engine will accept any credential whose signature can be verified with that certificate (or a chain leading to it). You can simply indicate in the interface whether a presented credential is “Signed by a Trusted Issuer” (no need to detail chain validation steps to the user).
	•	Private Key (Signing Key) – This is the secret key that an issuer uses to digitally sign credentials (e.g. to sign the mobile ID’s data or to sign an intermediate DSC). It’s never shared publicly. From a terminology standpoint, calling it “private key” is standard, but for a non-technical audience you may refer to it as the “Issuing key” or “Signing secret.” For instance, the UI might say: “Provide your organization’s signing key (private key). This key stays secure with you and is used to issue your digital credentials.” It’s important to emphasize that this piece should remain highly secure – likely the UI will not show or transmit the raw key if possible. You can allow the user to keep it in a secure store and only reference or use it when needed.
Setting Up an Organization’s Trust Model – Requirements: When an organization onboards to your mDoc management platform, there are two main things they must configure: (1) Whom they trust (which other issuers’ credentials will they consider valid) and (2) Their own issuing credentials (the keys/certificates they will use if they are going to issue mDocs). A good UI will guide them through both in simple terms:
	•	Choose a Trust Source for Verifying Credentials: Decide what PKI trust model the organization will use to verify incoming certificates from others. In practice, this could mean using a standard government trust list or a custom list. For example, an airport security checkpoint might choose to trust all passports and mobile IDs issued by governments participating in a global trust framework. In UI, this could be a dropdown or selection like: “Trust Model: [Use Official Government Issuer List] or [Custom Configuration]”. If they select an official list, your service can behind the scenes fetch and update the list of trusted root certificates (e.g. from AAMVA’s DTS for mDL issuers[2], or from ICAO’s PKD/master list for ePassports). If they choose custom, they should be able to add individual trusted issuer certificates. For each added issuer, they could input a name and either upload a certificate file (PEM/DER) or perhaps select from a known directory. Non-technical users won’t think in terms of “X.509 vs DID” – they think in terms of organizations or issuers. So your UI might say “Add Trusted Issuer” with options to either “Upload issuer certificate” or “Enter issuer Decentralized ID” (more on DIDs shortly). Internally, whether that issuer is represented by an X.509 certificate or a DID, your system will treat it as a trusted public key for verification. The Paradym platform, for example, uses a concept of Trusted Entities configured with either X.509 certificates or DIDs, and then ties those to verification rules[5]. This allows specifying exactly which issuers are considered valid for a given credential presentation. In the short term, most implementations simply let the admin list trusted issuers (by certificate or DID), whereas in the long term we expect government-maintained trust frameworks (e.g. an official list of accredited issuers for an entire region) to be available[6]. The UI should accommodate both: an easy way to select a predefined trust framework or manually add entries.
	•	Configure Your Organization’s Own Issuance Keys/Certificates: If the organization will issue mDocs (or any credentials), they need to set up their issuing certificate(s). This typically involves creating or importing a key pair and certificate. In a government scenario, an issuer often has a long-lived root key/certificate (e.g. the IACA or CSCA) which is kept very secure, and then uses it to sign short-lived document signer certificates for actual credential issuance[3][4]. For simplicity, you might not require the user to explicitly manage multiple levels of certificates if that’s too complex for them – the system could abstract it. For instance, the UI can simply ask: “Do you have an existing issuer certificate you’d like to use, or should we help generate a new one?” If they have one (e.g. a government agency might already have a CA set up), they could upload the public certificate (so your system knows what will be used to sign and can distribute that to verifiers if needed). They would not upload the private key to your cloud (for security reasons), but might indicate how they will perform signing (see next section on key storage). If they don’t have any existing PKI, your tool could generate a new key pair and produce a self-signed certificate (the user would download or record the private key securely). The UI can call this something like “Your Organization’s Digital ID Certificate”. Under the hood, this might become the root of a chain (the IACA). The system could then automatically generate a subordinate signing certificate (DSC) for day-to-day use, or it could even use the root certificate directly for signing if absolutely needed – but following standards, having a distinct document signer certificate is more ideal[4][7]. You might hide this complexity entirely: for example, once the user provides or creates their root certificate, the software could handle issuing an intermediate certificate for actual credential signing, without the user needing to know. The user just cares that “we have set up your issuing keys and certificate.”
	•	DID vs X.509 Considerations (Supporting Both): You mentioned needing to support both traditional X.509-based trust and DIDs (decentralized identifiers), ideally forcing DIDs to conform to a similar trust model. Indeed, DIDs don’t rely on hierarchical CAs; trust in a DID is often established by knowing the DID issuer (e.g. a trusted ledger or organization) or via out-of-band agreements. To keep things simple for users, you can treat a DID essentially as another form of issuer identifier. In the UI, when adding a trusted issuer, allow an input of a DID (with perhaps a dropdown of supported DID methods) as an alternative to uploading a certificate. Internally, your service can resolve that DID to obtain the associated public key(s) (from the DID Document) and then use those keys to verify credentials. The key point is you still maintain an explicit list of which DIDs are trusted – this way, even though the verification uses decentralized tech, the business user’s mental model is the same (“I trust issuer X”). For example, Paradym’s platform lets you link multiple DIDs and X.509 certificates to a single trusted entity definition[5]. In practice, you might restrict DIDs to ones issued by known authorities or that have some attestation, to mirror the assurance level of a CA-issued certificate. You mentioned “force any DIDs to use the same or similar (trust model)” – this could mean requiring that a DID corresponds to an issuer that is also recognized in the X.509 world or is distributed via an official trust list. Another approach is to issue an X.509 certificate to represent the DID (some ecosystems do this for compatibility). But rather than expose all that, the UI can simply accept a DID and perhaps display it as “Decentralized ID for Issuer” and handle trust verification in the background (for example, only allow DIDs from certain registry/ledger or require the admin to confirm the DID’s authenticity through a workflow).
Security and Key Management (Avoiding Cloud-Stored Secrets): A crucial aspect is ensuring the issuing private keys remain secure. Since your cloud service is managing mDocs for clients (organizations), it’s wise not to take custody of their secret keys if possible. Industry best practices suggest that issuers keep their signing private keys in a Hardware Security Module (HSM) or at least in a secure key vault, limiting access only to authorized personnel[8]. For your UI/UX, this means you can offer methods for the org to use your service without uploading their private key to you in plaintext. Here are some possibilities:
	•	Use Browser/OS Key Stores: Modern operating systems and browsers do have facilities for storing and using keys. For example, on a Mac, an organization can import their private key and certificate into the macOS Keychain. On Windows, there’s the Certificate Store. Browsers like Chrome can access client certificates (often for TLS client-auth), but using them for arbitrary signing via a web app is non-trivial. However, you can leverage the Web Cryptography API: a user could generate a key pair in the browser and mark it as non-extractable, which means it stays in the browser’s storage (or in an underlying OS keystore) and can be used for signing via JavaScript but never exposed directly. Safari, for instance, integrates with Keychain for WebCrypto keys on Apple devices[9]. In practice, you might implement a small local helper or browser extension that interfaces with the OS keystore to sign data. From the user’s perspective, when they need to issue credentials, the app can prompt “Please confirm use of your signing key” and the signing operation happens locally, with the signature then sent to your cloud service. This way, your cloud service gets the signed mDoc, but never the raw private key.
	•	External Password Managers or Vaults: The user mentioned storing PEM keys in a password manager. Password managers (like 1Password, LastPass, etc.) can securely store files or text (so they could hold an encrypted PEM), but they typically don’t provide direct cryptographic operations on those keys. The user would have to copy the key out when needed – which isn’t ideal for frequent signing operations. Instead, consider integration with a cloud key management service or vault that supports API access. For example, Azure Key Vault, AWS KMS, or even a self-hosted HSM, where the key remains in the vault and your service can request a signature via an API. For smaller orgs or simpler setups, a browser-based approach (WebCrypto) might suffice, whereas larger enterprises might have an HSM. In your UI, you could give an option: “Where is your signing key stored?” with choices like “Browser/Device keystore” or “External Key Vault” or even “Managed by us.” If they choose browser/keystore, you’d use something like the WebCrypto method; if Key Vault, you’d have them provide connection details (this might be too complex for non-tech users though, so likely a tech administrator would do that part). If they choose “Managed by us,” that means they are entrusting you with the key (which you said you prefer not to handle – but it could be an option for those who don’t have their own secure storage; in that case you’d need to clearly communicate the risks and use strong protection like storing it encrypted and using an HSM on your side).
	•	PEM Files and User-Protected Keys: Another approach is to let users upload a private key file encrypted with a passphrase. Your service never sees the raw key unless the user enters the passphrase to decrypt it in a secure client-side environment. For instance, the UI could allow an admin to upload an encrypted PKCS#12 (.p12) bundle or a PEM with a password. Each time a signature is needed (e.g. issuing a batch of credentials), the admin (or an automated process on their side) would need to supply the passphrase so the key can be used (or better, the signing happens client-side after they unlock the key). This is a bit clunky for non-technical users, so it might be reserved as an advanced option.
In summary, yes – it is possible to store and use PEM keys via Apple Keychain, Chrome’s storage, or password managers, but the integration needs to be smooth. On Apple platforms, storing keys in the Keychain provides strong security (keys can be marked non-exportable). On the web, the Chrome browser itself doesn’t offer a UI to just drop in a key for your web app’s use, but with the Web Crypto API you can generate or import a key into the browser context and keep it secure there[10][11]. The key point (which you are aiming for) is that your cloud service should not manage or see the private secrets – it should enable the org’s own environment to manage those. This aligns with industry guidance that issuing authorities protect their private keys with strong security controls (potentially hardware protection)[8].
Designing the User Interface (Hiding Complexity): The challenge is to present all the above in a friendly way for business and travel industry users (who might not be cryptography experts). Here are some suggestions for the UI/UX design to hide complexity:
	•	Use Wizards or Step-by-Step Setup: Guide the user through “Trust Setup” and “Issuer Setup” separately. For example, upon creating a new organization profile in your system, step 1 could be “Configure Trusted Credentials” and step 2 “Configure Your Organization’s Credentials.” Each step uses simple language. In step 1, you could ask: “Whose digital IDs will you accept or trust in your operations?” The user could choose options like “All government-issued IDs”, “Only our own issued IDs”, or “Custom list of issuers”. If they choose a broad option, you auto-select the appropriate trust list (maybe with a description like “This will trust any ID issued by a government authority that’s part of the international trust network”). If they choose custom, then provide an interface to add specific issuers as discussed. You might present an issuer addition form that has fields for “Issuer Name” and either “Certificate file” or “DID (Decentralized ID)” – but perhaps label the latter as “Issuer ID” with a hint that it can be a DID URL. That way, those who don’t know what DIDs are won’t be scared off; and those who do can input it.
	•	Terminology Tips: It may help to include brief tooltips or help text for terms like certificate, issuer, etc., written in plain English. For instance, next to a field that says “Certificate,” a tooltip could explain “A digital certificate is like an organization’s digital passport – it proves the identity of the issuer. Upload the file provided by the issuer or authority.” This draws an analogy (passport for computers) that makes sense to laypeople (indeed, one explanation is that certificates are like passports for public keys[12]).
	•	Default Sensible Choices: If possible, pre-populate fields or provide defaults. Non-technical users benefit from not having to make too many decisions. For example, if most of your customers will use a particular trust framework, have that selected by default (with the ability to change it). If your tool can generate a certificate for them, offer that as a one-click option (“Generate a new digital identity for my org”) and then instruct them clearly how to save the provided key. You could generate it client-side for security. After generation, present a “Download Your Key” prompt with big warnings to store it safely (since you won’t keep a copy).
	•	Abstract the Crypto Jargon: Avoid exposing things like “X.509”, “PKI”, “SHA-256”, “PEM” in the primary UI. Those can appear in a technical settings page if needed, but for the average user, use descriptive names. For example, instead of a button that says “Import PEM file,” just say “Upload Certificate.” Instead of “Select Hash Algorithm,” you’d likely have no such option for them – you’d hard-code recommended algorithms under the hood.
	•	Confirmation and Testing: Once the org sets up their trust model, it’s helpful to let them test it in a simple way. For example, “We’ve added 3 trusted issuers: [List]. We’ve recorded your organization’s certificate for issuing.” Perhaps provide a status: “All set! Your system will now trust IDs from X, Y, Z. Any ID you issue will be signed by [Org Name] and verifiable by others.” You might even offer a test verification: “Upload a sample credential to verify it’s recognized,” which internally checks the signature against the configured trust anchors.
By designing along these lines, you hide the complex web of certificate chains and key stores behind choices like “trusted issuers” and “signing key.” The terminology you use in the UI should focus on roles and outcomes (Issuer, Certificate, Trusted list, Signing key) rather than the low-level cryptographic details. Meanwhile, your system under the hood will enforce the PKI: verifying signatures, ensuring chains are valid up to a trusted root, and so on, but the user doesn’t need to see those logs unless they want to.
Bringing it All Together – Example Scenario: Imagine a travel company setting up your mDoc management tool. In the UI, they see a section for “Trust Settings.” They select “Government-issued IDs (standard trust framework)” as the option, which behind the scenes loads the official public keys of government issuers (for instance, all state DMVs, passport authorities, etc., depending on what frameworks you include). Next, in “Issuer Settings,” the company might not issue credentials themselves, so they could skip or say “Not applicable – we will only verify credentials.” In another scenario, a state DMV uses the tool: in Trust Settings they might also pick “Government-issued IDs” (because they need to verify out-of-state licenses, etc.), and in Issuer Settings they choose “Generate new certificate.” The tool generates an issuing certificate for that DMV. The private key is created in the browser and stored in the OS keychain (the UI would inform the admin: “Your digital certificate has been created and stored securely on this device. Please back it up safely.”). From then on, whenever the DMV official uses the cloud service to issue a mobile license, the system either prompts them to use the locally stored key (performing the signing locally) or routes the data to an on-prem signing service – achieving issuance without the cloud ever directly handling the secret key.
Finally, ensure that whatever approach you take aligns with the expected standards in this space. The trust model for mDLs and digital travel credentials is still evolving, but it is heavily based on X.509 PKI trust because of its maturity and deployment in government systems[13][14]. Even new decentralized approaches are being integrated in a way that complements PKI (for example, the European Digital Identity Wallet will likely use both PKI and DIDs). By using consistent terminology (certificate, issuer, trust list) and hiding complexity, you make the system accessible. And by enabling secure key storage (so that issuers manage their own keys, e.g. via keychains or vaults), you also increase security and trust in your platform – after all, no issuer wants to hand over their crown-jewel private keys. In fact, official guidelines for issuers explicitly recommend strict private key protection and management according to standards like NIST SP 800-57[8], which reinforces the idea that keys should be kept in secure modules and not spread around.
Conclusion: In summary, refer to PKI components with clear labels (e.g. “Digital Certificates” for X.509 certs, “Trusted Issuers” for trust anchors, “Signing Key” for private key). Provide a UI that simplifies the setup into choosing who to trust and providing one’s own credentials. Yes, it is feasible to avoid managing secrets by leveraging client-side storage (Apple Keychain, browser keystores, or external vaults) – this keeps the issuer’s private keys under their control, aligning with best practices for mDoc and passport issuance. By supporting both traditional certificate-based trust and DIDs in a unified way (treating both as configurable trusted issuers), you can cover both models without confusing the user. The end result should empower even non-technical business or travel personnel to configure their organization’s trust model with confidence, while your system handles the cryptographic heavy lifting behind the scenes.
Sources:
	•	AAMVA Mobile Driver’s License Implementation Guidelines – Trust Model and Digital Trust Service[1][2] (describes how mDL verifiers obtain and trust issuer public keys via a trust list)
	•	Keesing Journal – e-Passport Authentication (explains the ePassport chain of trust: DS certificate and need for the CSCA root key)
	•	MATTR Documentation – Chain of Trust for mDOC[3][4] (describes IACA root certificates and DSCs in mobile IDs)
	•	Paradym ID Blog – Trusted Entities with X.509 and DIDs[5][6] (example of configuring trusted issuer entries as either certificates or DIDs in a user interface)
	•	AAMVA Guidelines – Private Key Management[8] (emphasizes securing the issuer’s private key with best practices – underscoring the need to keep keys in secure modules under the issuer’s control)

[1] [2] [8] AAMVA mDL Implementation Guidelines
https://www.aamva.org/getmedia/bb4fee66-592d-4d39-813a-8fdfd910268a/MobileDLGuidelines1-5.pdf
[3] [4] [7] Overview | MATTR Learn
https://learn.mattr.global/docs/issuance/certificates/overview
[5] [6] [13] [14] Remote mDOC verification, Trusted Entities and X.509 certificates | Paradym
https://paradym.id/articles/mdoc-verification-trusted-entities-and-x509-certificates
[9] Storing CryptoKit Keys in the Keychain - Apple Developer
https://developer.apple.com/documentation/cryptokit/storing-cryptokit-keys-in-the-keychain
[10] public key - Where and how to store private keys in web applications ...
https://crypto.stackexchange.com/questions/35530/where-and-how-to-store-private-keys-in-web-applications-for-private-messaging-wi
[11] Khatim E-Passport Server - Codegic
https://www.codegic.com/khatim-e-passport-server/
[12] Everything you should know about certificates and PKI but are too ...
https://smallstep.com/blog/everything-pki/

.....
Yes — **the core approach (X.509-style chains, trust anchors, revocation, and “trust registries/lists”) absolutely carries over to EUDI**, but the **terminology and “who authenticates whom” expands** in ways that matter for your UI.

## What changes under EUDI (and why it still matches your direction)

### 1) “Trust model” is explicitly *multi-party* (Issuer *and* Verifier/Relying Party)

In airport/gov “gate” scenarios, EUDI expects the **Wallet to authenticate the verifier (the gate/kiosk/service)** *before* releasing attributes, using **certificates + trusted lists + revocation checks**. ([European Commission][1])

That maps cleanly to your “government security gate” mental model: the gate is not just a passive verifier — it presents **its own credentials** to the wallet.

### 2) “Certificate” is used broadly, but X.509 is first-class in practice

The ARF is careful: it uses “certificate” conceptually and says implementations **may use X.509 (RFC 5280) or other frameworks**. ([eudi.dev][2])
In parallel, the EUDI ecosystem work (e.g., EWC/LSP guidance) explicitly lists **“X.509 certificates based keys”** and **trust management via EU Trust Lists (ETSI TS 119 612)** as supported choices. 

So your stance — “use X.509-based trust and make DIDs conform to the same trust shape” — is aligned with how EUDI is being implemented.

### 3) EUDI adds *standard* EU trust-list plumbing you can hide behind a “profile”

The EU has an official **List Of Trusted Lists (LOTL)** mechanism and national trusted lists; these are the “roots distribution + status signaling” layer for trust services. ([European Commission][3])
This is exactly the sort of complexity your UI should absorb.

## EUDI terminology you’ll want in your product UI

Use EUDI/eIDAS words (business folks will recognize these faster than “PKI”):

* **Trust Anchor** (root) / **Trust Store**
* **Trusted List (TL)** and **List Of Trusted Lists (LOTL)** ([European Commission][3])
* **TSP / QTSP** (Trust Service Provider / Qualified Trust Service Provider)
* **Wallet-Relying Party (RP)** and **Registrar**
* **RP Access Certificate** (used to authenticate to wallets)
* **RP Registration Certificate** (may be required by Member States; used to enforce what attributes an RP is allowed to request) ([EUR-Lex][4])
* **PID Provider / (Q)EAA Provider** (issuer-side roles in ARF)

If you also support DID/VC trust chains in the EUDI world, EBSI’s language shows the pattern EUDI expects: **a “trusted issuer registry” + accreditation chain** (it’s the same *shape* as PKI, just different artifacts). ([hub.ebsi.eu][5])

## The key UI implication for your org setup wizard

Under EUDI, an org typically needs **two** configurations (even if they only “feel” like one):

1. **Verify (Gate/RP side):**

   * “How do we authenticate *relying parties/verifiers*?” (RP access certs, optional RP registration certs, and trust anchors) ([EUR-Lex][4])

2. **Issue (Issuer side):**

   * “What cert chain do we use to sign/issue, and what trust profile do others use to validate us?”

Your “hide PKI” move becomes: **choose a Trust Profile**:

* “**EUDI / eIDAS (EU Trust Lists)**” (you fetch/maintain LOTL+TL behind the scenes)
* “**Custom X.509 (Upload roots / pin CA)**”
* “**EBSI-compatible**” (if you support it, you still present it as “issuer registry + accreditation chain”)

## About storing PEM/private keys in Keychain / Chrome / password managers (in EUDI context)

For EUDI-grade assurance, the expectation trends toward:

* **Keys protected by hardware-backed storage** (HSM/KMS/QSCD/secure elements), and
* **Certificate policies + revocation + auditability** (because relying party access certs and registration certs have governance requirements). ([EUR-Lex][4])

So:

* **Apple Keychain / OS keystores** can be a reasonable *BYOK interface* (especially if you do client-side signing), but
* **Password managers as “issuer signing key storage”** usually won’t meet the governance/assurance story you’ll want for EUDI-like deployments.
* The clean SaaS pattern is: **“Bring Your Own Key” via customer-controlled HSM/KMS or remote signer**, so *you* never hold private keys, but you still work with X.509 chains and policies.

If you tell me whether your org users are primarily **(a) issuers, (b) relying parties/gates, or (c) both**, I can suggest the simplest 3–5 screen wizard that matches EUDI terminology and keeps the scary PKI bits off-screen.

[1]: https://ec.europa.eu/digital-building-blocks/sites/spaces/EUDIGITALIDENTITYWALLET/pages/930451396/Identification%2Bin%2Bproximity%2Bscenarios "Identification in proximity scenarios - EU Digital Identity Wallet - "
[2]: https://eudi.dev/1.4.0/arf/ "Architecture and reference framework - EUDI Wallet"
[3]: https://ec.europa.eu/digital-building-blocks/sites/display/DIGITAL/eSignature%2BList%2Bof%2BTrusted%2BLists?utm_source=chatgpt.com "eSignature List of Trusted Lists - European Commission"
[4]: https://eur-lex.europa.eu/legal-content/EN/TXT/PDF/?uri=OJ%3AL_202500848 "Commission Implementing Regulation (EU) 2025/848 of 6 May 2025 laying down rules for the application of Regulation (EU) No 910/2014 of the European Parliament and of the Council as regards the registration of wallet-relying parties"
[5]: https://hub.ebsi.eu/vc-framework/trust-model/issuer-trust-model-v3 "Issuer Trust Model | EBSI hub"

.....
Yes — your approach **still holds for EUDI**, but you need to model **two certificate “tracks”** and a **trust-list source** that’s very specific to the EU ecosystem.

## What EUDI adds (and what that means for your UI)

### 1) Relying Parties (your “gate/verifier”) must authenticate *to the wallet*

In the EUDI ARF, a Relying Party includes an **access certificate** in its request and signs the request; the wallet validates the certificate chain up to a **trust anchor from a Trusted List**, and checks revocation. ([European Digital Identity Wallet][1])

So your org setup can’t just be “trust these issuers.” It must also be “here’s **our** certificate so wallets will talk to us.”

### 2) “Registration certificate” (or Registrar lookup) is the *authorization scope*

EUDI distinguishes:

* **Access certificate** = proves *who you are* (authentication)
* **Registration certificate** (if used) = proves *what you’re allowed to request / do*; otherwise the wallet queries the **Registrar** using data referenced from the access certificate. ([European Digital Identity Wallet][1])

That’s perfect for non-technical UI: “Identity” vs “Permissions.”

### 3) EU trust distribution uses Trusted Lists + LOTL

For eIDAS/EUDI-adjacent trust, the EU uses **Trusted Lists (TLs)** and a central **LOTL** (List Of Trusted Lists) that points to Member State TLs and includes certs used to verify them. ([European Commission][2])

So your verifier trust model can be a simple toggle: **“Use EU Trusted Lists (recommended)”** vs **“Custom trust anchors.”**

---

## Map your “passport / mdoc” mental model to EUDI terms

| Your current concept   | Passport/mDL analogy  | EUDI term                                                                                |
| ---------------------- | --------------------- | ---------------------------------------------------------------------------------------- |
| Trust anchor           | CSCA / IACA root      | Trust anchor from Trusted List ([European Digital Identity Wallet][1])                   |
| Trust list             | ICAO PKD / AAMVA list | EU Trusted Lists + LOTL ([European Commission][2])                                       |
| Gate proves identity   | Terminal certificate  | RP **Access Certificate** ([European Digital Identity Wallet][1])                        |
| “Allowed to ask for X” | Authorization policy  | **Registration certificate** or Registrar lookup ([European Digital Identity Wallet][1]) |

---

## A clean 5-screen org setup wizard (for “Both”)

### Screen 1 — Choose trust profile (hide PKI words)

**“Where will you operate?”**

* ✅ **EU Digital Identity Wallet (EUDI / eIDAS)**
* (optional) US mDL, ICAO ePassport, Custom X.509

Behind the scenes this chooses default trust-list sources and validation rules.

### Screen 2 — “Your Verifier Identity” (Relying Party)

Plain-language framing:

* **“How wallets recognize your organization”**
  Inputs:
* Upload/select **RP Access Certificate** (public cert + chain)
* Choose **where the private key lives** (see key section below)
  Optional:
* Upload **RP Registration Certificate** if you have it (otherwise “we’ll use Registrar lookup”) ([European Digital Identity Wallet][1])

### Screen 3 — “Your Issuer Identity” (Attestation/PID Provider)

Plain-language framing:

* **“How wallets recognize you as an issuer”**
  Inputs:
* Upload/select **Issuer Access Certificate** (for authenticating to wallets during issuance flows) ([European Digital Identity Wallet][1])
* Upload/define **Issuing Signing Certificate** (the key that signs the actual mdoc/attestation payloads)

  * Keep this visually separate from the access cert. Users can grasp: “one key to connect, one key to sign credentials.”

### Screen 4 — “What you trust”

For EUDI profile:

* Toggle: **Use EU Trusted Lists (LOTL + Member State TLs)** ([European Commission][2])
* Optional filter: “Only trust issuers from these Member States”
* Advanced (hidden): add extra roots / pin a CA / offline bundle

### Screen 5 — Health check

Show green checks for:

* “Your RP access cert chains to a trusted anchor”
* “Revocation checks configured”
* “Registration scope available (cert or Registrar)”
* “Issuer signing key reachable”

This is where you make business folks feel safe.

---

## “We don’t manage customer secrets” — the practical key-storage answer

**Storing PEM in a password manager** is fine for *backup*, but it’s usually **not a usable signing mechanism** (password managers don’t expose “sign this payload with that key” APIs in a way you can rely on for production).

If you want **true BYOK (bring your own key)**, these are the three patterns that work:

### Option A — Customer-managed KMS/HSM (best for “government gate” vibe)

* Customer keeps keys in AWS KMS / Azure Key Vault / GCP KMS / on-prem HSM.
* Your cloud stores only: **key identifier + cert chain**.
* Your service requests **remote sign** operations.

### Option B — Customer runs a “Signing Agent” (simple, very controllable)

* A small local service (desktop or server) that:

  * reads keys from Apple Keychain / Windows cert store / PKCS#11 token
  * exposes a locked-down signing endpoint to your cloud (mTLS)
* Your cloud never sees the private key — just signatures.

### Option C — Browser/device keystore (OK for demos, not ideal for ops)

* WebCrypto can generate non-extractable keys, but cross-device, auditing, and ops are messy.
* Good for prototypes; risky for regulated deployments.

**My recommendation for your product:** ship **A + B** as first-class and treat C as “demo/dev only.”

---

## What to call “PKI” in your UI

Don’t say PKI. Use:

* **Trust Profile**
* **Trusted Lists**
* **Organization Certificates**
* **Signing Key Location** (“Your key stays with you”)

Under the hood, it’s still X.509 chain validation and trust anchors — which EUDI explicitly relies on for authenticating relying parties and providers to wallets using access certificates + trusted lists. ([European Digital Identity Wallet][1])

---

[1]: https://eu-digital-identity-wallet.github.io/eudi-doc-architecture-and-reference-framework/2.4.0/architecture-and-reference-framework-main/ "European Digital Identity Wallet - European Digital Identity"
[2]: https://ec.europa.eu/digital-building-blocks/sites/spaces/DIGITAL/pages/880312429/eSignature%2BFAQ?utm_source=chatgpt.com "eSignature FAQ - European Commission"
....

Got it — here’s **exact wizard UI copy** (headings, labels, helper text, buttons, errors) for a non-technical org onboarding flow where they do **both**: verify (gate/RP) and issue.

---

## Org Setup Wizard Copy (EUDI profile, Issuer + Verifier)

### Global wizard chrome

* **Title:** Set up your organization
* **Subtitle:** Connect your certificates and trust settings so you can **verify** and **issue** digital documents.
* **Step indicator:** Step 1 of 5
* **Primary buttons:** `Continue` / `Back`
* **Secondary:** `Save and exit`
* **Inline help link:** `What am I setting up?` (opens short glossary: “certificate”, “trusted list”, “signing key”)

---

## Step 1 — Choose where you operate

**Header:** Choose your trust profile
**Body:** This sets the defaults for trusted lists, certificate checks, and wallet compatibility.

**Options (cards):**

1. **EU Digital Identity Wallet (EUDI)**

   * **Description:** Use EU trusted lists and wallet-compatible certificates.
   * **Badge:** Recommended for Europe

2. **Custom X.509 (Advanced)**

   * **Description:** You provide the trusted roots and validation rules.

**Footer hint:** You can change this later in Settings.

**Buttons:**

* Primary: `Use EUDI profile`
* Secondary: `Choose Custom`

**If EUDI selected, show confirmation line:**

* ✅ “EUDI profile selected. We’ll guide you through the certificates wallets expect.”

---

## Step 2 — Verifier identity (Gate / Relying Party)

**Header:** Set up your verifier identity
**Body:** Wallets need to recognize your organization **before** they share any data.

### Section A — Relying Party access certificate

**Card title:** Verifier certificate (Access Certificate)
**Helper text:** This is the certificate your gate / app presents to the wallet to prove who you are.

**Field:**

* **Label:** Upload certificate file
* **Accepts:** `.pem .cer .crt .der .p7b`
* **Button:** `Upload certificate`
* **Optional link:** `I have a certificate chain file` (tooltip: “A chain may include intermediate certificates. We’ll detect it.”)

**Auto-detected display (after upload):**

* **Organization name:** `{Parsed Subject CN / O}`
* **Issued by:** `{Issuer}`
* **Valid:** `{Start date} – {End date}`
* **Status pill examples:** `Valid` / `Expiring soon` / `Not valid`

### Section B — How signing is performed (private key location)

**Card title:** Where your verifier key lives
**Helper text:** Your private key stays with you. We only need a way to request a signature when you verify.

**Radio options (with plain-language descriptions):**

1. **Customer Key Vault (recommended)**

   * “Use AWS KMS / Azure Key Vault / GCP KMS / HSM”
2. **Signing Agent (recommended)**

   * “Run a small service on your network that signs requests”
3. **This device / browser (demo only)**

   * “Works for trials. Not recommended for production gates”
4. **Upload encrypted key (advanced)**

   * “We store an encrypted key file. You provide the unlock secret at runtime”
5. **Managed by our cloud (not recommended)**

   * “We hold the key for you. Choose only if you understand the risk”

**If “Customer Key Vault” selected, show:**

* **Label:** Key reference / Key ID
* **Placeholder:** `e.g., arn:aws:kms:... or https://vault...`
* **Label:** Signing algorithm
* **Dropdown values:** `RS256 (default)` / `ES256` / `ES384`
* **Helper text:** “Leave default unless your certificate requires a specific algorithm.”

**If “Signing Agent” selected, show:**

* **Label:** Agent URL
* **Placeholder:** `https://signer.yourorg.com`
* **Label:** Authentication
* **Dropdown:** `mTLS (recommended)` / `API token`
* **Button:** `Test connection`

### Section C — Optional: registration / permissions

**Card title:** Verifier permissions (Registration)
**Helper text:** Some ecosystems require a separate proof of what you’re allowed to request.

**Toggle:** `I have a registration certificate`

* If on:

  * **Upload:** `.pem .cer .crt .der .p7b`
  * **Label:** Upload registration certificate
* If off:

  * **Info box:** “No problem. We’ll use registry/registrar checks if required by the wallet ecosystem.”

**Buttons:**

* Primary: `Continue`
* Secondary: `Skip verifier setup` (hidden behind “More options”, since user said both)

**Inline warnings / errors copy:**

* **“We couldn’t read this file.”** Try a different format (PEM/DER) or include the full chain.
* **“Certificate is expired.”** Upload a valid certificate or renew it with your CA.
* **“Chain incomplete.”** We’re missing intermediate certificates. Upload the full chain or a `.p7b`.
* **“Private key not reachable.”** We can’t reach your Key Vault / Signing Agent. Fix the connection and try again.
* **“This certificate can’t be used for this purpose.”** The certificate doesn’t include the required usage for relying party access.

---

## Step 3 — Issuer identity (Issuing organization)

**Header:** Set up your issuer identity
**Body:** This is how wallets and verifiers trust credentials you issue.

### Section A — Issuer access certificate (connect/auth)

**Card title:** Issuer certificate (Access Certificate)
**Helper text:** Used to authenticate your issuer service during wallet interactions.

**Field:**

* **Label:** Upload issuer access certificate
* **Accepts:** `.pem .cer .crt .der .p7b`
* **Button:** `Upload certificate`

**After upload show same parsed summary:**

* Organization / Issuer / Valid dates / Status

### Section B — Credential signing key (signs the actual documents)

**Card title:** Credential signing key
**Helper text:** This key signs the credentials themselves. It should be protected like a “company seal.”

**Choice (radio):**

1. **Use Customer Key Vault / HSM (recommended)**
2. **Use Signing Agent (recommended)**
3. **Upload encrypted key (advanced)**
4. **Managed by our cloud (not recommended)**

**Field labels mirror Step 2, but with issuer wording:**

* **Label:** Signing key reference / Key ID
* **Label:** Signing certificate (public)

  * Upload the public cert that matches the signing key
* **Button:** `Test signing`

**Test signing success message:**

* ✅ “Signing test succeeded. We can produce valid signatures with your key.”

**Buttons:**

* Primary: `Continue`

**Errors:**

* **“Signing certificate doesn’t match the key.”** The public certificate and the signing key don’t pair.
* **“We can’t sign with this key.”** Check permissions on your Key Vault / Agent and try again.

---

## Step 4 — What your org trusts (verification policy)

**Header:** Choose what you trust
**Body:** This controls which issuers and document types your organization will accept.

### Section A — Trusted source

**Card title:** Trusted list source
**Options:**

1. **Use EU Trusted Lists (recommended)**

   * Helper: “We automatically keep trust anchors up to date.”
2. **Add trusted issuers manually**

   * Helper: “Upload issuer certificates you want to accept.”

### Section B — Scope filters (simple business controls)

**Card title:** Limit what you accept
**Toggles:**

* `Only accept credentials from selected countries`

  * Picker label: `Allowed countries`
* `Only accept selected document types`

  * Checkboxes:

    * `Personal ID (PID)`
    * `Mobile Driver’s License (mDL)`
    * `Passport-derived / travel document`
    * `Other credentials`

### Section C — Revocation and freshness (keep it simple)

**Card title:** Safety checks
**Toggles (default ON):**

* ✅ `Check certificate revocation`
* ✅ `Require valid time (not expired / not before)`
* ✅ `Block unknown issuers`

**Tooltip copy:**

* “Revocation means a certificate was cancelled before its expiration date.”

**Buttons:**

* Primary: `Continue`

**Errors:**

* **“Trusted list unavailable.”** We can’t fetch the EU trusted list right now. Try again or switch to manual upload.
* **“No trusted issuers selected.”** Add at least one trusted source to verify credentials.

---

## Step 5 — Review and finalize (health check)

**Header:** Ready to activate
**Body:** We’ll run checks to ensure your org can verify and issue safely.

### Checklist (with green/yellow/red icons)

**Verifier (Gate/RP)**

* `Verifier access certificate loaded`
* `Verifier signing configured (Key Vault / Agent / Device)`
* `Verifier permissions confirmed (registration or registry lookup)`

**Issuer**

* `Issuer access certificate loaded`
* `Credential signing key reachable`
* `Signing certificate attached`

**Trust**

* `Trusted list configured`
* `Revocation checks enabled`

### Results messaging

* ✅ **All checks passed**

  * Body: “Your organization is ready to verify and issue.”
  * Button: `Activate organization`

* ⚠️ **Some checks need attention**

  * Body: “You can activate now, but these items may break verification or issuance.”
  * Button: `Review issues`

### Common issue copy

* **“Certificate expires soon (in X days).”** Renew to avoid downtime.
* **“Trust list sync is paused.”** Verification may fail until trust anchors are updated.
* **“Signing agent unreachable.”** Issuance/verification will fail until it’s back online.

---

## Microcopy glossary (tooltip-ready)

* **Certificate:** “A digital ID for an organization or system.”
* **Trusted list:** “An official list of organizations we accept as trusted.”
* **Signing key:** “A secret key that creates tamper-proof signatures. It must stay private.”
* **Chain:** “Supporting certificates that connect your certificate to a trusted root.”

---


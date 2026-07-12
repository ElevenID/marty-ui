# Beta UI/UX Complexity Review Against MIP

> Historical review baseline. The MIP 0.2 implementation completed on 2026-07-11 addresses the primary flow-contract, setup-readiness, Policy Set, IA, physical issuance, and Flow Instance findings. See `docs/beta-ui-ux-decision-tree.md` for current source behavior and residual opportunities; live beta may lag until deployment.

This review builds on `docs/beta-ui-ux-decision-tree.md` and compares the beta experience with the MIP protocol model in `../marty-protocol/SPECIFICATION.md`.

Assumption: "MIP" here means the local Marty Identity Protocol specification, not Microsoft Information Protection.

## Executive Summary

The main UX issue is that beta exposes too many protocol primitives before the user has chosen a goal. MIP has a clear object model, but the product experience should start with intent:

- I want to issue a credential.
- I want to verify a credential.
- I want to collect an application, approve it, then issue.
- I want to revoke or renew credentials.
- I want to connect a deployment surface such as API, QR, wallet, Canvas, or OpenBadges.

Today the console mostly asks users to walk a universal setup ladder:

```text
Trust -> Credential Template -> Presentation Policy -> Deployment Profile -> Flow
```

That ladder is too linear and issuer-biased. It makes verification feel dependent on issuance setup, hides Presentation Policies from the main sidebar, and labels Flows as "Issuance Flows" even though MIP makes Flow Definitions central to issuance, verification, renewal, revocation, and application approval.

The highest-impact UX fix is to make the first console question: "What are you trying to do?" Then the UI can assemble the required MIP objects behind the scenes and expose the dependency graph as advanced detail.

## Live Beta Notes

Live checks during this review found:

- The beta host is `https://beta.elevenidllc.com`.
- `https://beta.elevenidllc.com/.well-known/mip-configuration` returns HTTP 200 with `mip_version: 0.1` and `api_base_url: https://beta.elevenidllc.com/v1`.
- That same MIP configuration reports `active_compliance_profiles: []`. If this is a production-like beta, the dashboard should surface that as a setup blocker. If it is intentional for a sandbox, the UI should say so explicitly.
- The live sitemap has 474 raw URL entries, but 244 unique normalized paths. The duplication appears to come from slash/canonical variants. The previous decision tree correctly used normalized paths.
- The sitemap still exposes `/test-harness`.
- The sitemap includes duplicate tag concepts such as `/blog/tag/bbs%2B` and `/blog/tag/bbs+`, and `/blog/tag/privacy%20%26%20disclosure` and `/blog/tag/privacy%20&%20disclosure`.
- `/verification` returns the SPA shell at the HTTP layer, but there is no explicit public React route for it in the decision tree. Client-side routing falls through instead of landing on a meaningful verification page.

## MIP Dependency Model

The MIP object graph is not a single universal setup sequence. It is a set of reusable primitives that combine differently by intent.

```text
Organization
  -> Compliance Profile
  -> Trust Profile
       -> optional Revocation Profile
  -> Credential Template
       -> Compliance Profile
       -> optional Application Template
       -> optional Trust Profile
       -> optional Revocation Profile
  -> Presentation Policy
       -> optional/required Trust Profile depending on policy design
  -> Deployment Profile
       -> Trust Profile
       -> Presentation Policies
  -> Flow Definition
       -> Credential Template for issuance/renewal/revocation
       -> Presentation Policy for verification
       -> Application Template for application approval issuance
       -> Deployment Profiles where applicable
  -> Flow Instance
       -> one runtime execution: one issuance, verification, renewal, etc.
```

The UX dependency tree should therefore branch by intent:

```text
Start
  -> Issue a credential
       -> Compliance Profile
       -> Issuer identity and signing/KMS readiness
       -> Trust Profile
       -> Credential Template
       -> Flow Definition
       -> Delivery or Deployment Profile

  -> Verify a credential
       -> Compliance Profile
       -> Trust Profile
       -> Presentation Policy
       -> Flow Definition
       -> Deployment Profile or API key

  -> Collect application then issue
       -> Application Template
       -> Approval PolicySet
       -> Compliance Profile
       -> Credential Template
       -> application_approval_issuance Flow Definition

  -> Revoke or renew
       -> Credential Template
       -> Revocation Profile
       -> credential_revocation or credential_renewal Flow Definition

  -> Operate live activity
       -> Flow Instances as the primary runtime view
       -> Issued credentials, applications, and verification sessions as filtered views
```

## Complexity We Can Improve

### 1. Public IA Has Too Many Equivalent Paths

The public site has 244 unique normalized paths and 474 raw sitemap entries. That is a lot for a beta product whose main conversion paths should be simple. The biggest complexity is not just quantity; it is duplication and unclear path intent.

Observed issues:

- Slash/canonical variants inflate the raw sitemap.
- Tag variants duplicate the same meaning.
- `/test-harness` is present in the public sitemap.
- Product CTAs link to `/verification`, `/issuance`, and `/docs/quickstart`, but those are not explicit public routes in the React tree.
- There are many overlapping educational pages around identity, verification, issuance, protocols, architecture, resources, and blog topics.

UX risk:

- Visitors have many ways to enter the same concept but no obvious primary next step.
- Search results and shared links can land on thin or fallback pages.
- "Verify" and "Issue" CTAs can look broken even when the server returns HTTP 200.

Recommended change:

- Add explicit `/verification`, `/issuance`, and `/docs/quickstart` pages or redirect them to canonical destinations.
- Remove `/test-harness` from sitemap generation.
- Canonicalize tag routes so encoded and decoded variants collapse to one URL.
- Pick one primary learning hub for each product motion: issue, verify, govern, integrate.

### 2. Console Navigation Hides A Core MIP Primitive

MIP names five core primitives as implementation essentials: Trust Profile, Credential Template, Presentation Policy, Deployment Profile, and Flow.

Current console IA partially hides that model:

- The sidebar Design group mentions Presentation Policies in description copy, but does not list them as a first-class nav item.
- Compliance Profiles are nested under Credential Templates, even though MIP says compliance should abstract credential format complexity for users.
- The Deploy group labels Flow Definitions as "Issuance Flows", even though Flow Definitions also represent verification, renewal, revocation, and application approval.
- Audit links exist in multiple components as `/console/audit`, while the source route table uses `/console/org/audit`.

UX risk:

- A verifier-only customer can struggle to find the policy object that matters most.
- Users learn that "Flow" means issuance, which contradicts MIP.
- Compliance looks like a template detail rather than a governing abstraction.
- Audit links can route inconsistently.

Recommended change:

Use a console IA closer to:

```text
Build
  -> Use Cases / Flows
  -> Trust Profiles
  -> Credential Templates
  -> Presentation Policies
  -> Deployment Profiles

Govern
  -> Compliance Profiles
  -> Revocation Profiles
  -> Policy Sets
  -> Roles and Permissions

Operate
  -> Runs / Flow Instances
  -> Applications
  -> Issued Credentials
  -> Verification Sessions

Connect
  -> API Keys
  -> Webhooks
  -> Wallet Registry
  -> Canvas / OpenBadges

Org
  -> Team
  -> Settings
  -> Billing
  -> Audit
```

### 3. Setup Readiness Is Too Linear

The current dashboard rules encode a single setup order:

```text
trust -> template -> policy -> deployment -> flow
```

That is understandable from an implementation perspective, but it does not match how MIP flows branch.

What may be wrong:

- Trust Profile creation is blocked by KMS/issuer identity readiness. That is correct for issuance trust in many cases, but not for verifier trust profiles that point at external trust lists, root CAs, or pinned issuers.
- Presentation Policy readiness depends on Credential Template readiness. A verifier-only use case should not require a Credential Template.
- Compliance Profile readiness is not explicit in the setup ladder, even though MIP makes Compliance Profile the abstraction that hides credential format complexity.
- Deployment Profile is always before Flow, but API-only or stateless policy evaluation may not need the same deployment mental model.

Recommended change:

Replace the universal setup ladder with intent-specific readiness:

```text
Verify
  Compliance Profile -> Trust Profile -> Presentation Policy -> Verification Flow -> Deployment/API key

Issue
  Compliance Profile -> Issuer identity/KMS -> Trust Profile -> Credential Template -> Issuance Flow -> Delivery

Application approval then issue
  Application Template -> Approval PolicySet -> Credential Template -> application_approval_issuance Flow

Revoke/Renew
  Credential Template -> Revocation Profile -> Revocation/Renewal Flow
```

### 4. Flow Builder Uses Local Aliases Instead Of MIP Flow Types

MIP defines normative FlowType values such as:

- `oid4vci_pre_authorized`
- `oid4vci_authorization_code`
- `mdl_issuance`
- `application_approval_issuance`
- `credential_renewal`
- `credential_revocation`
- `oid4vp_presentation`
- `mdl_presentation`

The backend accepts local UI aliases such as `issuance`, `issuance_oid4vci`, and `verification`, then maps them to protocol values. That is useful for compatibility, but the UI currently uses those aliases as first-class state and payload values.

UX/protocol risk:

- Users and tests can learn a non-MIP vocabulary.
- Integrators may copy UI terms into API calls.
- Flow definitions become harder to compare with the spec.

Recommended change:

- Keep friendly card labels, but store and submit normative MIP values.
- Keep backend aliases only as migration compatibility.
- Rename "Issuance Flows" to "Flows" or "Flow Definitions".
- Show a small protocol label in the flow card, e.g. `OID4VP presentation` or `OID4VCI pre-authorized issuance`.

### 5. Freeform Flow Step Editing Can Create Non-MIP Flows

MIP defines standard step sequences for each FlowType. The current UI includes a flow step editor with presets and editable step sequences. Some presets use legacy endpoint strings such as `/api/issuance/token` and `/api/issuance/credential`, while MIP's canonical API surface is `/v1/...`.

UX/protocol risk:

- A user can reorder required protocol steps into a flow that looks valid in the UI but is not MIP-conformant.
- Protocol complexity leaks into the wizard before the user has a working mental model.
- Legacy `/api` endpoint strings undermine the `/v1` protocol story.

Recommended change:

- Replace arbitrary reorder with a locked "MIP sequence preview" for normative FlowTypes.
- Allow extension hooks in constrained slots: before flow, after approval, after issuance, after verification, on failure.
- Reserve fully custom step editing for an advanced mode with explicit validation.
- Display canonical `/v1` endpoints where endpoint examples are needed.

### 6. Runtime Operation Is Fragmented

MIP defines a Flow Instance as one runtime execution of one atomic identity operation. The console currently separates operation into Applications, Issued Credentials, Flow Instances, and Verification Sessions.

That separation can be useful, but the user needs one primary runtime spine.

Recommended change:

- Rename Flow Instances to "Runs" or "Activity" for normal users.
- Let Applications, Issued Credentials, and Verification Sessions be filtered views of Runs.
- Cross-link every credential, application, and verification session back to its Flow Instance audit trail.
- Put the audit trail one click away from any runtime object.

### 7. Auth And Proxy Namespaces Need A Single Story

The decision tree found multiple auth/callback paths and proxy namespaces. `/auth/*` can be proxy-intercepted while `/console/auth/callback` remains a React route. Public `/auth/callback` exists in source, but may not behave consistently on beta depending on proxy order.

Recommended change:

- Standardize on one console callback route, preferably `/console/auth/callback`.
- Remove or explicitly redirect unused callback paths.
- Document which namespaces belong to React, the gateway, Keycloak, and public wallet endpoints.
- Keep public marketing CTAs away from proxy-controlled namespaces.

## MIP Comparison Table

| MIP expectation | Current beta signal | UX risk | Recommendation |
| --- | --- | --- | --- |
| Flows are automatable and central across issuance, verification, renewal, revocation, and approval. | Flow nav is labeled "Issuance Flows". | Users think flows are only for issuance. | Rename to "Flows" and start setup from use case intent. |
| Presentation Policies define what must be shown for verification. | Route exists, quick action exists, but sidebar omits it as a first-class item. | Verifier-only setup feels hidden. | Add Presentation Policies to Build nav and verifier onboarding. |
| Compliance Profiles hide credential format complexity. | Compliance Profiles are nested under Credential Templates. | Users may think compliance is a template detail. | Put Compliance Profiles in Govern or early setup choice. |
| Policies are data, not hardcoded behavior. | Flow step presets and legacy endpoint strings leak behavior into the UI. | Users can configure brittle or non-conformant flows. | Use locked protocol sequences plus validated hooks. |
| Trust must be explicit. | Trust setup appears tied to issuer identity/KMS globally. | Verifier trust sources are harder to model. | Split issuer trust readiness from verifier trust readiness. |
| Deployment behavior is declarative. | Deployment is a generic setup dependency for all flows. | API-only verification and stateless evaluation can feel overbuilt. | Ask "where will this run?" and branch by QR/API/device/embed. |
| Authorization is deny-by-default and auditable. | Policy Sets are not prominent in the IA. | Users do not see where advanced authorization lives. | Add Policy Sets under Govern with clear RBAC vs Cedar positioning. |
| Canonical API prefix is `/v1/`. | Flow UI examples include `/api/issuance/*`. | Developers copy stale endpoint paths. | Replace examples with `/v1/issuance/*`. |

## Recommended UX Direction

### Primary Console Flow

The first-run experience should be intent-first:

```text
What are you trying to do?
  -> Issue credentials
  -> Verify credentials
  -> Collect applications and approve issuance
  -> Revoke or renew credentials
  -> Connect an integration
```

After intent selection, the wizard should ask for human concepts first:

- What standard or ecosystem are you working in?
- Who do you trust?
- What must be issued or shown?
- Where will this run?
- What should happen when it succeeds or fails?

Then it should create or bind the MIP objects:

- Compliance Profile
- Trust Profile
- Credential Template
- Presentation Policy
- Application Template
- Deployment Profile
- Flow Definition
- PolicySet where needed

The MIP object map should remain visible as an advanced review panel, not as the primary mental model.

### Public Site Flow

The public site should support three obvious paths:

```text
Learn
  -> What is verifiable identity?
  -> How MIP works
  -> Standards and ecosystems

Build
  -> Issue credentials
  -> Verify credentials
  -> API quickstart

Trust
  -> Compliance
  -> Privacy and disclosure
  -> Architecture and auditability
```

Everything else should ladder into those paths rather than compete with them.

## Priority List

### P0: Remove Confusion That Looks Broken

- Add or redirect `/verification`, `/issuance`, and `/docs/quickstart`.
- Add Presentation Policies to the sidebar.
- Fix `/console/audit` links to `/console/org/audit` or add a compatibility redirect.
- Rename "Issuance Flows" to "Flows".
- Remove `/test-harness` from the sitemap.

### P1: Align The Console With MIP

- Store and submit normative MIP FlowType values from the UI.
- Split setup readiness into intent-specific dependency trees.
- Add Compliance Profile readiness to first-run setup.
- Replace freeform normative flow step editing with locked protocol sequences and validated hooks.
- Replace `/api/issuance/*` examples with `/v1/issuance/*`.

### P2: Improve Long-Term Product Shape

- Reorganize console IA into Build, Govern, Operate, Connect, Org.
- Make Flow Instances/Runs the runtime spine.
- Canonicalize tag URLs and slash variants in sitemap output.
- Expose Policy Sets as advanced governance, clearly separated from basic org RBAC.
- Add a "MIP object map" review panel to setup wizards for advanced users.

## Suggested First PR Sequence

1. IA and route cleanup:
   - Add Presentation Policies to nav.
   - Rename Issuance Flows.
   - Fix audit links.
   - Add redirects or explicit pages for the three public CTA paths.
   - Remove test harness from sitemap.

2. Flow type normalization:
   - Change UI card values to normative FlowType values.
   - Keep labels user-friendly.
   - Update tests to expect MIP values.
   - Leave backend aliases for backwards compatibility.

3. Setup readiness split:
   - Replace `SETUP_ORDER` with an intent map.
   - Add separate Verify, Issue, Application Approval, Renewal, and Revocation readiness checks.
   - Add Compliance Profile as an explicit requirement where MIP requires it.

4. Flow wizard simplification:
   - Show standard MIP step sequence based on FlowType.
   - Add validated hook slots.
   - Move arbitrary custom sequences into advanced mode.

## Bottom Line

The product is close to MIP structurally, but the UX is making users manage the structure too early. MIP should be the system of record behind the experience. The foreground experience should be: choose an identity job, answer a small number of domain questions, review the generated MIP object map, then run and audit the flow.

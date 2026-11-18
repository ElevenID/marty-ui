/**
 * Issuance Protocol Registry
 *
 * Central registry of supported credential-issuance protocols.
 * Each entry describes how to generate an offer and which React component
 * renders the resulting invite (QR code, deep-link, etc.).
 *
 * To add a new protocol:
 *   1. Create a display component (see OID4VCIInviteDisplay for reference).
 *   2. Add an entry to ISSUANCE_PROTOCOLS below.
 *   3. The IssuingSection component picks it up automatically.
 */

import { issueOrganizationApplication } from '../services/applicantApi';
import OID4VCIInviteDisplay from '../components/issuance/OID4VCIInviteDisplay';

// ── Protocol definitions ────────────────────────────────────────────────────

const ISSUANCE_PROTOCOLS = [
  {
    /** Unique identifier persisted nowhere — used only as a runtime key. */
    id: 'oid4vci',
    /** Human-readable label for the dropdown. */
    label: 'OID4VCI',
    /** Short description shown under the selector. */
    description: 'OpenID for Verifiable Credential Issuance',
    /**
     * MUI icon name imported lazily by IssuingSection.
     * Keeping it as a string avoids importing every icon in this config file.
     */
    icon: 'QrCode2',
    /**
     * Generate (or refresh) an issuance offer for the given application.
     * Must return the offer payload expected by the protocol's InviteDisplay.
     *
     * @param {string} applicationId
     * @returns {Promise<Object>}
     */
    // This registry is used by the organization reviewer, not the applicant.
    // Keep the organization boundary explicit; never fall back to self-claim.
    generateOffer: async (applicationId, { organizationId } = {}) => {
      const data = await issueOrganizationApplication(organizationId, applicationId);
      return {
        ...data,
        offer_url: data.credential_offer_uri || data.offer_url || null,
        expires_at: data.offer_expires_at || data.expires_at || null,
        // The Applicant response status describes the application, not the QR
        // invitation. Expiry is evaluated separately by the invite display.
        status: data.credential_offer_uri || data.offer_url
          || Object.values(data.credential_offer_uris || {}).some((uri) => typeof uri === 'string' && uri.trim())
          ? 'active' : 'pending',
      };
    },
    /**
     * React component that renders the invite once the offer is available.
     * Receives props: { offerData, onRegenerate, loading }
     */
    InviteDisplay: OID4VCIInviteDisplay,
  },

  // ── Future protocols go here ──────────────────────────────────────────
  // {
  //   id: 'oid4vp',
  //   label: 'OID4VP',
  //   description: 'OpenID for Verifiable Presentations',
  //   icon: 'Verified',
  //   generateOffer: (applicationId) => generateVPRequest(applicationId),
  //   InviteDisplay: OID4VPInviteDisplay,
  // },
];

// ── Public helpers ──────────────────────────────────────────────────────────

/**
 * Return all registered issuance protocols.
 * @returns {Array<Object>}
 */
export const getAvailableProtocols = () => ISSUANCE_PROTOCOLS;

/**
 * Look up a single protocol by id.
 * @param {string} id
 * @returns {Object|undefined}
 */
export const getProtocol = (id) => ISSUANCE_PROTOCOLS.find((p) => p.id === id);

export default ISSUANCE_PROTOCOLS;

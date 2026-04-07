/**
 * Interaction tests: Verification Journey
 *
 * Exercises the verifier's presentation request → verification flow,
 * and the issuance metrics dashboard that tracks issued credentials.
 *
 *   Verifier:  create request → holder presents → verify presentation
 *   Issuance:  load metrics dashboard after successful issuance
 */

import { describe, expect, it, vi } from 'vitest';

import {
  createPresentationRequest,
  verifyPresentationRequest,
} from '../verifier/presentationRequestUseCases';
import {
  getPresentationRequestAttributes,
  PRESENTATION_REQUEST_CREDENTIAL_TYPES,
} from '../verifier/presentationRequestFlow';
import { loadIssuanceMetrics } from '../issuance/issuanceDashboardUseCases';
import { parseIssuanceMetrics } from '../issuance/issuanceDashboardFlow';

describe('Verification — create request, present, verify', () => {
  it('complete verification flow: request → present → verify (happy path)', async () => {
    // ── Step 1: Look up available attributes ────────────────
    const attrs = getPresentationRequestAttributes('mDL');
    expect(attrs).toContain('given_name');
    expect(attrs).toContain('age_over_21');

    // ── Step 2: Create presentation request ─────────────────
    const request = await createPresentationRequest({
      selectedCredentialType: 'mDL',
      verifierName: 'Age Check Kiosk',
      createRequest: vi.fn().mockResolvedValue({
        request_id: 'req-42',
        request_uri: 'openid4vp://verify?request_uri=https://marty.dev/req/42',
        audience: 'Age Check Kiosk',
      }),
    });

    expect(request.error).toBeNull();
    expect(request.requestId).toBe('req-42');
    expect(request.requestUri).toContain('openid4vp://');
    expect(request.requestStatus).toBe('pending');

    // ── Step 3: Holder presents VP token ────────────────────
    const verifyResult = await verifyPresentationRequest({
      presentationData: { vp_jwt: 'eyJhbGciOiJFZDI1NTE5...' },
      customNonce: 'nonce-abc',
      requestAudience: request.requestAudience,
      verifierName: 'Age Check Kiosk',
      verifyRequest: vi.fn().mockResolvedValue({ valid: true }),
    });

    expect(verifyResult.error).toBeNull();
    expect(verifyResult.requestStatus).toBe('verified');
  });

  it('verification failure returns error status', async () => {
    const result = await verifyPresentationRequest({
      presentationData: 'bad-token',
      verifyRequest: vi.fn().mockResolvedValue({ valid: false, error: 'Invalid signature' }),
    });

    expect(result.requestStatus).toBe('error');
    expect(result.error).toBe('Invalid signature');
  });

  it('request creation failure returns error state gracefully', async () => {
    const result = await createPresentationRequest({
      selectedCredentialType: 'mDL',
      createRequest: vi.fn().mockRejectedValue(new Error('Service unavailable')),
    });

    expect(result.requestStatus).toBe('error');
    expect(result.requestId).toBeNull();
  });

  it('supports multiple credential types for requests', () => {
    expect(PRESENTATION_REQUEST_CREDENTIAL_TYPES.length).toBeGreaterThanOrEqual(3);

    const types = PRESENTATION_REQUEST_CREDENTIAL_TYPES.map((t) => t.value);
    expect(types).toContain('mDL');
    expect(types).toContain('VerifiableId');
    expect(types).toContain('ProofOfAge');
  });
});

describe('Issuance Metrics — dashboard after issuance', () => {
  it('loads and parses issuance metrics', async () => {
    const { metrics, error } = await loadIssuanceMetrics({
      organizationId: 'org-1',
      days: 7,
      fetchSummary: vi.fn().mockResolvedValue({
        active_offers: 15,
        total_scans: 120,
        success_rate: 92.5,
        total_offers: 200,
      }),
    });

    expect(error).toBeNull();
    expect(metrics).toMatchObject({
      activeOffers: 15,
      totalScans: 120,
      successRate: 92.5,
      totalOffers: 200,
    });
  });

  it('returns null metrics and error message on API failure', async () => {
    const { metrics, error } = await loadIssuanceMetrics({
      organizationId: 'org-1',
      fetchSummary: vi.fn().mockRejectedValue(new Error('timeout')),
    });

    expect(metrics).toBeNull();
    expect(error).toBeTruthy();
  });

  it('parseIssuanceMetrics defaults missing fields to zero', () => {
    expect(parseIssuanceMetrics({})).toMatchObject({
      activeOffers: 0,
      totalScans: 0,
      successRate: 0,
      totalOffers: 0,
    });

    // null input throws — the use-case layer guards against this
    expect(() => parseIssuanceMetrics(null)).toThrow();
  });
});

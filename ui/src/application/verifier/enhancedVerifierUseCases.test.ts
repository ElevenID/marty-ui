import { describe, expect, it, vi } from 'vitest';
import {
  createAgeVerificationRequest,
  createOfflineQR,
  evaluateVerifierPolicy,
  fetchCertificateDashboard,
  fetchPolicySummary,
  renewVerifierCertificate,
  submitAgeVerification,
  submitOfflineQRVerification,
} from './enhancedVerifierUseCases';

describe('enhancedVerifierUseCases', () => {
  // ── Age Verification ────────────────────────────────────────────

  describe('createAgeVerificationRequest', () => {
    it('creates a flow and parses the response', async () => {
      const createFlow = vi.fn().mockResolvedValue({
        instance_id: 'inst-1',
        request_uri: 'https://example.com/request',
        qr_code_data: 'qr-data',
      });

      const result = await createAgeVerificationRequest({
        useCase: 'alcohol_purchase',
        createFlow,
      });

      expect(result.error).toBeNull();
      expect(result.request.request_id).toBe('inst-1');
      expect(createFlow).toHaveBeenCalledWith(
        expect.objectContaining({ flow_type: 'age_verification', use_case: 'alcohol_purchase' }),
      );
    });

    it('returns error when createFlow fails', async () => {
      const createFlow = vi.fn().mockRejectedValue(new Error('network'));
      const result = await createAgeVerificationRequest({ useCase: 'voting_registration', createFlow });
      expect(result.request).toBeNull();
      expect(result.error).toBeTruthy();
    });
  });

  describe('submitAgeVerification', () => {
    it('submits a mock presentation and returns the result', async () => {
      const submitFlow = vi.fn().mockResolvedValue({
        verification_result: { verified: true },
        privacy_report: { privacy_level: 'high' },
      });

      const result = await submitAgeVerification({
        requestId: 'inst-1',
        useCase: 'alcohol_purchase',
        now: () => 0,
        submitFlow,
      });

      expect(result.error).toBeNull();
      expect(result.result.verification_result.verified).toBe(true);
      expect(submitFlow).toHaveBeenCalledWith(
        expect.objectContaining({ instanceId: 'inst-1' }),
      );
    });
  });

  // ── Offline QR ──────────────────────────────────────────────────

  describe('createOfflineQR', () => {
    it('creates an offline QR flow', async () => {
      const createFlow = vi.fn().mockResolvedValue({
        instance_id: 'qr-1',
        qr_code_data: 'base64...',
        size_bytes: 1234,
      });

      const result = await createOfflineQR({ createFlow });

      expect(result.error).toBeNull();
      expect(result.qrCode.instance_id).toBe('qr-1');
      expect(createFlow).toHaveBeenCalledWith(
        expect.objectContaining({ flow_type: 'offline_qr' }),
      );
    });
  });

  describe('submitOfflineQRVerification', () => {
    it('submits QR data and returns the verification result', async () => {
      const submitFlow = vi.fn().mockResolvedValue({
        result: { verified: true, checks_performed: [] },
      });

      const result = await submitOfflineQRVerification({
        instanceId: 'qr-1',
        qrCodeData: 'base64...',
        submitFlow,
      });

      expect(result.error).toBeNull();
      expect(result.verificationResult.verified).toBe(true);
    });
  });

  // ── Certificates ────────────────────────────────────────────────

  describe('fetchCertificateDashboard', () => {
    it('returns the dashboard data', async () => {
      const fetchDashboard = vi.fn().mockResolvedValue({
        overview: { total_certificates: 5 },
        certificates: [],
      });

      const result = await fetchCertificateDashboard({ fetchDashboard });
      expect(result.error).toBeNull();
      expect(result.dashboard.overview.total_certificates).toBe(5);
    });
  });

  describe('renewVerifierCertificate', () => {
    it('renews and reloads the dashboard', async () => {
      const renewCert = vi.fn().mockResolvedValue({ renewal_successful: true });
      const reloadDashboard = vi.fn().mockResolvedValue({
        overview: { total_certificates: 5 },
        certificates: [],
      });

      const result = await renewVerifierCertificate({
        certId: 'cert-1',
        renewCert,
        reloadDashboard,
      });

      expect(result.renewed).toBe(true);
      expect(result.dashboard).toBeTruthy();
      expect(reloadDashboard).toHaveBeenCalled();
    });

    it('returns error when renewal is not successful', async () => {
      const renewCert = vi.fn().mockResolvedValue({ renewal_successful: false });
      const result = await renewVerifierCertificate({ certId: 'cert-1', renewCert });
      expect(result.renewed).toBe(false);
      expect(result.error).toBeTruthy();
    });
  });

  // ── Policy ──────────────────────────────────────────────────────

  describe('fetchPolicySummary', () => {
    it('returns the policy summary', async () => {
      const fetchSummary = vi.fn().mockResolvedValue({
        policies: { p1: { name: 'Age check' } },
      });

      const result = await fetchPolicySummary({ fetchSummary });
      expect(result.error).toBeNull();
      expect(result.policies.policies.p1.name).toBe('Age check');
    });
  });

  describe('evaluateVerifierPolicy', () => {
    it('evaluates and returns the result', async () => {
      const evaluate = vi.fn().mockResolvedValue({
        recommended_action: 'approve',
      });

      const result = await evaluateVerifierPolicy({ evaluate });
      expect(result.error).toBeNull();
      expect(result.evaluation.recommended_action).toBe('approve');
      expect(evaluate).toHaveBeenCalledWith(
        expect.objectContaining({ presentation_request: expect.any(Object) }),
      );
    });
  });
});

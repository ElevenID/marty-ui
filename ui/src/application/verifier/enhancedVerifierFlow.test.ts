import { describe, expect, it } from 'vitest';
import {
  AGE_VERIFICATION_USE_CASES,
  buildAgeVerificationFlowBody,
  buildOfflineQRFlowBody,
  createAgeVerificationMockPresentation,
  createDefaultMockMDLData,
  createDefaultMockPolicyEvaluation,
  parseFlowInstanceResponse,
  parseOfflineQRResponse,
} from './enhancedVerifierFlow';

describe('enhancedVerifierFlow', () => {
  describe('AGE_VERIFICATION_USE_CASES', () => {
    it('contains the four standard use cases', () => {
      expect(Object.keys(AGE_VERIFICATION_USE_CASES)).toEqual([
        'alcohol_purchase',
        'voting_registration',
        'senior_discount',
        'employment_eligibility',
      ]);
    });
  });

  describe('buildAgeVerificationFlowBody', () => {
    it('builds a flow request body for the given use case', () => {
      const body = buildAgeVerificationFlowBody({ useCase: 'alcohol_purchase' });
      expect(body).toEqual({
        flow_type: 'age_verification',
        use_case: 'alcohol_purchase',
        verifier_id: 'demo_enhanced_verifier',
        purpose: 'Enhanced demo for Alcohol Purchase (21+)',
      });
    });
  });

  describe('createAgeVerificationMockPresentation', () => {
    it('sets age_over_21 only for alcohol_purchase', () => {
      const p = createAgeVerificationMockPresentation({
        useCase: 'alcohol_purchase',
        now: () => 0,
      });
      const subject = p.verifiableCredential[0].credentialSubject;
      expect(subject.age_over_21).toBe(true);
      expect(subject.age_over_65).toBe(false);
    });

    it('sets age_over_65 only for senior_discount', () => {
      const p = createAgeVerificationMockPresentation({
        useCase: 'senior_discount',
        now: () => 0,
      });
      expect(p.verifiableCredential[0].credentialSubject.age_over_65).toBe(true);
      expect(p.verifiableCredential[0].credentialSubject.age_over_21).toBe(false);
    });
  });

  describe('parseFlowInstanceResponse', () => {
    it('returns the request when instance_id is present', () => {
      const data = { instance_id: 'id-1', request_uri: 'uri', qr_code_data: 'qr' };
      const { request, error } = parseFlowInstanceResponse(data);
      expect(error).toBeNull();
      expect(request.request_id).toBe('id-1');
    });

    it('returns an error when instance_id is missing', () => {
      const { request, error } = parseFlowInstanceResponse({ error: 'nope' });
      expect(request).toBeNull();
      expect(error).toBe('nope');
    });
  });

  describe('parseOfflineQRResponse', () => {
    it('returns qrCode when instance_id is present', () => {
      const { qrCode, error } = parseOfflineQRResponse({
        instance_id: 'qr-1',
        qr_code_data: 'data',
      });
      expect(error).toBeNull();
      expect(qrCode.instance_id).toBe('qr-1');
    });

    it('returns an error when instance_id is missing', () => {
      const { qrCode, error } = parseOfflineQRResponse({});
      expect(qrCode).toBeNull();
      expect(error).toBe('QR creation failed');
    });
  });

  describe('createDefaultMockMDLData', () => {
    it('returns MDL data with expected fields', () => {
      const data = createDefaultMockMDLData();
      expect(data.given_name).toBe('Jane');
      expect(data.document_number).toBe('DL123456789');
    });
  });

  describe('buildOfflineQRFlowBody', () => {
    it('wraps MDL data in an offline_qr flow body', () => {
      const body = buildOfflineQRFlowBody({ mdlData: createDefaultMockMDLData() });
      expect(body.flow_type).toBe('offline_qr');
      expect(body.expires_in_minutes).toBe(60);
    });
  });

  describe('createDefaultMockPolicyEvaluation', () => {
    it('returns evaluation input with all three sections', () => {
      const input = createDefaultMockPolicyEvaluation();
      expect(input).toHaveProperty('presentation_request');
      expect(input).toHaveProperty('available_attributes');
      expect(input).toHaveProperty('context');
    });
  });
});

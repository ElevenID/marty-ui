/**
 * Use cases for the Enhanced Verifier Demo.
 * Each function wraps a single transport call behind an injectable seam.
 */

import { get, getErrorMessage, post } from '../../services/api';
import {
  buildAgeVerificationFlowBody,
  buildOfflineQRFlowBody,
  createAgeVerificationMockPresentation,
  createDefaultMockMDLData,
  createDefaultMockPolicyEvaluation,
  parseFlowInstanceResponse,
  parseOfflineQRResponse,
} from './enhancedVerifierFlow';

const FLOWS_BASE = '/v1/flows';
const TRUST_BASE = '/v1/trust-profiles/verifier';
const POLICY_BASE = '/v1/trust/verifier/policy';

// ── default transports (thin wrappers around api.get / api.post) ────

async function defaultCreateFlow(body) {
  return post(`${FLOWS_BASE}/verify`, body);
}

async function defaultSubmitFlow({ instanceId, body }) {
  return post(`${FLOWS_BASE}/instances/${instanceId}/submit`, body);
}

async function defaultFetchCertificateDashboard() {
  return get(`${TRUST_BASE}/certificates/dashboard`);
}

async function defaultRenewCert({ certId }) {
  return post(`${TRUST_BASE}/certificates/${certId}/renew`);
}

async function defaultFetchPolicySummary() {
  return get(`${POLICY_BASE}/summary`);
}

async function defaultEvaluatePolicy(body) {
  return post(`${POLICY_BASE}/evaluate`, body);
}

// ── Age Verification ────────────────────────────────────────────────

export async function createAgeVerificationRequest({
  useCase,
  createFlow = defaultCreateFlow,
} = {}) {
  try {
    const body = buildAgeVerificationFlowBody({ useCase });
    const data = await createFlow(body);
    return parseFlowInstanceResponse(data);
  } catch (error) {
    return { request: null, error: getErrorMessage(error) || 'Age verification request failed' };
  }
}

export async function submitAgeVerification({
  requestId,
  useCase,
  now,
  submitFlow = defaultSubmitFlow,
} = {}) {
  try {
    const mockPresentation = createAgeVerificationMockPresentation({ useCase, now });
    const data = await submitFlow({
      instanceId: requestId,
      body: { vp_token: JSON.stringify(mockPresentation) },
    });
    return { result: data, error: null };
  } catch (error) {
    return { result: null, error: getErrorMessage(error) || 'Age verification failed' };
  }
}

// ── Offline QR ──────────────────────────────────────────────────────

export async function createOfflineQR({
  mdlData,
  createFlow = defaultCreateFlow,
} = {}) {
  try {
    const body = buildOfflineQRFlowBody({ mdlData: mdlData || createDefaultMockMDLData() });
    const data = await createFlow(body);
    return parseOfflineQRResponse(data);
  } catch (error) {
    return { qrCode: null, error: getErrorMessage(error) || 'Offline QR creation failed' };
  }
}

export async function submitOfflineQRVerification({
  instanceId,
  qrCodeData,
  submitFlow = defaultSubmitFlow,
} = {}) {
  try {
    const data = await submitFlow({
      instanceId,
      body: {
        qr_data: qrCodeData,
        verification_context: {
          purpose: 'age_verification',
          verifier_id: 'offline_demo_verifier',
        },
      },
    });
    return { verificationResult: data.result, error: null };
  } catch (error) {
    return { verificationResult: null, error: getErrorMessage(error) || 'Offline QR verification failed' };
  }
}

// ── Certificates ────────────────────────────────────────────────────

export async function fetchCertificateDashboard({
  fetchDashboard = defaultFetchCertificateDashboard,
} = {}) {
  try {
    const data = await fetchDashboard();
    return { dashboard: data, error: null };
  } catch (error) {
    return { dashboard: null, error: getErrorMessage(error) || 'Certificate dashboard failed' };
  }
}

export async function renewVerifierCertificate({
  certId,
  renewCert = defaultRenewCert,
  reloadDashboard = defaultFetchCertificateDashboard,
} = {}) {
  try {
    const data = await renewCert({ certId });
    if (data.renewal_successful) {
      const dashboardData = await reloadDashboard();
      return { renewed: true, dashboard: dashboardData, error: null };
    }
    return { renewed: false, dashboard: null, error: 'Renewal was not successful' };
  } catch (error) {
    return { renewed: false, dashboard: null, error: getErrorMessage(error) || 'Certificate renewal failed' };
  }
}

// ── Policy ──────────────────────────────────────────────────────────

export async function fetchPolicySummary({
  fetchSummary = defaultFetchPolicySummary,
} = {}) {
  try {
    const data = await fetchSummary();
    return { policies: data, error: null };
  } catch (error) {
    return { policies: null, error: getErrorMessage(error) || 'Policy summary failed' };
  }
}

export async function evaluateVerifierPolicy({
  evaluation,
  evaluate = defaultEvaluatePolicy,
} = {}) {
  try {
    const body = evaluation || createDefaultMockPolicyEvaluation();
    const data = await evaluate(body);
    return { evaluation: data, error: null };
  } catch (error) {
    return { evaluation: null, error: getErrorMessage(error) || 'Policy evaluation failed' };
  }
}

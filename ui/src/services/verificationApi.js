import { get, post } from './api';

const BASE = '/v1/verify';

export async function startVerificationSession(request) {
  return post(BASE, request);
}

export async function getVerificationSession(sessionId) {
  return get(`${BASE}/${sessionId}`);
}

export async function getVerificationRequest(sessionId) {
  return get(`${BASE}/${sessionId}/request`);
}

export async function submitPresentation(sessionId, body) {
  return post(`${BASE}/${sessionId}/submit`, body);
}

export async function evaluatePresentation(request) {
  return post(`${BASE}/evaluate`, request);
}

export async function listVerificationSessions(organizationId, params = {}) {
  return get(`${BASE}/sessions`, { params: { organization_id: organizationId, ...params } });
}

export async function getInspectionResult(sessionId) {
  return get(`${BASE}/${sessionId}/inspection`);
}

export default {
  startVerificationSession,
  getVerificationSession,
  getVerificationRequest,
  submitPresentation,
  evaluatePresentation,
  listVerificationSessions,
  getInspectionResult,
};

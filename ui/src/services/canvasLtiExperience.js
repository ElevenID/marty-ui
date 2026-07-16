import { get, post } from './api';

const CANVAS_LTI_SESSION_STORAGE_KEY = 'elevenid.canvas-lti.session.v1';

function browserSessionStorage() {
  return typeof window !== 'undefined' ? window.sessionStorage : null;
}

export function storeCanvasLtiSession({ session_token: token, expires_at: expiresAt } = {}) {
  if (!token) {
    throw new Error('Canvas launch did not return a session token.');
  }

  browserSessionStorage()?.setItem(
    CANVAS_LTI_SESSION_STORAGE_KEY,
    JSON.stringify({ token, expiresAt: expiresAt || null }),
  );
  return token;
}

export function clearCanvasLtiSession() {
  browserSessionStorage()?.removeItem(CANVAS_LTI_SESSION_STORAGE_KEY);
}

export function getCanvasLtiSessionToken() {
  const serialized = browserSessionStorage()?.getItem(CANVAS_LTI_SESSION_STORAGE_KEY);
  if (!serialized) return null;

  try {
    const session = JSON.parse(serialized);
    if (!session?.token) {
      clearCanvasLtiSession();
      return null;
    }
    if (session.expiresAt && Date.parse(session.expiresAt) <= Date.now()) {
      clearCanvasLtiSession();
      return null;
    }
    return session.token;
  } catch {
    clearCanvasLtiSession();
    return null;
  }
}

function canvasLtiAuthorization(token = getCanvasLtiSessionToken()) {
  if (!token) {
    throw new Error('Canvas launch session is missing or expired. Open the credential again from Canvas.');
  }
  return { headers: { Authorization: `Bearer ${token}` } };
}

export async function exchangeCanvasLtiExperienceCode(code) {
  const normalizedCode = String(code || '').trim();
  if (!normalizedCode) {
    throw new Error('Canvas launch code is missing.');
  }

  const exchange = await post(
    '/v1/integrations/canvas/lti/experience-sessions/exchange',
    { code: normalizedCode },
  );
  const token = storeCanvasLtiSession(exchange);
  return { ...exchange, session_token: token };
}

export function getCurrentCanvasLtiExperience() {
  return get(
    '/v1/integrations/canvas/lti/experience-sessions/current',
    canvasLtiAuthorization(),
  );
}

export function finalizeCanvasLtiAuthentication() {
  return post(
    '/v1/auth/canvas-lti/finalize',
    {},
    canvasLtiAuthorization(),
  );
}

export function bootstrapCurrentCanvasLtiApplication(payload = {}) {
  return post(
    '/v1/integrations/canvas/lti/experience-sessions/current/bootstrap',
    payload,
    canvasLtiAuthorization(),
  );
}

export function getCurrentCanvasLtiEvidenceStatus() {
  return get(
    '/v1/integrations/canvas/lti/experience-sessions/current/evidence-status',
    canvasLtiAuthorization(),
  );
}

export function enqueueCurrentCanvasLtiEvidenceSync() {
  return post(
    '/v1/integrations/canvas/lti/experience-sessions/current/evidence-sync',
    {},
    canvasLtiAuthorization(),
  );
}

export function createCurrentCanvasLtiDeepLinkingResponse() {
  return post(
    '/v1/integrations/canvas/lti/experience-sessions/current/deep-linking-response',
    {},
    canvasLtiAuthorization(),
  );
}

export const CANVAS_LTI_NAVIGATION_MARKER = 'current';

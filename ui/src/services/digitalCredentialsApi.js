export const DEFAULT_DC_API_PROTOCOL = 'openid4vp-v1-signed';

function resolveApiUrl(path) {
  if (!path) return '';
  if (/^https?:\/\//i.test(path)) return path;
  return `${import.meta.env.VITE_API_URL || ''}${path}`;
}

async function protocolAllowed(protocol) {
  if (typeof DigitalCredential === 'undefined') return false;
  if (typeof DigitalCredential.userAgentAllowsProtocol !== 'function') return true;
  const allowed = DigitalCredential.userAgentAllowsProtocol(protocol);
  return typeof allowed?.then === 'function' ? Boolean(await allowed) : Boolean(allowed);
}

export async function supportsDigitalCredentials(protocol = DEFAULT_DC_API_PROTOCOL) {
  if (typeof window === 'undefined' || !window.isSecureContext) return false;
  if (typeof navigator === 'undefined' || !navigator.credentials) return false;
  if (typeof navigator.credentials.get !== 'function') return false;
  try {
    return await protocolAllowed(protocol);
  } catch {
    return false;
  }
}

export function formatDigitalCredentialError(error) {
  if (!error) return 'Wallet request failed.';
  if (typeof error === 'string') return error;
  if (error.error_description) return error.error_description;
  if (typeof error.detail === 'string') return error.detail;
  if (error.detail?.error_description) return error.detail.error_description;
  if (error.detail?.error) return error.detail.error;
  if (error.name === 'NotAllowedError') return 'Wallet request was canceled.';
  if (error.message) return error.message;
  return 'Wallet request failed.';
}

export async function fetchDigitalCredentialRequest(requestUrl, { fetchImpl = fetch } = {}) {
  const response = await fetchImpl(resolveApiUrl(requestUrl), {
    credentials: 'same-origin',
    headers: { Accept: 'application/oauth-authz-req+jwt' },
  });
  if (!response.ok) {
    throw new Error('Failed to prepare wallet request.');
  }
  return response.text();
}

export async function requestOpenId4VpCredential({ requestJwt, protocol = DEFAULT_DC_API_PROTOCOL }) {
  if (!requestJwt) {
    throw new Error('Digital Credentials request JWT is required.');
  }
  return navigator.credentials.get({
    mediation: 'required',
    digital: {
      requests: [
        {
          protocol,
          data: { request: requestJwt },
        },
      ],
    },
  });
}

export async function submitDigitalCredentialResponse({
  submitUrl,
  credential,
  protocol = DEFAULT_DC_API_PROTOCOL,
  origin = typeof window !== 'undefined' ? window.location.origin : '',
  fetchImpl = fetch,
}) {
  const response = await fetchImpl(resolveApiUrl(submitUrl), {
    method: 'POST',
    credentials: 'same-origin',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      protocol: credential?.protocol || protocol,
      origin,
      data: credential?.data || {},
    }),
  });

  const payload = await response.json().catch(() => ({}));
  if (!response.ok) throw payload;
  return payload;
}

export async function runOpenId4VpDigitalCredentialFlow({
  requestUrl,
  submitUrl,
  protocol = DEFAULT_DC_API_PROTOCOL,
  fetchImpl = fetch,
}) {
  const supported = await supportsDigitalCredentials(protocol);
  if (!supported) {
    throw new Error('Digital Credentials API is not available in this browser.');
  }
  const requestJwt = await fetchDigitalCredentialRequest(requestUrl, { fetchImpl });
  const credential = await requestOpenId4VpCredential({ requestJwt, protocol });
  if (!credential?.data) {
    throw new Error('Wallet returned an empty credential response.');
  }
  if (credential.data.error) {
    throw credential.data;
  }
  return submitDigitalCredentialResponse({ submitUrl, credential, protocol, fetchImpl });
}

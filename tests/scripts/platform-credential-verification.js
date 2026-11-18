'use strict';
// Generic public-protocol verification extracted from the retired demo harness.
const crypto=require('node:crypto');
const {walletExpectationForTemplate,requireSignedCredentialBinding}=require('./platform-credential-identity');
const DEFAULT_MARTY_ORIGIN='https://beta.elevenidllc.com',DEFAULT_TIMEOUT_MS=60000,JOB_TIMEOUT_MS=180000;
class ContractFailure extends Error {
  constructor(code, summary, options = {}) {
    super(summary, options);
    this.name = 'ContractFailure';
    this.code = code;
  }
}

function fail(code, summary) {
  throw new ContractFailure(code, summary);
}

function requireCondition(condition, code, summary) {
  if (!condition) fail(code, summary);
}

function safeList(value) {
  if (Array.isArray(value)) return value;
  if (Array.isArray(value?.items)) return value.items;
  return [];
}

function transportFailureSummary(error, timedOut) {
  // Only closed diagnostic codes may cross into public evidence. Error messages,
  // stacks, URLs and request headers can contain credential material.
  const allowed = ['ETIMEDOUT', 'UND_ERR_CONNECT_TIMEOUT', 'ENETUNREACH', 'EHOSTUNREACH',
    'ENOTFOUND', 'EAI_AGAIN', 'ECONNREFUSED', 'ECONNRESET', 'CERT_HAS_EXPIRED',
    'DEPTH_ZERO_SELF_SIGNED_CERT', 'SELF_SIGNED_CERT_IN_CHAIN',
    'UNABLE_TO_VERIFY_LEAF_SIGNATURE', 'ERR_TLS_CERT_ALTNAME_INVALID'];
  const codes = new Set(timedOut ? ['REQUEST_TIMEOUT'] : []);
  const pending = [error];
  const seen = new Set();
  for (let count = 0; pending.length && count < 16; count++) {
    const item = pending.shift();
    if (!item || typeof item !== 'object' || seen.has(item)) continue;
    seen.add(item);
    if (allowed.includes(item.code)) codes.add(item.code);
    if (item.name === 'AbortError') codes.add('REQUEST_ABORTED');
    if (item.cause) pending.push(item.cause);
    if (Array.isArray(item.errors)) pending.push(...item.errors.slice(0, 16));
  }
  const ordered = ['REQUEST_TIMEOUT', 'REQUEST_ABORTED', ...allowed].filter(code => codes.has(code));
  return `A required HTTPS request failed (${ordered.join(', ') || 'UNKNOWN_TRANSPORT_ERROR'}).`;
}

async function fetchWithTimeout(url, options = {}, timeoutMs = DEFAULT_TIMEOUT_MS) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, { ...options, signal: controller.signal, redirect: options.redirect || 'manual' });
  } catch (error) {
    fail('http_transport_failed', transportFailureSummary(error, controller.signal.aborted));
  } finally {
    clearTimeout(timer);
  }
}

async function responseJson(response, code, summary, expectedStatuses = [200]) {
  const status = typeof response.status === 'function' ? response.status() : response.status;
  requireCondition(expectedStatuses.includes(status), code, `${summary} HTTP ${status}.`);
  if (status === 204) return null;
  try {
    return await response.json();
  } catch {
    fail(code, `${summary} did not return JSON.`);
  }
}

function parseCredentialOfferUri(uri) {
  const normalized = String(uri || '').trim();
  requireCondition(normalized, 'credential_offer_missing', 'The claim response omitted its OID4VCI offer.');
  let url;
  try {
    url = new URL(normalized);
  } catch {
    fail('credential_offer_invalid', 'The claim response returned an invalid OID4VCI offer URI.');
  }
  requireCondition(url.protocol === 'openid-credential-offer:', 'credential_offer_invalid', 'The claim response did not use the OID4VCI offer scheme.');
  const inline = url.searchParams.get('credential_offer');
  requireCondition(inline, 'credential_offer_reference_unsupported', 'The contract requires an inline OID4VCI offer for deterministic verification.');
  let offer;
  try {
    offer = JSON.parse(inline);
  } catch {
    fail('credential_offer_invalid', 'The inline OID4VCI offer is not valid JSON.');
  }
  const grant = offer?.grants?.['urn:ietf:params:oauth:grant-type:pre-authorized_code'];
  requireCondition(offer?.credential_issuer && safeList(offer?.credential_configuration_ids).length === 1 && grant?.['pre-authorized_code'], 'credential_offer_incomplete', 'The OID4VCI offer is missing required pre-authorized flow fields.');
  return {
    issuer: String(offer.credential_issuer),
    configurationId: String(offer.credential_configuration_ids[0]),
    preAuthorizedCode: String(grant['pre-authorized_code']),
  };
}

function pinnedHttpsUrl(value, expectedOrigin, code, summary) {
  let url;
  try {
    url = new URL(String(value || ''));
  } catch {
    fail(code, summary);
  }
  requireCondition(
    url.protocol === 'https:'
      && url.origin === expectedOrigin
      && !url.username
      && !url.password
      && !url.search
      && !url.hash,
    code,
    summary,
  );
  return url;
}

async function resolveOid4vciEndpoints(metadata, issuerUrl, expectedOrigin, fetchImpl = fetchWithTimeout) {
  const declaredIssuer = pinnedHttpsUrl(
    metadata?.credential_issuer,
    expectedOrigin,
    'credential_metadata_issuer_unpinned',
    'OID4VCI metadata returned an invalid or untrusted credential issuer.',
  );
  requireCondition(
    declaredIssuer.href.replace(/\/$/, '') === issuerUrl.href.replace(/\/$/, ''),
    'credential_metadata_issuer_mismatch',
    'OID4VCI metadata did not describe the credential issuer in the offer.',
  );
  const credentialEndpoint = pinnedHttpsUrl(
    metadata?.credential_endpoint,
    expectedOrigin,
    'credential_endpoint_unpinned',
    'OID4VCI metadata returned an invalid or untrusted credential endpoint.',
  );

  let tokenEndpointValue = metadata?.token_endpoint;
  if (!tokenEndpointValue) {
    const authorizationServers = safeList(metadata?.authorization_servers);
    requireCondition(
      authorizationServers.length === 1,
      'authorization_server_ambiguous',
      'OID4VCI metadata must identify exactly one authorization server when it omits token_endpoint.',
    );
    const authorizationServer = pinnedHttpsUrl(
      authorizationServers[0],
      expectedOrigin,
      'authorization_server_unpinned',
      'OID4VCI metadata returned an invalid or untrusted authorization server.',
    );
    const authorizationPath = authorizationServer.pathname === '/'
      ? ''
      : authorizationServer.pathname.replace(/\/$/, '');
    const authorizationMetadataUrl = `${authorizationServer.origin}/.well-known/oauth-authorization-server${authorizationPath}`;
    const authorizationResponse = await fetchImpl(authorizationMetadataUrl, {
      headers: { Accept: 'application/json' },
    });
    const authorizationMetadata = await responseJson(
      authorizationResponse,
      'authorization_metadata_failed',
      'OAuth authorization server metadata request failed',
    );
    const discoveredIssuer = pinnedHttpsUrl(
      authorizationMetadata?.issuer,
      expectedOrigin,
      'authorization_server_issuer_unpinned',
      'OAuth authorization server metadata returned an invalid or untrusted issuer.',
    );
    requireCondition(
      discoveredIssuer.href.replace(/\/$/, '') === authorizationServer.href.replace(/\/$/, ''),
      'authorization_server_issuer_mismatch',
      'OAuth authorization server metadata did not describe the selected authorization server.',
    );
    tokenEndpointValue = authorizationMetadata?.token_endpoint;
  }

  const tokenEndpoint = pinnedHttpsUrl(
    tokenEndpointValue,
    expectedOrigin,
    'token_endpoint_unpinned',
    'OID4VCI metadata returned an invalid or untrusted token endpoint.',
  );
  const nonceEndpoint = metadata?.nonce_endpoint
    ? pinnedHttpsUrl(
      metadata.nonce_endpoint,
      expectedOrigin,
      'nonce_endpoint_unpinned',
      'OID4VCI metadata returned an invalid or untrusted nonce endpoint.',
    )
    : null;
  return { tokenEndpoint, credentialEndpoint, nonceEndpoint };
}

async function resolveProofNonce(token, nonceEndpoint, fetchImpl = fetchWithTimeout) {
  const tokenNonce = String(token?.c_nonce || token?.nonce || '').trim();
  if (tokenNonce) return tokenNonce;
  requireCondition(
    nonceEndpoint,
    'credential_nonce_endpoint_missing',
    'OID4VCI metadata omitted the nonce endpoint required by the token response.',
  );
  const nonceResponse = await fetchImpl(nonceEndpoint, {
    method: 'POST',
    headers: { Accept: 'application/json' },
  });
  const nonce = await responseJson(
    nonceResponse,
    'credential_nonce_failed',
    'OID4VCI proof nonce request failed',
  );
  const proofNonce = String(nonce?.c_nonce || nonce?.nonce || '').trim();
  requireCondition(
    proofNonce,
    'credential_nonce_response_incomplete',
    'OID4VCI nonce response omitted the proof nonce.',
  );
  return proofNonce;
}

function base64urlJson(value) {
  return Buffer.from(JSON.stringify(value)).toString('base64url');
}

function decodeJwtPart(part) {
  try {
    return JSON.parse(Buffer.from(part, 'base64url').toString('utf8'));
  } catch {
    fail('jwt_decode_failed', 'A signed JWT component could not be decoded.');
  }
}

function publicHolderJwk(publicKey) {
  const jwk = publicKey.export({ format: 'jwk' });
  return { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y };
}

function createHolderProof(privateKey, publicJwk, issuer, nonce) {
  const did = `did:jwk:${Buffer.from(JSON.stringify(publicJwk)).toString('base64url')}`;
  const header = { typ: 'openid4vci-proof+jwt', alg: 'ES256', jwk: publicJwk };
  const payload = {
    iss: did,
    sub: did,
    aud: issuer,
    iat: Math.floor(Date.now() / 1000),
    nonce,
    jti: crypto.randomUUID(),
  };
  const input = `${base64urlJson(header)}.${base64urlJson(payload)}`;
  const signature = crypto.sign('sha256', Buffer.from(input), { key: privateKey, dsaEncoding: 'ieee-p1363' });
  return { did, jwt: `${input}.${signature.toString('base64url')}` };
}

function didWebResolutionUrl(did) {
  const prefix = 'did:web:';
  requireCondition(String(did).startsWith(prefix), 'issuer_did_method_unsupported', 'The contract verifier currently requires a published did:web issuer.');
  const segments = String(did).slice(prefix.length).split(':').map((segment) => decodeURIComponent(segment));
  requireCondition(segments.length >= 1 && segments.every(Boolean), 'issuer_did_invalid', 'The issued credential contains an invalid did:web issuer.');
  const authority = segments[0];
  const pathName = segments.length === 1
    ? '/.well-known/did.json'
    : `/${segments.slice(1).map(encodeURIComponent).join('/')}/did.json`;
  return `https://${authority}${pathName}`;
}

function verificationMethodFromDidDocument(document, kid) {
  const methods = safeList(document?.verificationMethod);
  const assertionIds = new Set(safeList(document?.assertionMethod).map((entry) => (
    typeof entry === 'string' ? entry : entry?.id
  )).filter(Boolean));
  const method = methods.find((entry) => entry?.id === kid)
    || safeList(document?.assertionMethod).find((entry) => typeof entry === 'object' && entry?.id === kid);
  requireCondition(method?.publicKeyJwk && (assertionIds.has(kid) || safeList(document?.assertionMethod).some((entry) => entry?.id === kid)), 'issuer_verification_method_missing', 'The credential signing key is not a published DID assertion method.');
  return method;
}

function verifyCompactJws(compact, publicJwk) {
  const parts = String(compact).split('.');
  requireCondition(parts.length === 3, 'credential_jws_invalid', 'The issued SD-JWT issuer-signed component is not a compact JWS.');
  const header = decodeJwtPart(parts[0]);
  const payload = decodeJwtPart(parts[1]);
  const key = crypto.createPublicKey({ key: publicJwk, format: 'jwk' });
  const data = Buffer.from(`${parts[0]}.${parts[1]}`);
  const signature = Buffer.from(parts[2], 'base64url');
  let verified = false;
  if (header.alg === 'ES256') {
    verified = crypto.verify('sha256', data, { key, dsaEncoding: 'ieee-p1363' }, signature);
  } else if (header.alg === 'RS256') {
    verified = crypto.verify('RSA-SHA256', data, key, signature);
  } else {
    fail('credential_algorithm_unsupported', `Unsupported credential JWS algorithm ${String(header.alg || 'missing')}.`);
  }
  requireCondition(verified, 'credential_signature_invalid', 'The issued credential signature did not verify against the published DID key.');
  return { header, payload };
}

async function receiveAndVerifyCredential(offerUri, expectedTemplate, expectedIssuerOrigin = DEFAULT_MARTY_ORIGIN, ownedEngineering = null) {
  requireCondition(
    typeof expectedTemplate?.vct === 'string' && expectedTemplate.vct.trim().length > 0,
    'credential_template_vct_missing',
    'Credential verification requires the selected template\'s exact VCT before claiming its offer.',
  );
  const walletExpectation = walletExpectationForTemplate(expectedTemplate);
  requireCondition(ownedEngineering===null,'owned_wallet_adapter_unavailable','Owned wallet transport needs its separately reviewed platform adapter.');
  const offer = parseCredentialOfferUri(offerUri);
  const issuerUrl = pinnedHttpsUrl(
    offer.issuer,
    expectedIssuerOrigin,
    'credential_issuer_unpinned',
    'The OID4VCI issuer is outside the reviewed beta origin.',
  );
  const metadataUrl = `${issuerUrl.origin}/.well-known/openid-credential-issuer${issuerUrl.pathname}`;
  const metadataResponse = await fetchWithTimeout(metadataUrl, { headers: { Accept: 'application/json' } });
  const metadata = await responseJson(metadataResponse, 'credential_metadata_failed', 'OID4VCI issuer metadata request failed');
  const { tokenEndpoint, credentialEndpoint, nonceEndpoint } = await resolveOid4vciEndpoints(
    metadata,
    issuerUrl,
    expectedIssuerOrigin,
  );

  const tokenResponse = await fetchWithTimeout(tokenEndpoint, {
    method: 'POST',
    headers: { Accept: 'application/json', 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'urn:ietf:params:oauth:grant-type:pre-authorized_code',
      'pre-authorized_code': offer.preAuthorizedCode,
    }).toString(),
  });
  const token = await responseJson(tokenResponse, 'credential_token_exchange_failed', 'OID4VCI token exchange failed');
  requireCondition(token?.access_token, 'credential_token_response_incomplete', 'OID4VCI token response omitted its access token.');
  const proofNonce = await resolveProofNonce(token, nonceEndpoint);

  const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const holderJwk = publicHolderJwk(publicKey);
  const proof = createHolderProof(privateKey, holderJwk, offer.issuer, proofNonce);
  const credentialResponse = await fetchWithTimeout(credentialEndpoint, {
    method: 'POST',
    headers: {
      Accept: 'application/json',
      'Content-Type': 'application/json',
      Authorization: `Bearer ${token.access_token}`,
    },
    body: JSON.stringify({
      credential_configuration_id: offer.configurationId,
      proofs: { jwt: [proof.jwt] },
    }),
  }, JOB_TIMEOUT_MS);
  const issued = await responseJson(credentialResponse, 'credential_issue_failed', 'OID4VCI credential request failed');
  const credential = String(issued?.credential || issued?.credentials?.[0]?.credential || issued?.credentials?.[0] || '');
  requireCondition(credential, 'credential_payload_missing', 'OID4VCI credential response omitted the signed credential.');

  const issuerJws = credential.split('~')[0];
  const predecoded = verifyCompactJwsStructure(issuerJws);
  const didUrl = didWebResolutionUrl(predecoded.payload.iss);
  const didResponse = await fetchWithTimeout(didUrl, { headers: { Accept: 'application/did+json, application/json' } });
  const didDocument = await responseJson(didResponse, 'issuer_did_resolution_failed', 'Issuer DID document request failed');
  requireCondition(didDocument?.id === predecoded.payload.iss, 'issuer_did_document_mismatch', 'The resolved DID document does not match the credential issuer.');
  const method = verificationMethodFromDidDocument(didDocument, predecoded.header.kid);
  const verified = verifyCompactJws(issuerJws, method.publicKeyJwk);
  try {
    requireSignedCredentialBinding(verified.payload, expectedTemplate);
  } catch {
    fail('open_badge_type_mismatch', 'The KMS-signed credential does not match the selected Open Badge template.');
  }
  const cnf = verified.payload.cnf?.jwk || {};
  const holderJwkMatches = ['kty', 'crv', 'x', 'y'].every((key) => cnf[key] === holderJwk[key]);
  const holderBound = verified.payload.sub === proof.did || holderJwkMatches;
  requireCondition(holderBound, 'holder_binding_missing', 'The issued Open Badge is not bound to the wallet proof key.');
  return { credential, header: verified.header, payload: verified.payload, holderDid: proof.did };
}

function verifyCompactJwsStructure(compact) {
  const parts = String(compact).split('.');
  requireCondition(parts.length === 3, 'credential_jws_invalid', 'The issued credential is not a compact JWS.');
  return { header: decodeJwtPart(parts[0]), payload: decodeJwtPart(parts[1]) };
}

module.exports={fetchWithTimeout,responseJson,didWebResolutionUrl,receiveAndVerifyCredential,verificationMethodFromDidDocument,verifyCompactJws,verifyCompactJwsStructure};

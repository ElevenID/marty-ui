const OID4VCI_SCHEMES = new Set(['openid-credential-offer', 'haip-vci']);
const OID4VP_SCHEMES = new Set(['openid4vp', 'haip-vp']);
const ROUTING_PLACEHOLDER_PATTERN = /\{(?:inner_uri|uri|offer_uri|offer|credential_offer_uri|request_uri)(?:_encoded)?\}/;
const OID4VCI_PROFILE_BY_FORMAT = {
  'spruce-vc+sd-jwt': {
    formatVariant: 'spruce-vc+sd-jwt',
    issuerPath: 'spruce',
    credentialConfigurationSuffix: 'spruce-sd-jwt',
  },
};
const KNOWN_WALLET_ROUTE_TEMPLATES = {
  'wr-spruce-001': {
    generic: 'openid-credential-offer://?{credential_offer_param}={offer_encoded}',
    ios: 'openid-credential-offer://?{credential_offer_param}={offer_encoded}',
    android: 'intent://?{credential_offer_param}={offer_encoded}#Intent;scheme=openid-credential-offer;package=com.spruceid.mobilesdkexample;end',
  },
  spruce: {
    generic: 'openid-credential-offer://?{credential_offer_param}={offer_encoded}',
    ios: 'openid-credential-offer://?{credential_offer_param}={offer_encoded}',
    android: 'intent://?{credential_offer_param}={offer_encoded}#Intent;scheme=openid-credential-offer;package=com.spruceid.mobilesdkexample;end',
  },
  sprucekit: {
    generic: 'openid-credential-offer://?{credential_offer_param}={offer_encoded}',
    ios: 'openid-credential-offer://?{credential_offer_param}={offer_encoded}',
    android: 'intent://?{credential_offer_param}={offer_encoded}#Intent;scheme=openid-credential-offer;package=com.spruceid.mobilesdkexample;end',
  },
  'wr-marty-001': {
    generic: 'marty-authenticator://open?inner={inner_uri_encoded}',
    ios: 'marty-authenticator://open?inner={inner_uri_encoded}',
    android: 'marty-authenticator://open?inner={inner_uri_encoded}',
  },
  marty: {
    generic: 'marty-authenticator://open?inner={inner_uri_encoded}',
    ios: 'marty-authenticator://open?inner={inner_uri_encoded}',
    android: 'marty-authenticator://open?inner={inner_uri_encoded}',
  },
};

function normalizeUri(value) {
  return typeof value === 'string' ? value.trim() : '';
}

function parseUri(value) {
  const uri = normalizeUri(value);
  if (!uri) return null;
  try {
    return new URL(uri);
  } catch {
    return null;
  }
}

function protocolFor(value) {
  const parsed = parseUri(value);
  return parsed?.protocol ? parsed.protocol.replace(/:$/, '').toLowerCase() : '';
}

function schemeForTemplate(value) {
  return normalizeUri(value).match(/^([a-z][a-z0-9+.-]*):/i)?.[1]?.toLowerCase() || '';
}

function templateValue(value) {
  if (typeof value === 'string') return value;
  if (value?.template) return value.template;
  if (value?.deep_link_template) return value.deep_link_template;
  if (value?.universal_link_template) return value.universal_link_template;
  return '';
}

function isWalletRoutingTemplate(template) {
  const source = templateValue(template);
  const scheme = schemeForTemplate(source);
  return Boolean(
    source &&
    ROUTING_PLACEHOLDER_PATTERN.test(source) &&
    !OID4VCI_SCHEMES.has(scheme) &&
    !OID4VP_SCHEMES.has(scheme)
  );
}

function knownWalletRouting(wallet) {
  return KNOWN_WALLET_ROUTE_TEMPLATES[wallet?.id] || KNOWN_WALLET_ROUTE_TEMPLATES[wallet?.wallet_id] || {};
}

export function isOid4vciUri(value) {
  return OID4VCI_SCHEMES.has(protocolFor(value));
}

export function isOid4vpUri(value) {
  return OID4VP_SCHEMES.has(protocolFor(value));
}

export function buildOid4vciCredentialOfferUri(offerUri) {
  const uri = normalizeUri(offerUri);
  if (!uri) return '';
  if (isOid4vciUri(uri)) return uri;
  return `openid-credential-offer://?credential_offer_uri=${encodeURIComponent(uri)}`;
}

export function buildOid4vpAuthorizationUri(requestUri) {
  const uri = normalizeUri(requestUri);
  if (!uri) return '';
  if (isOid4vpUri(uri)) return uri;
  return `openid4vp://authorize?request_uri=${encodeURIComponent(uri)}`;
}

function normalizeFormatToken(value) {
  return normalizeUri(value).toLowerCase().replace(/_/g, '-');
}

function walletFormatValues(wallet) {
  if (!wallet || typeof wallet !== 'object') return [];
  const explicitProfile = wallet.oid4vci_profile || wallet.credential_offer_profile || wallet.offer_profile || {};
  return [
    explicitProfile.format_variant,
    explicitProfile.format,
    wallet.format_variant,
    wallet.credential_format_variant,
    wallet.credential_format,
    ...(Array.isArray(wallet.supported_formats) ? wallet.supported_formats : []),
  ].filter(Boolean);
}

export function resolveWalletOid4vciProfile(wallet) {
  if (!wallet || typeof wallet !== 'object') return null;
  const explicitProfile = wallet.oid4vci_profile || wallet.credential_offer_profile || wallet.offer_profile || {};
  const explicitIssuerPath = normalizeUri(explicitProfile.issuer_path || explicitProfile.issuerPath);
  const explicitSuffix = normalizeUri(
    explicitProfile.credential_configuration_suffix || explicitProfile.credentialConfigurationSuffix,
  );
  const formatVariant = normalizeFormatToken(
    explicitProfile.format_variant || explicitProfile.format || walletFormatValues(wallet)[0],
  );

  if (explicitIssuerPath || explicitSuffix) {
    return {
      formatVariant,
      issuerPath: explicitIssuerPath,
      credentialConfigurationSuffix: explicitSuffix,
    };
  }

  const profileFormat = walletFormatValues(wallet)
    .map(normalizeFormatToken)
    .find((format) => OID4VCI_PROFILE_BY_FORMAT[format]);
  return profileFormat ? OID4VCI_PROFILE_BY_FORMAT[profileFormat] : null;
}

function issuerUrlWithProfilePath(issuerUrl, profile) {
  const issuer = normalizeUri(issuerUrl).replace(/\/+$/, '');
  const issuerPath = normalizeUri(profile?.issuerPath || profile?.issuer_path).replace(/^\/+|\/+$/g, '');
  if (!issuer || !issuerPath || issuer.endsWith(`/${issuerPath}`)) return issuer;
  return `${issuer.replace(/\/(credential-manager|apple-wallet|spruce)$/, '')}/${issuerPath}`;
}

function credentialConfigurationIdForProfile(configId, profile) {
  const id = normalizeUri(configId);
  const suffix = normalizeUri(
    profile?.credentialConfigurationSuffix || profile?.credential_configuration_suffix,
  ).replace(/^#/, '');
  if (!id || !suffix || id.endsWith(`#${suffix}`) || id.endsWith('#mdoc') || id.endsWith('#vds-nc')) return id;
  if (id.endsWith('#sd-jwt')) return id.replace(/#sd-jwt$/, `#${suffix}`);
  if (id.endsWith('#credential-manager') || id.endsWith('#apple-wallet')) return `${id.split('#')[0]}#${suffix}`;
  if (id.includes('#')) return id;
  return `${id}#${suffix}`;
}

/**
 * @param {string} offerUri
 * @param {Record<string, any> | null | undefined} wallet
 * @returns {string}
 */
export function adaptCredentialOfferForWallet(offerUri, wallet = null) {
  const uri = normalizeUri(offerUri);
  const profile = resolveWalletOid4vciProfile(wallet);
  if (!uri || !profile) return uri;

  const standardUri = buildOid4vciCredentialOfferUri(uri);
  const offerParts = extractCredentialOfferParts(standardUri);
  if (offerParts.parameter !== 'credential_offer') return uri;

  try {
    const offer = JSON.parse(offerParts.value);
    if (!offer || typeof offer !== 'object' || Array.isArray(offer)) return uri;

    const credentialConfigurationIds = Array.isArray(offer.credential_configuration_ids)
      ? offer.credential_configuration_ids.map((id) => credentialConfigurationIdForProfile(id, profile))
      : offer.credential_configuration_ids;

    const adaptedOffer = {
      ...offer,
      credential_issuer: issuerUrlWithProfilePath(offer.credential_issuer, profile),
      ...(Array.isArray(credentialConfigurationIds)
        ? { credential_configuration_ids: credentialConfigurationIds }
        : {}),
    };

    return `openid-credential-offer://?credential_offer=${encodeURIComponent(JSON.stringify(adaptedOffer))}`;
  } catch {
    return uri;
  }
}

export function extractQueryValue(uri, keys) {
  const parsed = parseUri(uri);
  if (!parsed) return '';
  for (const key of keys) {
    const value = parsed.searchParams.get(key);
    if (value) return value;
  }
  return '';
}

export function extractCredentialOfferValue(uri) {
  return extractCredentialOfferParts(uri).value;
}

export function extractCredentialOfferParts(uri) {
  const parsed = parseUri(uri);
  if (!parsed) return { parameter: 'credential_offer_uri', value: normalizeUri(uri) };

  const byReference = parsed.searchParams.get('credential_offer_uri');
  if (byReference) return { parameter: 'credential_offer_uri', value: byReference };

  const byValue = parsed.searchParams.get('credential_offer');
  if (byValue) return { parameter: 'credential_offer', value: byValue };

  return { parameter: 'credential_offer_uri', value: normalizeUri(uri) };
}

export function extractRequestUriValue(uri) {
  return extractQueryValue(uri, ['request_uri']) || normalizeUri(uri);
}

/**
 * @param {string | Record<string, any>} template
 * @param {{ innerUri?: string, platform?: string, walletId?: string }} [options]
 * @returns {string}
 */
export function renderWalletRouteTemplate(template, { innerUri, platform = '', walletId = '' } = {}) {
  let source = normalizeUri(template);
  const uri = normalizeUri(innerUri);
  if (!source || !uri) return uri;

  const offerParts = extractCredentialOfferParts(uri);
  const offerValue = offerParts.value;
  const requestUri = extractRequestUriValue(uri);

  if (offerParts.parameter === 'credential_offer') {
    source = source.replace(
      /credential_offer_uri=(\{(?:offer_uri|offer|credential_offer_uri)(?:_encoded)?\})/g,
      'credential_offer=$1',
    );
  }

  const replacements = {
    inner_uri: uri,
    inner_uri_encoded: encodeURIComponent(uri),
    uri,
    uri_encoded: encodeURIComponent(uri),
    offer_uri: offerValue,
    offer_uri_encoded: encodeURIComponent(offerValue),
    offer: offerValue,
    offer_encoded: encodeURIComponent(offerValue),
    credential_offer_param: offerParts.parameter,
    credential_offer_uri: offerValue,
    credential_offer_uri_encoded: encodeURIComponent(offerValue),
    request_uri: requestUri,
    request_uri_encoded: encodeURIComponent(requestUri),
    platform,
    wallet_id: walletId,
  };

  return source.replace(/\{([a-zA-Z0-9_]+)\}/g, (match, key) => {
    return Object.prototype.hasOwnProperty.call(replacements, key) ? replacements[key] : match;
  });
}

export function resolveWalletRouteTemplate(wallet, platform = '') {
  if (!wallet) return '';
  const routing = wallet.routing || wallet.routing_templates || wallet.route_templates || {};
  const knownRouting = knownWalletRouting(wallet);
  const platformKey = platform === 'desktop' ? 'web' : platform;
  const exactTemplate = templateValue(routing?.[platformKey]) ||
    wallet[`${platformKey}_universal_link_template`] ||
    wallet[`${platformKey}_deep_link_template`] ||
    wallet[`${platformKey}_link_template`] ||
    templateValue(knownRouting?.[platformKey]) ||
    '';
  if (isWalletRoutingTemplate(exactTemplate)) return exactTemplate;
  if (exactTemplate) return exactTemplate;

  const genericTemplate = templateValue(routing.generic) ||
    templateValue(routing.default) ||
    templateValue(knownRouting.generic) ||
    wallet.deep_link_template ||
    wallet.deep_link_pattern ||
    '';
  if (isWalletRoutingTemplate(genericTemplate)) return genericTemplate;
  if (genericTemplate) return genericTemplate;

  if (platformKey) return '';

  const fallbackTemplates = [
    routing.ios,
    routing.android,
    routing.web,
    routing.desktop,
    knownRouting.ios,
    knownRouting.android,
    knownRouting.web,
    knownRouting.desktop,
    knownRouting.generic,
    ...Object.values(routing),
    ...Object.values(knownRouting),
    wallet.ios_deep_link_template,
    wallet.android_deep_link_template,
    wallet.web_deep_link_template,
    wallet.deep_link_template,
    wallet.deep_link_pattern,
  ].map(templateValue);
  const nestedFallback = fallbackTemplates.find(isWalletRoutingTemplate);
  return nestedFallback || exactTemplate || genericTemplate;
}

export function resolveWalletOpenUri({ wallet, innerUri, platform = '', walletId = '' } = {}) {
  const template = resolveWalletRouteTemplate(wallet, platform);
  return renderWalletRouteTemplate(template, { innerUri, platform, walletId: walletId || wallet?.id || '' });
}

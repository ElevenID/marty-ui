export function formatMyDocumentDate(dateString) {
  if (!dateString) {
    return 'N/A';
  }

  return new Date(dateString).toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'long',
    day: 'numeric',
  });
}

export function getMyDocumentIssueDate(document = {}) {
  return document.issue_date || document.issued_at || null;
}

export function getMyDocumentExpiryDate(document = {}) {
  return document.expiry_date || document.expires_at || null;
}

export function isMyDocumentExpired(expiryDate, now = new Date()) {
  if (!expiryDate) {
    return false;
  }

  return new Date(expiryDate) < now;
}

export function isMyDocumentExpiringSoon(expiryDate, now = new Date()) {
  if (!expiryDate) {
    return false;
  }

  const expiry = new Date(expiryDate);
  const sixMonthsFromNow = new Date(now);
  sixMonthsFromNow.setMonth(sixMonthsFromNow.getMonth() + 6);

  return expiry <= sixMonthsFromNow;
}

export function getMyDocumentDisplayName(document = {}) {
  return document.metadata?.credential_display_name || document.document_type || 'Credential';
}

export function getMyDocumentStatus(document = {}, now = new Date()) {
  const expiryDate = getMyDocumentExpiryDate(document);

  if (isMyDocumentExpired(expiryDate, now)) {
    return {
      key: 'expired',
/**
 * @param {Record<string, any>} [document]
 * @param {{ nationality?: string } | null | undefined} [user]
 * @returns {string}
 */
      label: 'Expired',
      color: 'error',
    };
  }

  if (isMyDocumentExpiringSoon(expiryDate, now)) {
    return {
      key: 'expiring',
      label: 'Expiring Soon',
      color: 'warning',
    };
  }

  return {
    key: 'valid',
    label: 'Valid',
    color: 'success',
  };
}

export function getMyDocumentNationality(document = {}, user = null) {
  return document.nationality || user?.nationality || 'N/A';
}

export async function loadMyDocuments({ getMyCredentials }) {
  const result = await getMyCredentials();
  return result.items;
}

/**
 * Pure helpers for CSCA management.
 */

export const CSCA_CREATE_DEFAULTS = {
  key_algorithm: 'RSA',
  key_size: 2048,
  validity_days: 365,
};

export function resolveCscaCertificates(data = {}) {
  return data.certificates || [];
}

export function createCscaCertificatePayload({ subjectName = '' } = {}) {
  return {
    subject_name: subjectName,
    ...CSCA_CREATE_DEFAULTS,
  };
}

export function formatCscaDate(dateString) {
  if (!dateString) return 'N/A';

  return new Date(dateString).toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
  });
}

export function getCscaCertificateStatus(certificate = {}) {
  return {
    label: certificate.revoked ? 'Revoked' : 'Active',
    color: certificate.revoked ? 'error' : 'success',
  };
}

export function createCscaDeleteSuccessMessage(certificate = {}) {
  return `Certificate "${certificate.subject}" has been deleted`;
}
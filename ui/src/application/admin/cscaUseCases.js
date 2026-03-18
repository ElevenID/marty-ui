import { del, get, getErrorMessage, post } from '../../services/api';
import {
  createCscaCertificatePayload,
  createCscaDeleteSuccessMessage,
  resolveCscaCertificates,
} from './cscaFlow';

async function defaultLoadCertificates() {
  return get('/v1/trust-profiles/admin/csca');
}

async function defaultCreateCertificate(payload) {
  return post('/v1/trust-profiles/admin/csca', payload);
}

async function defaultDeleteCertificate(certificateId) {
  return del(`/v1/trust-profiles/admin/csca/${certificateId}`);
}

export async function loadCscaCertificates({
  loadCertificates = defaultLoadCertificates,
} = {}) {
  try {
    const data = await loadCertificates();
    return {
      certificates: resolveCscaCertificates(data),
      error: null,
    };
  } catch (error) {
    return {
      certificates: [],
      error: getErrorMessage(error) || 'Failed to fetch certificates',
    };
  }
}

export async function createCscaCertificate({
  subjectName,
  createCertificate = defaultCreateCertificate,
} = {}) {
  try {
    await createCertificate(createCscaCertificatePayload({ subjectName }));
    return {
      success: true,
      error: null,
    };
  } catch (error) {
    return {
      success: false,
      error: getErrorMessage(error) || 'Failed to create certificate',
    };
  }
}

export async function deleteCscaCertificate({
  certificate,
  deleteCertificate = defaultDeleteCertificate,
} = {}) {
  try {
    await deleteCertificate(certificate.id);
    return {
      success: true,
      error: null,
      successMessage: createCscaDeleteSuccessMessage(certificate),
    };
  } catch (error) {
    return {
      success: false,
      error: getErrorMessage(error) || 'Failed to delete certificate',
      successMessage: null,
    };
  }
}
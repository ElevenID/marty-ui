import { describe, expect, it, vi } from 'vitest';

import {
  createCscaCertificate,
  deleteCscaCertificate,
  loadCscaCertificates,
} from './cscaUseCases';

describe('cscaUseCases', () => {
  it('loads certificates through an injected transport', async () => {
    const loadCertificates = vi.fn().mockResolvedValue({
      certificates: [{ id: 'cert-1', subject: 'CN=Root' }],
    });

    await expect(loadCscaCertificates({ loadCertificates })).resolves.toEqual({
      certificates: [{ id: 'cert-1', subject: 'CN=Root' }],
      error: null,
    });
  });

  it('creates a certificate through an injected transport', async () => {
    const createCertificate = vi.fn().mockResolvedValue({});

    await expect(createCscaCertificate({
      subjectName: 'CN=Root',
      createCertificate,
    })).resolves.toEqual({
      success: true,
      error: null,
    });

    expect(createCertificate).toHaveBeenCalledWith({
      subject_name: 'CN=Root',
      key_algorithm: 'RSA',
      key_size: 2048,
      validity_days: 365,
    });
  });

  it('deletes a certificate through an injected transport', async () => {
    const deleteCertificate = vi.fn().mockResolvedValue({});

    await expect(deleteCscaCertificate({
      certificate: { id: 'cert-1', subject: 'CN=Root' },
      deleteCertificate,
    })).resolves.toEqual({
      success: true,
      error: null,
      successMessage: 'Certificate "CN=Root" has been deleted',
    });
  });
});
import { describe, expect, it } from 'vitest';

import {
  CSCA_CREATE_DEFAULTS,
  createCscaCertificatePayload,
  createCscaDeleteSuccessMessage,
  formatCscaDate,
  getCscaCertificateStatus,
  resolveCscaCertificates,
} from './cscaFlow';

describe('cscaFlow', () => {
  it('resolves certificates and create payload defaults', () => {
    expect(resolveCscaCertificates({ certificates: [{ id: 'cert-1' }] })).toEqual([{ id: 'cert-1' }]);
    expect(resolveCscaCertificates({})).toEqual([]);

    expect(createCscaCertificatePayload({ subjectName: 'CN=Root' })).toEqual({
      subject_name: 'CN=Root',
      ...CSCA_CREATE_DEFAULTS,
    });
  });

  it('formats dates and status consistently', () => {
    expect(formatCscaDate('2026-03-17T00:00:00.000Z')).toBeTruthy();
    expect(formatCscaDate('')).toBe('N/A');

    expect(getCscaCertificateStatus({ revoked: false })).toEqual({
      label: 'Active',
      color: 'success',
    });

    expect(getCscaCertificateStatus({ revoked: true })).toEqual({
      label: 'Revoked',
      color: 'error',
    });
  });

  it('creates a delete success message', () => {
    expect(createCscaDeleteSuccessMessage({ subject: 'CN=Root' })).toBe('Certificate "CN=Root" has been deleted');
  });
});
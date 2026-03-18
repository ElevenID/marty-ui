import { describe, expect, it } from 'vitest';

import {
  MASTER_LIST_SAMPLE_DATA,
  formatMasterListDate,
  getMasterListCertificateStatus,
  getMasterListCountryStats,
  getMasterListSummary,
  resolveMasterLists,
} from './masterListFlow';

describe('masterListFlow helpers', () => {
  it('normalizes master list payloads', () => {
    expect(resolveMasterLists({ masterLists: [{ country: 'CAN', certificates: [] }] })).toEqual([{ country: 'CAN', certificates: [] }]);
    expect(resolveMasterLists(null)).toEqual(MASTER_LIST_SAMPLE_DATA);
  });

  it('formats dates and resolves certificate status', () => {
    expect(formatMasterListDate('2026-03-17T00:00:00.000Z')).toMatch(/Mar\s(16|17),\s2026/);
    expect(getMasterListCertificateStatus({ validFrom: '2026-01-01T00:00:00.000Z', validTo: '2027-01-01T00:00:00.000Z' }, new Date('2026-03-17T00:00:00.000Z'))).toEqual({
      status: 'valid',
      color: 'success',
      label: 'Valid',
    });
  });

  it('computes country and global summary stats', () => {
    const now = new Date('2026-03-17T00:00:00.000Z');
    const masterLists = [
      {
        country: 'CAN',
        certificates: [
          { validFrom: '2025-01-01T00:00:00.000Z', validTo: '2027-01-01T00:00:00.000Z' },
          { validFrom: '2025-01-01T00:00:00.000Z', validTo: '2026-03-20T00:00:00.000Z' },
          { validFrom: '2025-01-01T00:00:00.000Z', validTo: '2026-01-01T00:00:00.000Z' },
        ],
      },
    ];

    expect(getMasterListCountryStats(masterLists[0], now)).toEqual({
      total: 3,
      valid: 1,
      expiring: 1,
      expired: 1,
    });

    expect(getMasterListSummary(masterLists, now)).toEqual({
      countryCount: 1,
      totalCertificates: 3,
      totalValid: 1,
      needsAttention: 2,
    });
  });
});

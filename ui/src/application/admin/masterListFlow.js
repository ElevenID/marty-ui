/**
 * Pure helpers for ICAO master list browsing.
 */

export const MASTER_LIST_SAMPLE_DATA = [
  {
    country: 'FRA',
    sequenceNumber: 33,
    version: '1.0.0',
    issueDate: '2025-10-04T00:43:13.053013+00:00',
    nextUpdate: '2025-11-03T00:43:13.053013+00:00',
    certificates: [
      {
        certificateId: 'FRA_CSCA_1',
        thumbprint: 'db4df868f89e0d4f0676056bfe61b1694bb3d4b9',
        subject: 'CN=FRA CSCA 1, O=FRA Government, C=FRA',
        validFrom: '2025-05-13T00:43:13.052762+00:00',
        validTo: '2026-10-02T00:43:13.052762+00:00',
      },
      {
        certificateId: 'FRA_CSCA_2',
        thumbprint: '040b21ef683b04040620158ce8d4fd792c38118a',
        subject: 'CN=FRA CSCA 2, O=FRA Government, C=FRA',
        validFrom: '2025-07-14T00:43:13.052993+00:00',
        validTo: '2028-06-05T00:43:13.052993+00:00',
      },
      {
        certificateId: 'FRA_CSCA_3',
        thumbprint: '57ca71cf7cba18bd0b4d390cef5919b00e8f453b',
        subject: 'CN=FRA CSCA 3, O=FRA Government, C=FRA',
        validFrom: '2024-11-29T00:43:13.053001+00:00',
        validTo: '2026-02-26T00:43:13.053001+00:00',
      },
      {
        certificateId: 'FRA_CSCA_4',
        thumbprint: 'cc0bdc1863719e890094c89eebdd98f9156d1be2',
        subject: 'CN=FRA CSCA 4, O=FRA Government, C=FRA',
        validFrom: '2024-11-06T00:43:13.053007+00:00',
        validTo: '2027-01-12T00:43:13.053007+00:00',
      },
    ],
    signer: 'FRA CSCA',
    metadata: {
      certificateCount: 4,
      testingOnly: true,
    },
  },
  {
    country: 'USA',
    sequenceNumber: 575,
    version: '1.0.0',
    issueDate: '2025-10-04T00:43:13.053065+00:00',
    nextUpdate: '2025-11-03T00:43:13.053065+00:00',
    certificates: [
      {
        certificateId: 'USA_CSCA_1',
        thumbprint: '790c11e07e8dcca5287f2187a34abe73f8d76251',
        subject: 'CN=USA CSCA 1, O=USA Government, C=USA',
        validFrom: '2025-07-19T00:43:13.053047+00:00',
        validTo: '2027-02-27T00:43:13.053047+00:00',
      },
      {
        certificateId: 'USA_CSCA_2',
        thumbprint: '89b61a3aabf1cec7ecbb0448b9b6bf583fd997e9',
        subject: 'CN=USA CSCA 2, O=USA Government, C=USA',
        validFrom: '2025-05-08T00:43:13.053054+00:00',
        validTo: '2027-10-07T00:43:13.053054+00:00',
      },
      {
        certificateId: 'USA_CSCA_3',
        thumbprint: 'cc6dde19f152171db7af0a1f83fdb50054e9ff33',
        subject: 'CN=USA CSCA 3, O=USA Government, C=USA',
        validFrom: '2024-10-31T00:43:13.053060+00:00',
        validTo: '2025-11-27T00:43:13.053060+00:00',
      },
    ],
    signer: 'USA CSCA',
    metadata: {
      certificateCount: 3,
      testingOnly: true,
    },
  },
  {
    country: 'ESP',
    sequenceNumber: 829,
    version: '1.0.0',
    issueDate: '2025-10-04T00:43:13.053113+00:00',
    nextUpdate: '2025-11-03T00:43:13.053113+00:00',
    certificates: [
      {
        certificateId: 'ESP_CSCA_1',
        thumbprint: '5870e1a10e7bde197513ad2595424217b9545747',
        subject: 'CN=ESP CSCA 1, O=ESP Government, C=ESP',
        validFrom: '2024-10-07T00:43:13.053091+00:00',
        validTo: '2027-09-25T00:43:13.053091+00:00',
      },
      {
        certificateId: 'ESP_CSCA_2',
        thumbprint: '225d34f50ea9261dce673af8d32c8962875e9ea5',
        subject: 'CN=ESP CSCA 2, O=ESP Government, C=ESP',
        validFrom: '2024-11-29T00:43:13.053098+00:00',
        validTo: '2027-02-01T00:43:13.053098+00:00',
      },
      {
        certificateId: 'ESP_CSCA_3',
        thumbprint: '2c7c92d463ad76f16f7c08b4ed6a92377b258822',
        subject: 'CN=ESP CSCA 3, O=ESP Government, C=ESP',
        validFrom: '2025-05-15T00:43:13.053102+00:00',
        validTo: '2027-08-17T00:43:13.053102+00:00',
      },
      {
        certificateId: 'ESP_CSCA_4',
        thumbprint: 'e3c9c5a29b62eb2d4192238af7ff0cd77d3252c6',
        subject: 'CN=ESP CSCA 4, O=ESP Government, C=ESP',
        validFrom: '2024-11-07T00:43:13.053107+00:00',
        validTo: '2026-08-18T00:43:13.053107+00:00',
      },
    ],
    signer: 'ESP CSCA',
    metadata: {
      certificateCount: 4,
      testingOnly: true,
    },
  },
];

export function resolveMasterLists(data, fallback = MASTER_LIST_SAMPLE_DATA) {
  if (Array.isArray(data)) {
    return data;
  }

  if (Array.isArray(data?.masterLists)) {
    return data.masterLists;
  }

  return fallback;
}

export function getMasterListCertificateStatus(cert, now = new Date()) {
  const validFrom = new Date(cert.validFrom);
  const validTo = new Date(cert.validTo);

  if (now < validFrom) {
    return { status: 'pending', color: 'warning', label: 'Not Yet Valid' };
  }

  if (now > validTo) {
    return { status: 'expired', color: 'error', label: 'Expired' };
  }

  const thirtyDaysFromNow = new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000);
  if (validTo < thirtyDaysFromNow) {
    return { status: 'expiring', color: 'warning', label: 'Expiring Soon' };
  }

  return { status: 'valid', color: 'success', label: 'Valid' };
}

export function formatMasterListDate(dateString) {
  return new Date(dateString).toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
  });
}

export function getMasterListCountryStats(masterList, now = new Date()) {
  const certificates = masterList?.certificates || [];
  const total = certificates.length;
  const valid = certificates.filter((cert) => getMasterListCertificateStatus(cert, now).status === 'valid').length;
  const expiring = certificates.filter((cert) => getMasterListCertificateStatus(cert, now).status === 'expiring').length;
  const expired = certificates.filter((cert) => getMasterListCertificateStatus(cert, now).status === 'expired').length;

  return { total, valid, expiring, expired };
}

export function getMasterListSummary(masterLists, now = new Date()) {
  const totalCertificates = masterLists.reduce((acc, masterList) => acc + (masterList.certificates?.length || 0), 0);
  const totalValid = masterLists.reduce(
    (acc, masterList) => acc + (masterList.certificates || []).filter((cert) => getMasterListCertificateStatus(cert, now).status === 'valid').length,
    0
  );

  return {
    countryCount: masterLists.length,
    totalCertificates,
    totalValid,
    needsAttention: totalCertificates - totalValid,
  };
}

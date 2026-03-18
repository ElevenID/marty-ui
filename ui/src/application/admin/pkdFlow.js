/**
 * Pure helpers for PKD management.
 */

export const PKD_DEFAULT_DIRECTORY_STATUS = [
  {
    key: 'ldap',
    primary: 'LDAP Service',
    secondary: 'Running - Port 389',
    status: 'healthy',
  },
  {
    key: 'http',
    primary: 'HTTP Service',
    secondary: 'Running - Port 8080',
    status: 'healthy',
  },
  {
    key: 'replication',
    primary: 'Replication',
    secondary: 'Active',
    status: 'healthy',
  },
];

export const PKD_DEFAULT_STATISTICS = [
  {
    key: 'active-csca-certs',
    value: '142',
    label: 'Active CSCA Certs',
  },
  {
    key: 'document-signer-certs',
    value: '1,205',
    label: 'Document Signer Certs',
  },
  {
    key: 'crls-published',
    value: '58',
    label: 'CRLs Published',
  },
  {
    key: 'availability',
    value: '24/7',
    label: 'Availability',
  },
];

export function createPkdSyncSuccess(message = 'PKD synchronization completed successfully.') {
  return {
    syncStatus: 'success',
    message,
  };
}

export function createPkdSyncError(message = 'Sync failed') {
  return {
    syncStatus: 'error',
    message,
  };
}

const structuredModes = {
  access_key: [
    { name: 'access_key_id', label: 'Access key ID', required: true },
    { name: 'secret_access_key', label: 'Secret access key', required: true, secret: true },
    { name: 'session_token', label: 'Session token', secret: true },
  ],
  assume_role: [
    { name: 'role_arn', label: 'Role ARN', required: true },
    { name: 'external_id', label: 'External ID', secret: true },
  ],
  managed_identity: [
    { name: 'client_id', label: 'User-assigned client ID (optional)' },
  ],
  client_secret: [
    { name: 'tenant_id', label: 'Tenant ID', required: true },
    { name: 'client_id', label: 'Client ID', required: true },
    { name: 'client_secret', label: 'Client secret', required: true, secret: true },
  ],
  service_account: [
    { name: 'email', label: 'Service account email', required: true },
  ],
}

const unavailableModes = new Set(['certificate', 'approle', 'mtls', 'api_key', 'custom', 'service_token'])
const identityModes = new Set(['iam_role', 'workload_identity'])

export const isAuthModeAvailable = (mode) => !unavailableModes.has(mode)

export const authFieldsForMode = (mode) => structuredModes[mode] || []

export const authModeHelp = (mode) => {
  switch (mode) {
    case 'iam_role':
      return 'Uses the service workload identity from web identity, container credentials, or EC2 metadata.'
    case 'workload_identity':
      return 'Uses the Google Cloud workload identity available to this service.'
    case 'service_token':
      return 'Uses the managed OpenBao token mounted into the signing service.'
    case 'managed_identity':
      return 'Uses the Azure managed identity of this service. Set a client ID only for a user-assigned identity.'
    case 'service_account':
      return 'Impersonates this service account using the Google Cloud workload identity of this service. Do not enter a JSON key.'
    case 'assume_role':
      return 'Assumes this AWS role using the service workload identity.'
    case 'token':
      return 'Enter a transit token. Marty encrypts it before storing the service registration.'
    case 'access_key':
    case 'client_secret':
      return 'Marty encrypts these credentials before storing the service registration.'
    default:
      return 'This mode requires provider-side support before registration.'
  }
}

export const isAuthComplete = (mode, values = {}) => {
  if (!isAuthModeAvailable(mode)) return false
  if (identityModes.has(mode)) return true
  if (mode === 'token') return Boolean(values.token?.trim())
  const fields = authFieldsForMode(mode)
  if (fields.length === 0) return false
  return fields.every((field) => !field.required || Boolean(values[field.name]?.trim()))
}

export const serializeAuthReference = (mode, values = {}) => {
  if (identityModes.has(mode)) return ''
  if (mode === 'token') return values.token?.trim() || ''
  const entries = authFieldsForMode(mode)
    .map(({ name }) => [name, values[name]?.trim() || ''])
    .filter(([, value]) => value)
  return entries.length ? JSON.stringify(Object.fromEntries(entries)) : ''
}

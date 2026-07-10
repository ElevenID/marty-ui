import { useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useNavigate } from 'react-router-dom'
import {
  Alert,
  Box,
  Button,
  Chip,
  CircularProgress,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  Grid,
  Paper,
  Stack,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  TextField,
  Typography,
} from '@mui/material'
import ContentCopyIcon from '@mui/icons-material/ContentCopy'
import AddIcon from '@mui/icons-material/Add'
import LanguageIcon from '@mui/icons-material/Language'
import AccountTreeIcon from '@mui/icons-material/AccountTree'

import signingKeysApi from '../../../services/signingKeysApi'
import { getOrganizationLifecycle } from '../../../services/dashboardApi'
import ResourcePage from '../../common/ResourcePage'
import EmptyState from '../../common/EmptyState'
import ErrorState from '../../common/ErrorState'
import { TableSkeleton } from '../../common/skeletons'
import { useNotifications } from '../../../hooks/useNotifications'
import { useAsyncData } from '../../../hooks/useAsyncData'
import { useAuth } from '../../../hooks/useAuth'
import { useConsole } from '../../../contexts/ConsoleContext'
import {
  DEFAULT_KEY_MANAGEMENT_CONFIG,
  normalizeKeyManagementConfig,
} from './keyManagementServiceCatalog'
import {
  buildDidIdentities,
  buildDidMethodCatalog,
  getDidIdentityBreadcrumbs,
} from './didIdentityUtils'
import {
  getDidWebX509ChainGateMessage,
  isDidWebX509ChainEligible,
  normalizePlanTier,
} from './kmsEntitlements'

const EMPTY_KEYS = []
const EMPTY_PROFILES = []

const GENERIC_ISSUER_PROFILE_NAMES = new Set([
  'did:web identity',
  'did:jwk identity',
  'did:key identity',
  'did:web issuer',
  'did:jwk issuer',
  'did:key issuer',
])

const KEY_REFERENCE_PREFIX = /^cred-(issuer|dsc|key|signer)-/i

function logDidIdentitiesPageError(message, error) {
  if (import.meta.env?.DEV && import.meta.env?.MODE !== 'test') {
    console.error(message, error)
  }
}

const humanizeProfileSegment = (value) => value
  .split(/[-_]+/)
  .filter(Boolean)
  .map((segment) => {
    const normalized = segment.toLowerCase()
    if (normalized === 'es256' || normalized === 'es384' || normalized === 'rs256' || normalized === 'eddsa') {
      return normalized.toUpperCase()
    }
    return segment.charAt(0).toUpperCase() + segment.slice(1)
  })
  .join(' ')

const getSigningKeyHint = (signingKeyReference) => {
  if (typeof signingKeyReference !== 'string') {
    return ''
  }
  const trimmed = signingKeyReference.trim()
  if (!trimmed) {
    return ''
  }
  const compact = trimmed.replace(KEY_REFERENCE_PREFIX, '')
  return humanizeProfileSegment(compact || trimmed)
}

const normalizeLower = (value) => (typeof value === 'string' ? value.trim().toLowerCase() : '')

const getDidMethodFromProfile = (issuerDid) => {
  if (typeof issuerDid !== 'string') {
    return ''
  }
  if (issuerDid.startsWith('did:web:')) {
    return 'did:web'
  }
  if (issuerDid.startsWith('did:jwk:')) {
    return 'did:jwk'
  }
  if (issuerDid.startsWith('did:key:')) {
    return 'did:key'
  }
  return ''
}

const getSigningKeyServiceId = (signingKey) => (
  signingKey?.signing_service_id
  || signingKey?.service_id
  || signingKey?.metadata?.signing_service_id
  || signingKey?.metadata?.service_id
  || ''
)

const getIssuerProfileDisplayName = (profile, organizationName) => {
  const explicitName = typeof profile?.name === 'string' ? profile.name.trim() : ''
  const signingKeyHint = getSigningKeyHint(profile?.signing_key_reference)

  if (explicitName && !GENERIC_ISSUER_PROFILE_NAMES.has(explicitName.toLowerCase())) {
    return explicitName
  }

  const didMethod = getDidMethodFromProfile(profile?.issuer_did)
  const orgLabel = typeof organizationName === 'string' ? organizationName.trim() : ''
  const withKeyHint = (baseLabel) => (signingKeyHint ? `${baseLabel} (${signingKeyHint})` : baseLabel)

  if (orgLabel && didMethod) {
    if (didMethod === 'did:web') {
      return withKeyHint(`${orgLabel} web issuer`)
    }
    if (didMethod === 'did:jwk') {
      return withKeyHint(`${orgLabel} JWK issuer`)
    }
    if (didMethod === 'did:key') {
      return withKeyHint(`${orgLabel} key issuer`)
    }
  }

  if (didMethod === 'did:web' && typeof profile?.issuer_did === 'string') {
    const didParts = profile.issuer_did.replace(/^did:web:/, '').split(':').filter(Boolean)
    const pathParts = didParts.slice(1)
    const lastPathPart = pathParts[pathParts.length - 1]
    if (lastPathPart) {
      return withKeyHint(`${humanizeProfileSegment(lastPathPart)} issuer`)
    }
    if (didParts[0]) {
      return withKeyHint(`${didParts[0]} issuer`)
    }
  }

  return withKeyHint(explicitName || profile?.issuer_did || 'Issuer profile')
}

const getStatusColor = (status) => {
  switch (status) {
    case 'ready':
    case 'active':
      return 'success'
    case 'draft':
      return 'warning'
    case 'revoked':
      return 'error'
    default:
      return 'default'
  }
}

const getProfileUsageLabel = (profile) => {
  const purpose = normalizeLower(profile?.key_purpose)
  if (purpose === 'mdoc_dsc' || purpose === 'x509_doc_signer') {
    return 'Document signing'
  }
  if (purpose === 'jwks_signing') {
    return 'JWKS signing'
  }

  const signingRef = normalizeLower(profile?.signing_key_reference)
  if (signingRef.includes('cred-dsc')) {
    return 'Document signing'
  }
  if (signingRef.includes('jwks')) {
    return 'JWKS signing'
  }

  return 'Credential issuance'
}

function OverviewStatCard({ label, value, helper, monospace = false }) {
  return (
    <Paper variant="outlined" sx={{ p: 1.5, height: '100%' }}>
      <Typography variant="caption" color="text.secondary" sx={{ display: 'block', letterSpacing: 0.35 }}>
        {label}
      </Typography>
      <Typography
        variant="h6"
        sx={{
          mt: 0.5,
          wordBreak: 'break-word',
          fontFamily: monospace ? 'Consolas, Monaco, monospace' : 'inherit',
        }}
      >
        {value}
      </Typography>
      <Typography variant="caption" color="text.secondary" sx={{ display: 'block', mt: 0.25 }}>
        {helper}
      </Typography>
    </Paper>
  )
}

function SectionHeader({ eyebrow, title, description }) {
  return (
    <Box sx={{ mb: 3 }}>
      <Typography variant="overline" color="text.secondary" sx={{ display: 'block', mb: 0.5 }}>
        {eyebrow}
      </Typography>
      <Typography variant="h5" sx={{ mb: 1 }}>
        {title}
      </Typography>
      <Typography variant="body1" color="text.secondary">
        {description}
      </Typography>
    </Box>
  )
}

function MethodSupportCard({
  method,
  description,
}) {
  const protocolLinks = {
    'did:web': {
      href: 'https://w3c-ccg.github.io/did-method-web/',
      label: 'did:web specification',
    },
    'did:jwk': {
      href: 'https://github.com/quartzjer/did-jwk',
      label: 'did:jwk specification draft',
    },
    'did:key': {
      href: 'https://w3c-ccg.github.io/did-key-spec/',
      label: 'did:key specification',
    },
  }
  const protocol = protocolLinks[method]

  return (
    <Paper variant="outlined" sx={{ p: 2.5, height: '100%' }}>
      <Stack direction="row" spacing={1} alignItems="center" useFlexGap flexWrap="wrap" sx={{ mb: 1 }}>
        <Typography variant="h6">{method}</Typography>
      </Stack>
      <Typography variant="body2" color="text.secondary" sx={{ mb: 1.5 }}>
        {description}
      </Typography>
      {protocol && (
        <Button
          size="small"
          variant="text"
          component="a"
          href={protocol.href}
          target="_blank"
          rel="noreferrer"
        >
          Read {protocol.label}
        </Button>
      )}
    </Paper>
  )
}

function IdentityRecordCard({ identity, selected, onSelect }) {
  // Truncate long identifiers for display
  const truncateIdentifier = (str, maxLength = 24) => {
    if (typeof str !== 'string') return ''
    return str.length > maxLength ? str.slice(0, maxLength) + '…' : str
  }

  return (
    <Paper
      variant="outlined"
      onClick={onSelect}
      sx={{
        p: 2,
        width: '100%',
        cursor: 'pointer',
        borderColor: selected ? 'primary.main' : 'divider',
        bgcolor: selected ? 'action.selected' : 'background.paper',
        transition: 'border-color 0.2s ease, background-color 0.2s ease',
        boxSizing: 'border-box',
      }}
    >
      <Stack spacing={1.5}>
        <Stack direction={{ xs: 'column', sm: 'row' }} spacing={1.5} justifyContent="space-between">
          <Box sx={{ minWidth: 0, flex: 1 }}>
            <Stack direction="row" spacing={1} useFlexGap flexWrap="wrap" sx={{ mb: 1, minHeight: '32px', alignContent: 'flex-start' }}>
              <Chip size="small" label={identity.method} variant="outlined" />
              <Chip size="small" color={getStatusColor(identity.status)} label={identity.readinessLabel} />
              <Chip size="small" label={identity.documentKind === 'template' ? 'Template' : 'Document'} />
              <Chip size="small" color="primary" label="Selected" sx={{ visibility: selected ? 'visible' : 'hidden' }} />
            </Stack>

            <Typography variant="body2" fontFamily="monospace" sx={{ mb: 0.75, wordBreak: 'break-word' }} title={identity.did}>
              {truncateIdentifier(identity.did)}
            </Typography>
            <Typography variant="body2" color="text.secondary">
              Used for: {identity.associatedWith}
            </Typography>
            <Typography variant="caption" color="text.secondary">
              Source: {identity.source}
            </Typography>
          </Box>

          <Box>
            <Button
              size="small"
              variant={selected ? 'contained' : 'outlined'}
              onClick={(event) => {
                event.stopPropagation()
                onSelect()
              }}
            >
              {selected ? 'Viewing JSON' : 'Preview JSON'}
            </Button>
          </Box>
        </Stack>

        {identity.issues?.length > 0 && (
          <Alert severity="warning">
            {identity.issues[0]}
          </Alert>
        )}
      </Stack>
    </Paper>
  )
}

function ImportDidDialog({ open, signingKey, organizationId, onClose, onImported }) {
  const [didValue, setDidValue] = useState('')
  const [label, setLabel] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState('')
  const { showNotification } = useNotifications()

  const keyLabel = signingKey?.name || signingKey?.provider_key_name || signingKey?.id || 'Signing key'
  const signingServiceId = getSigningKeyServiceId(signingKey)

  const isValidDid = (value) => /^did:[a-z0-9]+:.+/.test(value.trim())

  const handleClose = () => {
    setDidValue('')
    setLabel('')
    setError('')
    onClose()
  }

  const handleSubmit = async () => {
    const trimmedDid = didValue.trim()
    if (!isValidDid(trimmedDid)) {
      setError('Enter a valid DID (e.g. did:web:example.com or did:key:z6Mk…)')
      return
    }
    if (!organizationId) {
      setError('An active organization is required before importing a DID.')
      return
    }
    if (!signingServiceId) {
      setError('This signing key is not linked to a key management service. Select a KMS-backed key before importing a DID.')
      return
    }
    setSubmitting(true)
    setError('')
    try {
      await signingKeysApi.createIssuerProfile({
        organization_id: organizationId,
        name: label.trim() || `${keyLabel} — imported`,
        issuer_did: trimmedDid,
        signing_service_id: signingServiceId,
        signing_key_reference: signingKey?.provider_key_name || signingKey?.id || undefined,
        status: 'active',
      })
      showNotification?.('DID imported and issuer profile created.', 'success')
      handleClose()
      onImported()
    } catch (err) {
      setError(err?.response?.data?.detail || err?.message || 'Failed to import DID.')
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <Dialog open={open} onClose={handleClose} maxWidth="sm" fullWidth>
      <DialogTitle>Import existing DID</DialogTitle>
      <DialogContent>
        <Stack spacing={2} sx={{ mt: 0.5 }}>
          <Typography variant="body2" color="text.secondary">
            Link a DID that was created outside Marty to the signing key <strong>{keyLabel}</strong>.
            An issuer profile will be created so this key can be used for credential issuance.
          </Typography>
          <TextField
            label="DID"
            placeholder="did:web:example.com or did:key:z6Mk…"
            value={didValue}
            onChange={(e) => { setDidValue(e.target.value); setError('') }}
            fullWidth
            size="small"
            inputProps={{ spellCheck: false }}
            error={Boolean(error)}
            helperText={error || 'Paste the full DID string associated with this key.'}
            autoFocus
          />
          <TextField
            label="Profile label (optional)"
            placeholder={`${keyLabel} — imported`}
            value={label}
            onChange={(e) => setLabel(e.target.value)}
            fullWidth
            size="small"
            helperText="Human-readable name for this issuer profile."
          />
          {!signingServiceId && (
            <Alert severity="warning">
              This signing key is missing its key management service binding. Import is unavailable until the key is repaired or recreated through KMS.
            </Alert>
          )}
        </Stack>
      </DialogContent>
      <DialogActions sx={{ px: 3, pb: 2 }}>
        <Button onClick={handleClose} disabled={submitting}>Cancel</Button>
        <Button
          variant="contained"
          onClick={handleSubmit}
          disabled={submitting || !didValue.trim() || !signingServiceId}
          startIcon={submitting ? <CircularProgress size={16} /> : null}
        >
          Import DID
        </Button>
      </DialogActions>
    </Dialog>
  )
}

function UnboundKeyCard({ signingKey, onCreateDid, onImportDid }) {
  const keyLabel = signingKey.name || signingKey.provider_key_name || signingKey.id || 'Signing key'
  const keyHint = signingKey.provider_key_name || signingKey.id

  return (
    <Paper
      variant="outlined"
      sx={{
        p: 2,
        width: '100%',
        boxSizing: 'border-box',
        borderColor: 'warning.main',
        borderStyle: 'dashed',
      }}
    >
      <Stack direction={{ xs: 'column', sm: 'row' }} spacing={1.5} justifyContent="space-between" alignItems={{ sm: 'center' }}>
        <Box sx={{ minWidth: 0, flex: 1 }}>
          <Stack direction="row" spacing={1} useFlexGap flexWrap="wrap" sx={{ mb: 0.75, alignContent: 'flex-start' }}>
            <Chip size="small" color="warning" label="No DID configured" />
          </Stack>
          <Typography variant="body2" sx={{ mb: 0.25, fontWeight: 500 }}>
            {keyLabel}
          </Typography>
          {keyHint && keyHint !== keyLabel && (
            <Typography variant="caption" color="text.secondary" fontFamily="monospace">
              {keyHint}
            </Typography>
          )}
          <Typography variant="caption" color="text.secondary" sx={{ display: 'block', mt: 0.5 }}>
            This key has no associated DID identity. Create a new one or import an existing DID.
          </Typography>
        </Box>
        <Stack direction="row" spacing={1} sx={{ flexShrink: 0 }}>
          <Button size="small" variant="outlined" onClick={onImportDid}>
            Import DID
          </Button>
          <Button size="small" variant="outlined" color="warning" onClick={onCreateDid}>
            Create DID
          </Button>
        </Stack>
      </Stack>
    </Paper>
  )
}

function DidDocumentPanel({ identity, onCopy }) {
  if (!identity) {
    return (
      <Paper variant="outlined" sx={{ p: 3, minHeight: { xs: 320, lg: 680 } }}>
        <Typography variant="overline" color="text.secondary" sx={{ display: 'block', mb: 0.5 }}>
          Selected artifact
        </Typography>
        <Typography variant="h6" sx={{ mb: 1 }}>
          DID document preview
        </Typography>
        <Typography variant="body2" color="text.secondary">
          Choose an identity on the left to inspect the exact JSON artifact. This panel only covers the publishable DID document or did.json template, not issuer profile activation.
        </Typography>
      </Paper>
    )
  }

  return (
    <Paper
      variant="outlined"
      sx={{
        p: 3,
        width: '100%',
        maxWidth: '100%',
        minWidth: 0,
        overflow: 'hidden',
        display: 'flex',
        flexDirection: 'column',
        minHeight: { xs: 420, lg: 680 },
        height: { lg: 680 },
      }}
    >
      <Stack direction={{ xs: 'column', sm: 'row' }} justifyContent="space-between" spacing={2} sx={{ mb: 2, minWidth: 0, flex: '0 0 auto' }}>
        <Box sx={{ minWidth: 0, flex: 1 }}>
          <Typography variant="overline" color="text.secondary" sx={{ display: 'block', mb: 0.5 }}>
            Selected artifact
          </Typography>
          <Typography
            variant="h6"
            sx={{
              mb: 1,
              minWidth: 0,
              maxWidth: '100%',
              wordBreak: 'break-word',
              overflowWrap: 'anywhere',
            }}
          >
            {identity.did}
          </Typography>
          <Stack direction="row" spacing={1} alignItems="center" useFlexGap flexWrap="wrap" sx={{ mb: 1, minWidth: 0 }}>
            <Chip size="small" label={identity.method} variant="outlined" />
            <Chip size="small" color={getStatusColor(identity.status)} label={identity.readinessLabel} />
            <Chip size="small" label={identity.documentKind === 'template' ? 'Template' : 'Document'} />
          </Stack>
          <Typography variant="body2" color="text.secondary">
            Inspect the JSON that will be published or hosted. Issuance flows reference issuer profiles separately.
          </Typography>
          <Typography variant="body2" color="text.secondary" sx={{ mt: 0.5 }}>
            Source: {identity.source} · Associated with: {identity.associatedWith}
          </Typography>
        </Box>

        <Button variant="outlined" startIcon={<ContentCopyIcon />} onClick={() => onCopy(identity.document)} sx={{ flexShrink: 0 }}>
          Copy JSON
        </Button>
      </Stack>

      {identity.issues?.length > 0 && (
        <Alert severity="warning" sx={{ mb: 2 }}>
          {identity.issues[0]}
        </Alert>
      )}

      <Typography
        component="pre"
        sx={{
          flex: 1,
          minHeight: 0,
          width: '100%',
          maxWidth: '100%',
          p: 2,
          m: 0,
          borderRadius: 1,
          overflowX: 'auto',
          overflowY: 'auto',
          scrollbarGutter: 'stable',
          bgcolor: 'grey.100',
          fontSize: '0.8125rem',
          lineHeight: 1.5,
          fontFamily: 'Consolas, Monaco, monospace',
        }}
      >
        {JSON.stringify(identity.document, null, 2)}
      </Typography>
    </Paper>
  )
}

export default function DidIdentitiesPage() {
  const { t } = useTranslation('console')
  const navigate = useNavigate()
  const { organizationId, organizationName } = useAuth()
  const { activeOrgId } = useConsole()
  const effectiveOrganizationId = activeOrgId || organizationId
  const { showNotification } = useNotifications()
  const { data: signingKeysData, loading, error, reload } = useAsyncData(async () => {
    const data = await signingKeysApi.listSigningKeys({ organization_id: effectiveOrganizationId })
    const rawKeys = Array.isArray(data) ? data : data?.keys || []
    return {
      keys: Array.isArray(rawKeys) ? rawKeys.filter((key) => key && typeof key === 'object') : [],
      domainConfig: data?.domain_config || null,
      providerMetadata: data?.provider_metadata || null,
    }
  }, [effectiveOrganizationId])

  const {
    data: keyManagementData,
  } = useAsyncData(
    async () => normalizeKeyManagementConfig(
      await signingKeysApi.getKeyManagementConfig({ organization_id: effectiveOrganizationId })
    ),
    [effectiveOrganizationId]
  )

  const { data: organizationLifecycle } = useAsyncData(async () => {
    if (!effectiveOrganizationId) {
      return null
    }
    return getOrganizationLifecycle(effectiveOrganizationId)
  }, [effectiveOrganizationId])

  const {
    data: issuerProfilesData,
    loading: issuerProfilesLoading,
    error: issuerProfilesError,
    reload: reloadIssuerProfiles,
  } = useAsyncData(async () => {
    const response = await signingKeysApi.listIssuerProfiles({ organization_id: effectiveOrganizationId })
    return response?.profiles || []
  }, [effectiveOrganizationId])

  const safeKeys = Array.isArray(signingKeysData?.keys) ? signingKeysData.keys : EMPTY_KEYS
  const issuerProfiles = Array.isArray(issuerProfilesData) ? issuerProfilesData : EMPTY_PROFILES
  const keyManagementConfig = normalizeKeyManagementConfig(keyManagementData || DEFAULT_KEY_MANAGEMENT_CONFIG)
  const domainSummary = keyManagementConfig.domain_config || signingKeysData?.domainConfig || null
  const planTier = normalizePlanTier(organizationLifecycle?.planTier)
  const didWebX509ChainEligible = isDidWebX509ChainEligible(planTier)

  const identities = useMemo(
    () => buildDidIdentities({ keys: safeKeys, domainSummary }),
    [safeKeys, domainSummary]
  )

  const keysWithoutDid = useMemo(() => {
    const boundKeyIds = new Set(identities.map((id) => id.backingKeyId).filter(Boolean))
    return safeKeys.filter((key) => key?.id && !boundKeyIds.has(key.id))
  }, [safeKeys, identities])

  const methodCatalog = useMemo(
    () => buildDidMethodCatalog(safeKeys, domainSummary),
    [safeKeys, domainSummary]
  )
  const [selectedIdentityId, setSelectedIdentityId] = useState(null)
  const [importDialogKey, setImportDialogKey] = useState(null)

  const configuredServiceCount = Math.max(
    Array.isArray(keyManagementConfig.services) ? keyManagementConfig.services.length : 0,
    safeKeys.length > 0 ? 1 : 0,
  )
  const activeIssuerProfiles = issuerProfiles.filter((profile) => profile.status === 'active').length
  const publicDomain = domainSummary?.public_domain || ''
  const issuanceProfileStats = useMemo(() => {
    const total = issuerProfiles.length
    const active = issuerProfiles.filter((profile) => profile.status === 'active').length

    const methodCounts = issuerProfiles.reduce((acc, profile) => {
      const method = getDidMethodFromProfile(profile?.issuer_did)
      if (method) {
        acc[method] = (acc[method] || 0) + 1
      }
      return acc
    }, {})

    const usageCounts = issuerProfiles.reduce((acc, profile) => {
      const usage = getProfileUsageLabel(profile)
      acc[usage] = (acc[usage] || 0) + 1
      return acc
    }, {})

    const methodSummary = Object.entries(methodCounts)
      .sort(([, aCount], [, bCount]) => bCount - aCount)
      .slice(0, 3)
      .map(([method, count]) => `${method} (${count})`)
      .join(' · ') || 'No DID methods yet'

    const usageSummary = Object.entries(usageCounts)
      .sort(([, aCount], [, bCount]) => bCount - aCount)
      .slice(0, 2)
      .map(([usage, count]) => `${usage} (${count})`)
      .join(' · ') || 'No usage yet'

    return {
      total,
      active,
      activeRate: total > 0 ? Math.round((active / total) * 100) : 0,
      methodSummary,
      usageSummary,
    }
  }, [issuerProfiles])

  const selectedIdentity = identities.find((identity) => identity.id === selectedIdentityId) || identities[0] || null

  const handleCopyJson = async (document) => {
    try {
      await navigator.clipboard.writeText(JSON.stringify(document, null, 2))
      showNotification?.('Copied DID document JSON to clipboard.', 'success')
    } catch (err) {
      logDidIdentitiesPageError('Failed to copy DID document JSON:', err)
      showNotification?.('Unable to copy DID document JSON.', 'error')
    }
  }

  const renderIdentityRecords = () => {
    if (loading) {
      return <TableSkeleton rows={4} columns={4} showActions={false} />
    }

    if (error) {
      return <ErrorState error={error} onRetry={reload} variant="inline" />
    }

    if (identities.length === 0) {
      return (
        <EmptyState
          icon={LanguageIcon}
          title="No DID identities can be derived yet"
          description="Configure a domain or expose public key material from your signing service to derive managed DID identities."
          whyItMatters="This section only shows publishable DID artifacts. Issuer profiles come later, once a DID can actually be referenced by issuance flows."
          actionLabel="Go to key management"
          onAction={() => navigate('/console/org/deploy/key-management')}
        />
      )
    }

    return (
      <Stack spacing={1.5} sx={{ width: '100%', boxSizing: 'border-box' }}>
        {identities.map((identity) => (
          <IdentityRecordCard
            key={identity.id}
            identity={identity}
            selected={selectedIdentity?.id === identity.id}
            onSelect={() => setSelectedIdentityId(identity.id)}
          />
        ))}
        {keysWithoutDid.map((key) => (
          <UnboundKeyCard
            key={key.id}
            signingKey={key}
            onCreateDid={() => navigate(`/console/org/deploy/issuer-identity/new?prefill_key_id=${encodeURIComponent(key.id)}`)}
            onImportDid={() => setImportDialogKey(key)}
          />
        ))}
      </Stack>
    )
  }

  return (
    <ResourcePage
      title="Issuer Identity"
      description="Create and manage issuer DIDs, method readiness, key bindings, and DID document publication state."
      resourceName="Issuer identities"
      breadcrumbs={getDidIdentityBreadcrumbs(t)}
      icon={<LanguageIcon />}
      pageTestId="deploy.issuerIdentity.page"
    >
      <Stack spacing={3.5}>
        <Paper variant="outlined" sx={{ p: { xs: 2.5, md: 3 } }}>
          <Stack spacing={2}>
            <Box>
              <Typography variant="overline" color="text.secondary" sx={{ display: 'block', mb: 0.5 }}>
                Issuer identity workflow
              </Typography>
              <Typography variant="h4" sx={{ mb: 1.5 }}>
                Manage issuer identities
              </Typography>
              <Typography variant="body1" color="text.secondary" sx={{ mb: 2.5 }}>
                Create, review, and activate DID-backed issuer profiles for your organization.
              </Typography>

              <Stack direction={{ xs: 'column', sm: 'row' }} spacing={1.5} useFlexGap flexWrap="wrap" sx={{ mb: 1.5 }}>
                <Button
                  variant="contained"
                  startIcon={<AddIcon />}
                  onClick={() => navigate('/console/org/deploy/issuer-identity/new')}
                >
                  Create DID identity
                </Button>
                <Button
                  variant="outlined"
                  startIcon={<AccountTreeIcon />}
                  onClick={() => navigate('/console/org/trust/profiles/new?mode=advanced&prefill_source=did-identities')}
                  disabled={!didWebX509ChainEligible}
                >
                  Configure X.509 trust chain
                </Button>
              </Stack>

              <Stack direction={{ xs: 'column', md: 'row' }} spacing={1} useFlexGap flexWrap="wrap">
                <Box sx={{ flex: '1 1 210px', minWidth: { xs: '100%', md: 210 } }}>
                  <OverviewStatCard
                    label="Active issuer profiles"
                    value={String(activeIssuerProfiles)}
                    helper="Profiles that issuance flows can use today"
                  />
                </Box>
                <Box sx={{ flex: '1 1 210px', minWidth: { xs: '100%', md: 210 } }}>
                  <OverviewStatCard
                    label="Connected signing services"
                    value={String(configuredServiceCount)}
                    helper="KMS/HSM connections available to this org"
                  />
                </Box>
                <Box sx={{ flex: '1 1 210px', minWidth: { xs: '100%', md: 210 } }}>
                  <OverviewStatCard
                    label="Public domain"
                    value={publicDomain || 'Not set'}
                    helper="Needed for production did:web publication"
                    monospace={Boolean(publicDomain)}
                  />
                </Box>
              </Stack>
            </Box>

            <Box>
              <Typography variant="h6" sx={{ mb: 0.75 }}>
                DID methods reference
              </Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                Select a DID method for issuer identity documents. Remote key-management readiness is tracked separately in key management.
              </Typography>

              <Alert severity="info" sx={{ mb: 2.5 }}>
                Marty stores connector metadata and generated DID artifacts only. Private keys remain in your external KMS/HSM.
              </Alert>

              <Grid container spacing={2}>
                {methodCatalog.map((entry) => (
                  <Grid item xs={12} md={4} key={entry.method}>
                    <MethodSupportCard {...entry} />
                  </Grid>
                ))}
              </Grid>
            </Box>
          </Stack>
        </Paper>

        <Paper variant="outlined" sx={{ p: { xs: 2.5, md: 3 }, overflow: 'hidden' }}>
          <SectionHeader
            eyebrow="DID artifacts"
            title="Generated DID documents and templates"
            description="Review the generated DID JSON and did.json templates for your configured keys and domain."
          />

          <Grid container spacing={3} sx={{ minWidth: 0 }}>
            <Grid item xs={12} lg={5} sx={{ minWidth: 0 }}>
              <Box sx={{ maxHeight: { lg: 680 }, overflowX: 'hidden', overflowY: 'auto', scrollbarGutter: 'stable' }}>
                {renderIdentityRecords()}
              </Box>
            </Grid>
            <Grid item xs={12} lg={7} sx={{ minWidth: 0, overflow: 'hidden' }}>
              <DidDocumentPanel identity={selectedIdentity} onCopy={handleCopyJson} />
            </Grid>
          </Grid>
        </Paper>

        <Paper variant="outlined" sx={{ p: { xs: 2.5, md: 3 } }}>
          <SectionHeader
            eyebrow="Issuance profiles"
            title="Profiles powering issuance"
            description="Quick view of how many issuer profiles are in use and what they are used for."
          />

          {!issuerProfilesLoading && !issuerProfilesError && issuerProfiles.length > 0 && (
            <Stack direction={{ xs: 'column', md: 'row' }} spacing={1} useFlexGap flexWrap="wrap" sx={{ mb: 2 }}>
              <Box sx={{ flex: '1 1 220px', minWidth: { xs: '100%', md: 220 } }}>
                <OverviewStatCard
                  label="Profiles linked to issuance"
                  value={String(issuanceProfileStats.total)}
                  helper="Total DID-to-signing-service bindings"
                />
              </Box>
              <Box sx={{ flex: '1 1 220px', minWidth: { xs: '100%', md: 220 } }}>
                <OverviewStatCard
                  label="Active now"
                  value={String(issuanceProfileStats.active)}
                  helper={`${issuanceProfileStats.activeRate}% currently active`}
                />
              </Box>
              <Box sx={{ flex: '1 1 280px', minWidth: { xs: '100%', md: 280 } }}>
                <OverviewStatCard
                  label="Used for"
                  value={issuanceProfileStats.usageSummary}
                  helper={issuanceProfileStats.methodSummary}
                />
              </Box>
            </Stack>
          )}

          {issuerProfilesLoading && <TableSkeleton rows={2} columns={6} showActions={false} />}

          {issuerProfilesError && (
            <ErrorState error={issuerProfilesError} onRetry={reloadIssuerProfiles} variant="inline" />
          )}

          {!issuerProfilesLoading && !issuerProfilesError && issuerProfiles.length === 0 && (
            <Alert severity="info">
              No issuer profiles yet. Create a DID identity when you are ready to bind a DID to a signing service for issuance.
            </Alert>
          )}

          {!issuerProfilesLoading && !issuerProfilesError && issuerProfiles.length > 0 && (
            <TableContainer component={Paper} variant="outlined">
              <Table size="small">
                <TableHead>
                  <TableRow>
                    <TableCell>Name</TableCell>
                    <TableCell>Issuer DID</TableCell>
                    <TableCell>Signing binding</TableCell>
                    <TableCell>Status</TableCell>
                    <TableCell>Created</TableCell>
                    <TableCell align="right">Actions</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {issuerProfiles.map((profile) => (
                    <TableRow key={profile.id} hover>
                      <TableCell>{getIssuerProfileDisplayName(profile, organizationName)}</TableCell>
                      <TableCell>
                        <Typography variant="body2" fontFamily="monospace" sx={{ maxWidth: 320, wordBreak: 'break-word' }}>
                          {profile.issuer_did}
                        </Typography>
                      </TableCell>
                      <TableCell>
                        <Typography variant="body2" fontFamily="monospace" sx={{ wordBreak: 'break-word' }}>
                          {profile.signing_service_id || '—'}
                        </Typography>
                        {profile.signing_key_reference && (
                          <Typography variant="caption" color="text.secondary" fontFamily="monospace" sx={{ wordBreak: 'break-word' }}>
                            {profile.signing_key_reference}
                          </Typography>
                        )}
                      </TableCell>
                      <TableCell>
                        <Chip size="small" color={getStatusColor(profile.status)} label={profile.status} />
                      </TableCell>
                      <TableCell>
                        <Typography variant="body2" color="text.secondary">
                          {profile.created_at ? new Date(profile.created_at).toLocaleDateString() : '—'}
                        </Typography>
                      </TableCell>
                      <TableCell align="right">
                        <Stack direction="row" spacing={1} justifyContent="flex-end" useFlexGap flexWrap="wrap">
                          {profile.status === 'draft' && (
                            <Button
                              size="small"
                              onClick={async () => {
                                try {
                                  await signingKeysApi.updateIssuerProfile(profile.id, {
                                    organization_id: effectiveOrganizationId,
                                    status: 'active',
                                  })
                                  // Publish key material now that the profile is active
                                  if (profile.signing_service_id) {
                                    await Promise.allSettled([
                                      signingKeysApi.publishServiceToJwks(profile.signing_service_id, effectiveOrganizationId, {
                                        key_reference: profile.signing_key_reference || undefined,
                                      }),
                                      signingKeysApi.publishServiceToDidVm(profile.signing_service_id, effectiveOrganizationId, {
                                        key_reference: profile.signing_key_reference || undefined,
                                      }),
                                    ])
                                  }
                                  showNotification?.('Issuer profile activated and keys published.', 'success')
                                  reloadIssuerProfiles()
                                } catch (err) {
                                  showNotification?.('Failed to activate profile.', 'error')
                                }
                              }}
                            >
                              Activate
                            </Button>
                          )}

                          {profile.status === 'active' && (
                            <Button
                              size="small"
                              color="warning"
                              onClick={async () => {
                                try {
                                  await signingKeysApi.updateIssuerProfile(profile.id, {
                                    organization_id: effectiveOrganizationId,
                                    status: 'revoked',
                                  })
                                  showNotification?.('Issuer profile revoked.', 'success')
                                  reloadIssuerProfiles()
                                } catch (err) {
                                  showNotification?.('Failed to revoke profile.', 'error')
                                }
                              }}
                            >
                              Revoke
                            </Button>
                          )}

                          <Button
                            size="small"
                            color="error"
                            onClick={async () => {
                              try {
                                await signingKeysApi.deleteIssuerProfile(profile.id, { organization_id: effectiveOrganizationId })
                                showNotification?.('Issuer profile deleted.', 'success')
                                reloadIssuerProfiles()
                              } catch (err) {
                                showNotification?.('Failed to delete profile.', 'error')
                              }
                            }}
                          >
                            Delete
                          </Button>
                        </Stack>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          )}
        </Paper>
      </Stack>

      <ImportDidDialog
        open={Boolean(importDialogKey)}
        signingKey={importDialogKey}
        organizationId={effectiveOrganizationId}
        onClose={() => setImportDialogKey(null)}
        onImported={() => { setImportDialogKey(null); reload(); reloadIssuerProfiles() }}
      />
    </ResourcePage>
  )
}

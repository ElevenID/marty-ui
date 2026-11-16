import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { act, fireEvent, renderWithRouter, screen, waitFor } from '@test/utils'
import { Link, Route, Routes } from 'react-router'
import FlowDetailPage from '../FlowDetailPage'
import * as publicEntry from '../../../../application/routing/publicEntry'
import englishConsole from '../../../../../public/locales/en/console.json'

const { mockGetFlow, mockPublishFlow, mockNavigate, route } = vi.hoisted(() => ({
  mockGetFlow: vi.fn(),
  mockPublishFlow: vi.fn(),
  mockNavigate: vi.fn(),
  route: { flowId: 'flow-1', actual: false },
}))

vi.mock('react-i18next', async (importOriginal) => {
  const actual = await importOriginal<typeof import('react-i18next')>()
  return {
    ...actual,
    useTranslation: () => ({
      t: (key: string, options?: { defaultValue?: string }) => {
        const translations: Record<string, string> = {
          'flows.flowDetail.runtime.notAvailable': 'N/A',
          'flows.flowDetail.configuration.notAvailable': 'N/A',
          'flows.flowDetail.configuration.credentialTemplateLabel': 'Credential Template',
          'flows.flowDetail.entryPoints.downloadQrButton': 'Download QR Code',
          'flows.flowDetail.actions.downloadQr': 'Download QR',
          'flows.flowDetail.actions.previewButton': 'Preview applicant experience',
          'flows.flowDetail.actions.copyApplicationLink': 'Copy Application Link',
          'flows.flowDetail.actions.copied': 'Copied!',
          'flows.flowDetail.statusChips.active': 'Active',
          'flows.flowDetail.statusChips.draft': 'Draft',
          'flows.flowDetail.statusChips.paused': 'Paused',
          'flows.flowDetail.statusChips.archived': 'Archived',
          'flows.flowDetail.statusChips.unknown': 'Unknown status',
          'flows.flowDetail.alerts.draftStatus': 'This flow is a draft.',
          'flows.flowDetail.lifecycleTitle': 'Flow lifecycle',
          'flows.flowDetail.entryPoints.linkUnavailable': 'No application link is available for this flow.',
          'flows.flowDetail.errors.copyFailed': 'The link could not be copied. Try again.',
          'flows.flowDetail.errors.invalidActivation': 'The activation response did not match this flow.',
        }
        return translations[key] || options?.defaultValue || key
      },
    }),
  }
})

vi.mock('react-router', async () => {
  const actual = await vi.importActual<typeof import('react-router')>('react-router')
  return {
    ...actual,
    useParams: () => route.actual ? actual.useParams() : route,
    useNavigate: () => route.actual ? actual.useNavigate() : mockNavigate,
  }
})

vi.mock('../../../../services/flowsApi', () => ({
  getFlow: (...args: unknown[]) => mockGetFlow(...args),
  publishFlow: (...args: unknown[]) => mockPublishFlow(...args),
  testFlow: vi.fn(),
  validateFlow: vi.fn(),
}))

const nativeFlow = {
  id: 'flow-1',
  organization_id: 'owner-org',
  name: 'Production credential flow',
  status: 'ACTIVE',
  flow_type: 'oid4vci_pre_authorized',
  resolved_steps: ['create_offer', 'token_exchange', 'credential_request', 'issue_credential'],
  created_at: '2026-07-09T12:00:00Z',
  updated_at: '2026-07-09T12:00:00Z',
}

function deferred<T>() {
  let resolve!: (value: T) => void
  const promise = new Promise<T>(res => { resolve = res })
  return { promise, resolve }
}

function renderFlowRoutes() {
  route.actual = true
  return renderWithRouter(<>
    <Link to="/console/org/flows/definitions/flow-1">First flow</Link>
    <Link to="/console/org/flows/definitions/flow-2">Second flow</Link>
    <Routes>
      <Route path="/console/org/flows/definitions/:flowId" element={<FlowDetailPage />} />
    </Routes>
  </>, { initialEntries: ['/console/org/flows/definitions/flow-1'] })
}

describe('FlowDetailPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    route.flowId = 'flow-1'
    route.actual = false
    mockPublishFlow.mockReset()
    mockGetFlow.mockResolvedValue(nativeFlow)
  })

  afterEach(() => { vi.restoreAllMocks() })

  it('provides named navigation and omits unavailable native metrics and publication metadata', async () => {
    const { user } = renderWithRouter(<FlowDetailPage />, {
      initialEntries: ['/console/org/flows/definitions/flow-1'],
    })

    await waitFor(() => {
      expect(screen.getByText('Production credential flow')).toBeInTheDocument()
    })

    expect(screen.queryByText('142')).not.toBeInTheDocument()
    expect(screen.queryByText('12')).not.toBeInTheDocument()
    expect(screen.queryByText('130')).not.toBeInTheDocument()
    expect(screen.queryByText('EU Digital Identity Credential')).not.toBeInTheDocument()
    expect(screen.queryByText('Employee email required (domain: example.com)')).not.toBeInTheDocument()
    expect(screen.queryByText('Open Badge 2.0, EUDI-ready')).not.toBeInTheDocument()
    expect(screen.getAllByText('N/A').length).toBeGreaterThanOrEqual(8)
    expect(screen.getAllByRole('heading', { level: 1 })).toHaveLength(1)
    expect(screen.getByRole('heading', { level: 1, name: nativeFlow.name })).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '' })).not.toBeInTheDocument()
    expect(screen.getByText('Share an available applicant link to start this flow.')).toBeInTheDocument()
    expect(screen.queryByText(/flows\.flowDetail\.audit\.publishedByLabel/)).not.toBeInTheDocument()
    // The loaded mock catalog omits the new key, as an existing browser session can.
    expect(englishConsole.flows.flowDetail.actions.backToFlows).toBe('Back to Flows')
    await user.click(screen.getByRole('button', { name: 'Back to Flows' }))
    expect(mockNavigate).toHaveBeenCalledExactlyOnceWith('/console/org/flows/definitions')
  })

  it('names linked configuration and keeps QR download disabled until a real QR payload exists', async () => {
    mockGetFlow.mockResolvedValue({
      ...nativeFlow,
      public_url: 'https://example.test/apply/flow-1',
      credential_template_id: 'credential-template-1',
      presentation_policy_id: 'presentation-policy-1',
    })
    renderWithRouter(<FlowDetailPage />, {
      initialEntries: ['/console/org/flows/definitions/flow-1'],
    })

    await waitFor(() => {
      expect(screen.getByText('Production credential flow')).toBeInTheDocument()
    })

    expect(screen.getByRole('button', { name: 'Download QR' })).toBeDisabled()
    expect(screen.getByRole('button', { name: 'Download QR Code' })).toBeDisabled()
    expect(screen.getByRole('link', { name: 'Credential Template' })).toHaveAttribute('href', '/console/org/templates/credentials/credential-template-1')
    expect(screen.getByRole('link', { name: 'Presentation policy' })).toHaveAttribute('href', '/console/org/policies/presentation/presentation-policy-1')
  })

  it.each(['DRAFT', 'ACTIVE', 'PAUSED', 'ARCHIVED'])('opens the native %s definition in its owned preview without a public URL', async status => {
    mockGetFlow.mockResolvedValue({ ...nativeFlow, status })
    const open = vi.spyOn(window, 'open').mockImplementation(() => null)
    const { user } = renderWithRouter(<FlowDetailPage />)
    await screen.findByText(nativeFlow.name)
    await user.click(screen.getByRole('button', { name: 'Preview applicant experience' }))

    expect(open).toHaveBeenCalledExactlyOnceWith('/applicant/preview/flows/flow-1?organization_id=owner-org', '_blank', 'noopener,noreferrer')
  })

  it.each([{ id: 'different-flow' }, { organization_id: undefined }, { organization_id: '' }, { organization_id: 42 }])('does not open a preview with an invalid native identity: %j', async replacement => {
    mockGetFlow.mockResolvedValue({ ...nativeFlow, ...replacement })
    const open = vi.spyOn(window, 'open').mockImplementation(() => null)
    renderWithRouter(<FlowDetailPage />)
    await screen.findByText(nativeFlow.name)
    const button = screen.getByRole('button', { name: 'Preview applicant experience' })
    expect(button).toBeDisabled()
    fireEvent.click(button)
    expect(open).not.toHaveBeenCalled()
  })

  it('encodes the definition and owner and respects public-entry navigation', async () => {
    route.flowId = 'flow/one?two'
    mockGetFlow.mockResolvedValue({ ...nativeFlow, id: route.flowId, organization_id: 'org/name&part' })
    const href = vi.spyOn(publicEntry, 'publicEntryHref').mockImplementation(destination => `https://canonical.example${destination}`)
    const open = vi.spyOn(window, 'open').mockImplementation(() => null)
    const { user } = renderWithRouter(<FlowDetailPage />)
    await screen.findByText(nativeFlow.name)
    await user.click(screen.getByRole('button', { name: 'Preview applicant experience' }))

    const path = '/applicant/preview/flows/flow%2Fone%3Ftwo?organization_id=org%2Fname%26part'
    expect(href).toHaveBeenCalledWith(path)
    expect(open).toHaveBeenCalledExactlyOnceWith(`https://canonical.example${path}`, '_blank', 'noopener,noreferrer')
  })

  it.each(['DRAFT', 'ACTIVE', 'PAUSED', 'ARCHIVED'])('labels the native %s lifecycle without calling other states a draft', async status => {
    mockGetFlow.mockResolvedValue({ ...nativeFlow, status })
    renderWithRouter(<FlowDetailPage />)
    await screen.findByText(nativeFlow.name)
    const label = { DRAFT: 'Draft', ACTIVE: 'Active', PAUSED: 'Paused', ARCHIVED: 'Archived' }[status]!
    expect(screen.getByText(label)).toBeInTheDocument()
    if (status === 'DRAFT') expect(screen.getByText('This flow is a draft.')).toBeInTheDocument()
    else expect(screen.queryByText('This flow is a draft.')).not.toBeInTheDocument()
    if (status !== 'ACTIVE') {
      expect(screen.getByText('Flow lifecycle')).toBeInTheDocument()
      expect(screen.queryByText('Draft lifecycle')).not.toBeInTheDocument()
    }
  })

  it('does not offer to copy a native active flow when no application link is returned', async () => {
    renderWithRouter(<FlowDetailPage />)
    await screen.findByText(nativeFlow.name)
    expect(screen.getByRole('button', { name: 'Copy Application Link' })).toBeDisabled()
    expect(screen.getByDisplayValue('No application link is available for this flow.')).toBeInTheDocument()
  })

  it.each(['', 'javascript:alert(1)', { href: 'https://example.test/apply' }])('does not offer an invalid application URL: %j', async public_url => {
    mockGetFlow.mockResolvedValue({ ...nativeFlow, public_url })
    renderWithRouter(<FlowDetailPage />)
    await screen.findByText(nativeFlow.name)
    expect(screen.getByRole('button', { name: 'Copy Application Link' })).toBeDisabled()
  })

  it('waits for clipboard success and does not start a second copy while pending', async () => {
    const copied = deferred<void>()
    mockGetFlow.mockResolvedValue({ ...nativeFlow, public_url: 'https://example.test/apply/flow-1' })
    renderWithRouter(<FlowDetailPage />)
    const write = vi.spyOn(navigator.clipboard, 'writeText').mockReturnValue(copied.promise)
    await screen.findByText(nativeFlow.name)
    const copy = screen.getByRole('button', { name: 'Copy Application Link' })
    fireEvent.click(copy)
    expect(screen.queryByRole('button', { name: 'Copied!' })).not.toBeInTheDocument()
    expect(copy).toBeDisabled()
    fireEvent.click(copy)
    expect(write).toHaveBeenCalledExactlyOnceWith('https://example.test/apply/flow-1')
    await act(async () => { copied.resolve() })
    expect(screen.getByRole('button', { name: 'Copied!' })).toBeEnabled()
  })

  it('reports clipboard rejection honestly and permits a successful retry', async () => {
    mockGetFlow.mockResolvedValue({ ...nativeFlow, public_url: 'https://example.test/apply/flow-1' })
    const { user } = renderWithRouter(<FlowDetailPage />)
    const write = vi.spyOn(navigator.clipboard, 'writeText').mockRejectedValueOnce(new Error('Denied')).mockResolvedValue(undefined)
    await screen.findByText(nativeFlow.name)
    await user.click(screen.getByRole('button', { name: 'Copy Application Link' }))
    expect(await screen.findByText('The link could not be copied. Try again.')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Copied!' })).not.toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Copy Application Link' }))
    expect(await screen.findByRole('button', { name: 'Copied!' })).toBeInTheDocument()
    expect(screen.queryByText('The link could not be copied. Try again.')).not.toBeInTheDocument()
    expect(write).toHaveBeenCalledTimes(2)
  })

  it('copies the displayed activation result rather than the original draft', async () => {
    mockGetFlow.mockResolvedValue({ ...nativeFlow, status: 'DRAFT' })
    mockPublishFlow.mockResolvedValue({ ...nativeFlow, public_url: 'https://example.test/apply/flow-1' })
    const { user } = renderWithRouter(<FlowDetailPage />)
    const write = vi.spyOn(navigator.clipboard, 'writeText').mockResolvedValue(undefined)
    await user.click(await screen.findByRole('button', { name: 'Activate' }))
    await user.click(await screen.findByRole('button', { name: 'Copy Application Link' }))
    expect(write).toHaveBeenCalledExactlyOnceWith('https://example.test/apply/flow-1')
  })

  it('updates Last Modified from the returned activation definition', async () => {
    const updatedAt = '2026-11-09T07:00:00Z'
    mockGetFlow.mockResolvedValue({ ...nativeFlow, status: 'DRAFT' })
    mockPublishFlow.mockResolvedValue({ ...nativeFlow, updated_at: updatedAt })
    const { user } = renderWithRouter(<FlowDetailPage />)
    await user.click(await screen.findByRole('button', { name: 'Activate' }))
    await screen.findByText('Active')
    const footer = screen.getByText('flows.flowDetail.audit.lastModifiedLabel:').parentElement
    expect(footer).toHaveTextContent(new Date(updatedAt).toLocaleString())
  })

  it('resets activated state and configuration on a real Router parameter change', async () => {
    const second = { ...nativeFlow, id: 'flow-2', name: 'Second native flow', status: 'PAUSED', credential_template_id: 'second-template' }
    mockGetFlow.mockImplementation((id: string) => Promise.resolve(id === 'flow-1' ? { ...nativeFlow, status: 'DRAFT' } : second))
    mockPublishFlow.mockResolvedValue({ ...nativeFlow, name: 'Activated first flow' })
    const { user } = renderFlowRoutes()
    await user.click(await screen.findByRole('button', { name: 'Activate' }))
    await screen.findByText('Activated first flow')
    await user.click(screen.getByRole('link', { name: 'Second flow' }))
    await screen.findByText('Second native flow')
    expect(screen.queryByText('Activated first flow')).not.toBeInTheDocument()
    expect(screen.getByText('second-template')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Preview applicant experience' })).toBeEnabled()
  })

  it('does not let a pending activation replace the next Router entry', async () => {
    const activation = deferred<typeof nativeFlow>()
    mockGetFlow.mockImplementation((id: string) => Promise.resolve(id === 'flow-1' ? { ...nativeFlow, status: 'DRAFT' } : { ...nativeFlow, id, name: 'Second native flow' }))
    mockPublishFlow.mockReturnValue(activation.promise)
    const { user } = renderFlowRoutes()
    await user.click(await screen.findByRole('button', { name: 'Activate' }))
    await user.click(screen.getByRole('link', { name: 'Second flow' }))
    await screen.findByText('Second native flow')
    await act(async () => { activation.resolve({ ...nativeFlow, name: 'Late first flow' }) })
    expect(screen.getByText('Second native flow')).toBeInTheDocument()
    expect(screen.queryByText('Late first flow')).not.toBeInTheDocument()
  })

  it('does not apply an activation response for a different native definition', async () => {
    mockGetFlow.mockResolvedValue({ ...nativeFlow, status: 'DRAFT' })
    mockPublishFlow.mockResolvedValue({ ...nativeFlow, id: 'different-flow', name: 'Wrong flow' })
    const { user } = renderWithRouter(<FlowDetailPage />)
    await user.click(await screen.findByRole('button', { name: 'Activate' }))
    expect(await screen.findByText('The activation response did not match this flow.')).toBeInTheDocument()
    expect(screen.getByText(nativeFlow.name)).toBeInTheDocument()
    expect(screen.queryByText('Wrong flow')).not.toBeInTheDocument()
  })

  it('discards pending copy feedback when a different flow becomes current', async () => {
    const copied = deferred<void>()
    mockGetFlow.mockImplementation((id: string) => Promise.resolve({ ...nativeFlow, id, name: id === 'flow-1' ? nativeFlow.name : 'Second native flow', public_url: `https://example.test/apply/${id}` }))
    const { user } = renderFlowRoutes()
    vi.spyOn(navigator.clipboard, 'writeText').mockReturnValue(copied.promise)
    await user.click(await screen.findByRole('button', { name: 'Copy Application Link' }))
    await user.click(screen.getByRole('link', { name: 'Second flow' }))
    await screen.findByText('Second native flow')
    await act(async () => { copied.resolve() })
    expect(screen.queryByRole('button', { name: 'Copied!' })).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Copy Application Link' })).toBeEnabled()
  })
})

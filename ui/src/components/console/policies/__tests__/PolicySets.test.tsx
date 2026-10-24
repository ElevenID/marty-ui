import { beforeEach, describe, expect, it, vi } from 'vitest'
import { Route, Routes } from 'react-router'
import { http, HttpResponse } from 'msw'
import { renderWithRouter, screen, waitFor } from '@test/utils'
import { server } from '@test/mocks/server'
import PolicySetDetailPage from '../PolicySetDetailPage'
import PolicySetWizard from '../PolicySetWizard'
import PolicySetsPage from '../PolicySetsPage'

const { scope, can } = vi.hoisted(() => ({ scope: { org: 'org-1' }, can: vi.fn() }))
vi.mock('../../../../contexts/ConsoleContext', () => ({ useConsole: () => ({ activeOrgId: scope.org }) }))
vi.mock('../../../../hooks/useAuth', () => ({ useAuth: () => ({ organizationId: 'org-1' }) }))
vi.mock('../../../../hooks/usePermissions', () => ({ usePermissions: () => ({ can, isLoading: false }) }))
vi.mock('../../../common', () => ({ ResourcePage: ({ title, actions, children }: any) => <main><h1>{title}</h1>{actions}{children}</main> }))

const BASE = '/console/org/policies/sets'
const policies = [{ policy_id: 'read', effect: 'permit', enabled: true, description: 'Viewer reads', cedar_text: 'permit (principal, action, resource);' }]
const template = { template_id: 'access_read_only', name: 'Read-only access', description: 'Viewer template', policy_type: 'ACCESS_CONTROL', cedar_policies: policies }
let record: any
let writes: Array<{ method: string; path: string; org: string | null; body: any }>
function pages() { return <Routes>
  <Route path={BASE + '/new'} element={<PolicySetWizard />} />
  <Route path={BASE + '/:policySetId'} element={<PolicySetDetailPage />} />
  <Route path={BASE} element={<PolicySetsPage />} />
</Routes> }
function renderPage(suffix = '/set-1') { return renderWithRouter(pages(), { initialEntries: [BASE + suffix] }) }

describe('Policy Set scoped consumer journeys', () => {
  beforeEach(() => {
    vi.clearAllMocks(); scope.org = 'org-1'; can.mockReturnValue(true); writes = []
    record = { id: 'set-1', organization_id: 'org-1', name: 'Owned policy set', description: 'Original', policy_type: 'ACCESS_CONTROL', status: 'DRAFT', cedar_schema_version: 'mip.v1', cedar_policies: policies, updated_at: '2026-10-24T16:00:00Z' }
    server.use(
      http.get('*/v1/policy-sets', () => HttpResponse.json([record])),
      http.get('*/v1/policy-sets/templates', () => HttpResponse.json([template])),
      http.get('*/v1/policy-sets/:id', () => HttpResponse.json(record)),
      http.patch('*/v1/policy-sets/:id', async ({ request }) => {
        const body = await request.json(); writes.push({ method: 'PATCH', path: new URL(request.url).pathname, org: new URL(request.url).searchParams.get('organization_id'), body })
        record = { ...record, ...body as object }; return HttpResponse.json(record)
      }),
      http.post('*/v1/policy-sets/validate', () => HttpResponse.json({ valid: true, errors: [] })),
      http.post('*/v1/policy-sets/:id/:action', ({ request, params }) => {
        writes.push({ method: 'POST', path: new URL(request.url).pathname, org: new URL(request.url).searchParams.get('organization_id'), body: null })
        record = { ...record, status: params.action === 'activate' ? 'ACTIVE' : 'ARCHIVED' }; return HttpResponse.json(record)
      }),
      http.post('*/v1/policy-sets', async ({ request }) => {
        const body = await request.json(); writes.push({ method: 'POST', path: new URL(request.url).pathname, org: new URL(request.url).searchParams.get('organization_id'), body })
        record = { ...record, ...body as object }; return HttpResponse.json(record, { status: 201 })
      }),
    )
  })

  it('rejects an existing detail response from another organization', async () => {
    record.organization_id = 'org-2'; renderPage()
    expect(await screen.findByRole('alert')).toHaveTextContent(/selected organization/)
    expect(screen.queryByRole('heading', { name: record.name })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Activate' })).not.toBeInTheDocument()
  })

  it('rejects a detail response for a different ID in the same organization', async () => {
    record.id = 'set-2'; renderPage()
    expect(await screen.findByRole('alert')).toHaveTextContent(/selected organization/)
    expect(screen.queryByRole('heading', { name: record.name })).not.toBeInTheDocument()
  })

  it('does not display a late previous-organization detail response', async () => {
    let resolveOld!: () => void
    server.use(http.get('*/v1/policy-sets/:id', async ({ request }) => {
      if (new URL(request.url).searchParams.get('organization_id') === 'org-1') await new Promise<void>(resolve => { resolveOld = resolve })
      return HttpResponse.json(record)
    }))
    const { rerender } = renderPage()
    await waitFor(() => expect(resolveOld).toBeDefined())
    scope.org = 'org-2'; rerender(pages()); resolveOld()
    expect(await screen.findByRole('alert')).toHaveTextContent(/selected organization/)
    expect(screen.queryByRole('heading', { name: record.name })).not.toBeInTheDocument()
  })

  it('offers viewers inspection without mutation controls', async () => {
    can.mockImplementation((_resource: string, action: string) => action === 'view')
    renderPage(); await screen.findByRole('heading', { name: record.name })
    expect(screen.queryByRole('button', { name: 'Activate' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Edit metadata' })).not.toBeInTheDocument()
    expect(writes).toEqual([])
  })

  it('requires confirmation and uses the independent native lifecycle grants without requiring create', async () => {
    can.mockImplementation((_resource: string, action: string) => ['view', 'activate', 'archive'].includes(action))
    const { user } = renderPage(); await screen.findByRole('heading', { name: record.name })
    expect(screen.queryByRole('button', { name: 'Edit metadata' })).not.toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Activate', exact: true })); expect(writes).toEqual([])
    expect(screen.getByRole('dialog')).toHaveTextContent('archives any previously active Policy Set of the same type')
    await user.click(screen.getByRole('button', { name: 'Confirm activation' }))
    await user.click(await screen.findByRole('button', { name: 'Archive', exact: true }))
    await user.click(screen.getByRole('button', { name: 'Confirm archive' }))
    expect(await screen.findByText('ARCHIVED', { exact: true })).toBeInTheDocument()
    expect(writes).toEqual([
      { method: 'POST', path: '/v1/policy-sets/set-1/activate', org: 'org-1', body: null },
      { method: 'POST', path: '/v1/policy-sets/set-1/archive', org: 'org-1', body: null },
    ])
  })

  it('does not offer activation with only view and create grants', async () => {
    can.mockImplementation((_resource: string, action: string) => ['view', 'create'].includes(action))
    renderPage(); await screen.findByRole('heading', { name: record.name })
    expect(screen.queryByRole('button', { name: 'Activate', exact: true })).not.toBeInTheDocument()
  })

  it('does not offer archive without its independent grant', async () => {
    record.status = 'ACTIVE'
    can.mockImplementation((_resource: string, action: string) => ['view', 'create', 'activate'].includes(action))
    renderPage(); await screen.findByRole('heading', { name: record.name })
    expect(screen.queryByRole('button', { name: 'Archive', exact: true })).not.toBeInTheDocument()
  })

  it('requires validation permission independently of draft creation permission', async () => {
    can.mockImplementation((_resource: string, action: string) => ['view', 'create'].includes(action))
    renderPage('/new')
    expect(await screen.findByText(/permission to validate Policy Sets/)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Validate', exact: true })).toBeDisabled()
    expect(screen.getByRole('button', { name: 'Create draft' })).toBeDisabled()
  })

  it('edits only changed draft metadata and explicitly clears a description without replacing Cedar', async () => {
    const { user } = renderPage(); await screen.findByRole('heading', { name: record.name })
    await user.click(screen.getByRole('button', { name: 'Edit metadata' }))
    await user.clear(screen.getByLabelText('Description'))
    await user.click(screen.getByRole('button', { name: 'Save changes' }))
    await waitFor(() => expect(writes).toHaveLength(1))
    expect(writes[0]).toEqual({ method: 'PATCH', path: '/v1/policy-sets/set-1', org: 'org-1', body: { description: null } })
    expect(record.cedar_policies).toEqual(policies); expect(record.policy_type).toBe('ACCESS_CONTROL')
  })

  it('does not offer draft metadata editing for active sets', async () => {
    record.status = 'ACTIVE'; renderPage(); await screen.findByRole('heading', { name: record.name })
    expect(screen.queryByRole('button', { name: 'Edit metadata' })).not.toBeInTheDocument()
  })

  it('reads the persisted snapshot after a mutation before the next lifecycle preflight', async () => {
    server.use(http.patch('*/v1/policy-sets/:id', async ({ request }) => {
      const body = await request.json(); record = { ...record, ...body as object, updated_at: '2026-10-24T16:01:00.123456Z' }
      return HttpResponse.json({ ...record, updated_at: '2026-10-24T16:01:00.123456789Z' })
    }))
    const { user } = renderPage(); await screen.findByRole('heading', { name: record.name })
    await user.click(screen.getByRole('button', { name: 'Edit metadata' }))
    await user.clear(screen.getByLabelText('Description')); await user.type(screen.getByLabelText('Description'), 'Changed')
    await user.click(screen.getByRole('button', { name: 'Save changes' }))
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
    await user.click(screen.getByRole('button', { name: 'Activate', exact: true }))
    await user.click(screen.getByRole('button', { name: 'Confirm activation' }))
    expect(await screen.findByText('ACTIVE', { exact: true })).toBeInTheDocument()
    expect(writes).toHaveLength(1)
    expect(writes[0].path).toBe('/v1/policy-sets/set-1/activate')
  })

  it('refuses a lifecycle operation if the scoped preflight has changed', async () => {
    const { user } = renderPage(); await screen.findByRole('heading', { name: record.name })
    await user.click(screen.getByRole('button', { name: 'Activate', exact: true }))
    record = { ...record, updated_at: '2026-10-24T16:01:00Z' }
    await user.click(screen.getByRole('button', { name: 'Confirm activation' }))
    expect(await screen.findByRole('alert')).toHaveTextContent(/changed/)
    expect(writes).toEqual([])
    await user.click(screen.getByRole('button', { name: 'Refresh' }))
    await waitFor(() => expect(screen.getByRole('button', { name: 'Activate', exact: true })).toBeEnabled())
  })

  it('treats malformed list responses as an error instead of an empty inventory', async () => {
    server.use(http.get('*/v1/policy-sets', () => HttpResponse.json({ items: [] })))
    renderPage(''); expect(await screen.findByRole('alert')).toHaveTextContent(/invalid/i)
    expect(screen.queryByText('No Policy Sets')).not.toBeInTheDocument()
  })

  it('rejects foreign list records and hides create links for viewers', async () => {
    can.mockImplementation((_resource: string, action: string) => action === 'view')
    record.organization_id = 'org-2'; renderPage('')
    expect(await screen.findByRole('alert')).toHaveTextContent(/selected organization/)
    expect(screen.queryByRole('link', { name: 'Create Policy Set' })).not.toBeInTheDocument()
    expect(screen.queryByText(record.name)).not.toBeInTheDocument()
  })

  it('uses global provider templates and creates a scoped draft after successful validation', async () => {
    const { user } = renderPage('/new')
    await user.click(await screen.findByRole('button', { name: /Read-only access/ }))
    await user.click(screen.getByRole('button', { name: 'Create draft' }))
    await screen.findByRole('heading', { name: 'Read-only access' })
    expect(writes).toEqual([{ method: 'POST', path: '/v1/policy-sets', org: 'org-1', body: { name: template.name, description: template.description, policy_type: template.policy_type, cedar_policies: policies } }])
  })

  it('resets a draft and never creates after late validation from a former organization', async () => {
    let resolveValidation!: () => void
    server.use(http.post('*/v1/policy-sets/validate', async () => {
      await new Promise<void>(resolve => { resolveValidation = resolve }); return HttpResponse.json({ valid: true, errors: [] })
    }))
    const { user, rerender } = renderPage('/new')
    await user.click(await screen.findByRole('button', { name: /Read-only access/ }))
    await user.click(screen.getByRole('button', { name: 'Create draft' }))
    await waitFor(() => expect(resolveValidation).toBeDefined())
    scope.org = 'org-2'; rerender(pages()); resolveValidation()
    await waitFor(() => expect(screen.getByLabelText(/Name/)).toHaveValue(''))
    expect(screen.getByRole('button', { name: 'Create draft' })).toBeDisabled()
    expect(writes).toEqual([])
  })

  it('blocks direct wizard access without create permission', async () => {
    can.mockImplementation((_resource: string, action: string) => action === 'view')
    renderPage('/new'); expect(await screen.findByRole('alert')).toHaveTextContent(/permission/i)
    expect(screen.queryByRole('button', { name: 'Create draft' })).not.toBeInTheDocument()
  })

  it('recovers a failed list load through an explicit refresh', async () => {
    let unavailable = true
    server.use(http.get('*/v1/policy-sets', () => unavailable ? HttpResponse.json({ detail: 'Policy service unavailable' }, { status: 503 }) : HttpResponse.json([record])))
    const { user } = renderPage('')
    expect(await screen.findByText('Policy service unavailable', {}, { timeout: 10000 })).toBeInTheDocument()
    unavailable = false; await user.click(screen.getByRole('button', { name: 'Refresh' }))
    expect(await screen.findByText(record.name)).toBeInTheDocument()
  })

  it('recovers unavailable provider templates without inventing a preset', async () => {
    let unavailable = true
    server.use(http.get('*/v1/policy-sets/templates', () => unavailable ? HttpResponse.json({ detail: 'Templates unavailable' }, { status: 503 }) : HttpResponse.json([template])))
    const { user } = renderPage('/new')
    expect(await screen.findByText('Templates unavailable', {}, { timeout: 10000 })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Create draft' })).toBeDisabled()
    unavailable = false; await user.click(screen.getByRole('button', { name: 'Reload templates' }))
    expect(await screen.findByRole('button', { name: /Read-only access/ })).toBeEnabled()
  })

  it.each([{ valid: false, errors: ['Invalid Cedar policy.'] }, { valid: 'true', errors: [] }])('does not create from rejected or malformed validation %j', async (validation) => {
    server.use(http.post('*/v1/policy-sets/validate', () => HttpResponse.json(validation)))
    const { user } = renderPage('/new')
    await user.click(await screen.findByRole('button', { name: /Read-only access/ }))
    await user.click(screen.getByRole('button', { name: 'Create draft' }))
    expect(await screen.findByRole('alert')).toHaveTextContent(/invalid/i)
    expect(writes).toEqual([])
  })

  it('stops creation if the create grant is revoked while validation is pending', async () => {
    let resolveValidation!: () => void
    server.use(http.post('*/v1/policy-sets/validate', async () => {
      await new Promise<void>(resolve => { resolveValidation = resolve }); return HttpResponse.json({ valid: true, errors: [] })
    }))
    const { user, rerender } = renderPage('/new')
    await user.click(await screen.findByRole('button', { name: /Read-only access/ }))
    await user.click(screen.getByRole('button', { name: 'Create draft' }))
    await waitFor(() => expect(resolveValidation).toBeDefined())
    can.mockImplementation((_resource: string, action: string) => action === 'view')
    rerender(pages()); resolveValidation()
    expect(await screen.findByRole('alert')).toHaveTextContent(/permission/i)
    expect(writes).toEqual([])
  })

  it('hides a displayed former-organization list while the next list is pending', async () => {
    let resolveNext!: () => void
    server.use(http.get('*/v1/policy-sets', async ({ request }) => {
      if (new URL(request.url).searchParams.get('organization_id') === 'org-2') {
        await new Promise<void>(resolve => { resolveNext = resolve }); return HttpResponse.json([])
      }
      return HttpResponse.json([record])
    }))
    const { rerender } = renderPage(''); await screen.findByText(record.name)
    scope.org = 'org-2'; rerender(pages())
    expect(screen.queryByText(record.name)).not.toBeInTheDocument()
    await waitFor(() => expect(resolveNext).toBeDefined()); resolveNext()
    expect(await screen.findByText('No Policy Sets')).toBeInTheDocument()
  })
})

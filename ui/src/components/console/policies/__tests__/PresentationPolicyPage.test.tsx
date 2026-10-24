import { beforeEach, describe, expect, it, vi } from 'vitest'
import { Route, Routes } from 'react-router'
import { http, HttpResponse } from 'msw'
import { renderWithRouter, screen } from '@test/utils'
import { server } from '@test/mocks/server'
import PresentationPolicyPage from '../PresentationPolicyPage'

const { context, can } = vi.hoisted(() => ({ context: { activeOrgId: 'org-1' }, can: vi.fn() }))
vi.mock('../../../../contexts/ConsoleContext', () => ({ useConsole: () => context }))
vi.mock('../../../../hooks/usePermissions', () => ({ usePermissions: () => ({ can, isLoading: false }) }))
vi.mock('../../../common/ResourcePage', () => ({ default: ({ title, children }: { title: string; children: React.ReactNode }) => <main><h1>{title}</h1>{children}</main> }))

const BASE = '/console/org/policies/presentation'
const ID = '50000000-0000-0000-0000-000000000099'
let profile: Record<string, any>
let requests: Array<{ method: string; path: string; body?: any }>
let reads: number
const renderPage = (suffix = `/${ID}`) => renderWithRouter(<Routes>
  <Route path={BASE + '/:policyId/edit'} element={<PresentationPolicyPage mode="edit" />} />
  <Route path={BASE + '/:policyId'} element={<PresentationPolicyPage />} />
  <Route path={BASE} element={<p>Policy list</p>} />
</Routes>, { initialEntries: [BASE + suffix] })

describe('scoped presentation policy detail and metadata editing', () => {
  beforeEach(() => {
    vi.clearAllMocks(); context.activeOrgId = 'org-1'; can.mockReturnValue(true); requests = []; reads = 0
    profile = { id: ID, organization_id: 'org-1', name: 'Pinned membership policy', status: 'draft',
      description: 'Initial description', purpose: 'Verify membership',
      required_claims: [{ claim_name: 'member_id' }],
      credential_requirements: [{ credential_template_id: 'template', trust_profile_id: 'trust' }],
      alternative_requirements: [], holder_binding: { required: true, binding_methods: ['CREDENTIAL_KEY'] },
      freshness: { require_not_revoked: true, max_age_seconds: 300 },
    }
    server.use(
      http.get('*/v1/presentation-policies/:id', ({ request }) => {
        reads += 1
        expect(new URL(request.url).searchParams.get('organization_id')).toBe(context.activeOrgId)
        return HttpResponse.json(profile)
      }),
      http.patch('*/v1/presentation-policies/:id', async ({ request }) => {
        const body = await request.json(); requests.push({ method: 'PATCH', path: new URL(request.url).pathname, body })
        profile = { ...profile, ...body as object }; return HttpResponse.json(profile)
      }),
      http.post('*/v1/presentation-policies/:id/:action', async ({ request, params }) => {
        requests.push({ method: 'POST', path: new URL(request.url).pathname, body: await request.json() })
        profile = { ...profile, status: params.action === 'activate' ? 'active' : 'suspended' }
        return HttpResponse.json(profile)
      }),
      http.delete('*/v1/presentation-policies/:id', ({ request }) => {
        requests.push({ method: 'DELETE', path: new URL(request.url).pathname }); return HttpResponse.json({ success: true })
      }),
    )
  })

  it('inspects native requirements and activates and suspends without offering immutable edits', async () => {
    const { user } = renderPage()
    expect(await screen.findByRole('heading', { name: profile.name })).toBeInTheDocument()
    expect(screen.getByText(/credential_requirements/)).toHaveTextContent('CREDENTIAL_KEY')
    expect(screen.getByRole('link', { name: 'Edit metadata' })).toHaveAttribute('href', `${BASE}/${ID}/edit`)
    await user.click(screen.getByRole('button', { name: 'Activate policy' }))
    expect(await screen.findByText('active', { exact: true })).toBeInTheDocument()
    expect(screen.queryByRole('link', { name: 'Edit metadata' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Delete policy' })).not.toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Suspend policy' }))
    expect(await screen.findByText('suspended', { exact: true })).toBeInTheDocument()
    expect(requests).toHaveLength(2)
    expect(requests).toEqual([
      { method: 'POST', path: `/v1/presentation-policies/${ID}/activate`, body: {} },
      { method: 'POST', path: `/v1/presentation-policies/${ID}/suspend`, body: {} },
    ])
  })

  it('requires explicit confirmation before deleting a draft', async () => {
    const { user } = renderPage(); await screen.findByRole('heading', { name: profile.name })
    await user.click(screen.getByRole('button', { name: 'Delete policy' }))
    expect(requests).toHaveLength(0)
    await user.click(screen.getByRole('button', { name: 'Confirm deletion' }))
    expect(await screen.findByText('Policy list')).toBeInTheDocument()
    expect(requests).toEqual([{ method: 'DELETE', path: `/v1/presentation-policies/${ID}` }])
  })

  it('uses the public edit grant for activation and suspension without inventing lifecycle grants', async () => {
    can.mockImplementation((_resource: string, action: string) => ['view', 'edit'].includes(action))
    const { user } = renderPage(); await screen.findByRole('heading', { name: profile.name })
    expect(screen.queryByRole('button', { name: 'Delete policy' })).not.toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Activate policy' }))
    expect(await screen.findByText('active', { exact: true })).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Suspend policy' }))
    expect(await screen.findByText('suspended', { exact: true })).toBeInTheDocument()
    expect(requests).toHaveLength(2)
  })

  it('rejects direct editing of active policies without offering a save', async () => {
    profile.status = 'active'; renderPage(`/${ID}/edit`)
    expect(await screen.findByRole('alert')).toHaveTextContent('Only draft policies can be edited')
    expect(screen.queryByLabelText('Description')).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Save changes' })).not.toBeInTheDocument()
    expect(requests).toEqual([])
  })

  it('sends a sparse metadata edit without losing any native requirement or binding', async () => {
    const initial = structuredClone(profile); const { user } = renderPage(`/${ID}/edit`)
    const description = await screen.findByLabelText('Description')
    await user.clear(description); await user.type(description, 'Updated metadata')
    await user.click(screen.getByRole('button', { name: 'Save changes' }))
    expect(await screen.findByRole('heading', { name: profile.name })).toBeInTheDocument()
    expect(requests[0].body).toEqual({ organization_id: 'org-1', description: 'Updated metadata' })
    expect(profile).toEqual({ ...initial, description: 'Updated metadata' })
  })

  it('does not reveal a policy returned from another organization', async () => {
    profile.organization_id = 'other-org'; renderPage()
    expect(await screen.findByRole('alert')).toHaveTextContent('not available in the selected organization')
    expect(screen.queryByText('Pinned membership policy')).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Activate policy' })).not.toBeInTheDocument()
  })

  it('enforces direct edit grants before loading policy data', async () => {
    can.mockImplementation((_resource: string, action: string) => action !== 'edit')
    renderPage(`/${ID}/edit`)
    expect(await screen.findByRole('alert')).toHaveTextContent('permission to edit')
    expect(screen.queryByLabelText('Description')).not.toBeInTheDocument()
    expect(requests).toEqual([])
    expect(reads).toBe(0)
  })

  it('shows lifecycle errors in the page and allows an explicit retry', async () => {
    let attempts = 0
    server.use(http.post('*/v1/presentation-policies/:id/activate', () => {
      attempts += 1
      if (attempts === 1) return HttpResponse.json({ detail: 'Activation unavailable' }, { status: 503 })
      profile.status = 'active'; return HttpResponse.json(profile)
    }))
    const { user } = renderPage(); await screen.findByRole('heading', { name: profile.name })
    await user.click(screen.getByRole('button', { name: 'Activate policy' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('Activation unavailable')
    expect(profile.status).toBe('draft')
    await user.click(screen.getByRole('button', { name: 'Activate policy' }))
    expect(await screen.findByText('active', { exact: true })).toBeInTheDocument()
    expect(attempts).toBe(2)
  })
})

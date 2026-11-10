import { beforeEach, describe, expect, it, vi } from 'vitest';
import { webcrypto } from 'node:crypto';
import { BrowserRouter } from 'react-router';
import { act, fireEvent, waitFor, within } from '@testing-library/react';
import { http, HttpResponse } from 'msw';
import { server } from '@test/mocks/server';
import { renderWithoutRouter, screen } from '@test/utils';
import PresentationPolicyWizard from '../PresentationPolicyWizard';

const scope = vi.hoisted(() => ({ organization: 'org-1', principal: 'principal-1' }));
vi.mock('../../../../contexts/ConsoleContext', () => ({ useConsole: () => ({ activeOrgId: scope.organization }) }));
vi.mock('../../../../hooks/useAuth', () => ({ useAuth: () => ({ user: { user_id: scope.principal } }) }));

const POLICY_ID = '11111111-1111-4111-8111-111111111111';
const TRUST_ID = '22222222-2222-4222-8222-222222222222';
const TEMPLATE_ID = '33333333-3333-4333-8333-333333333333';
const NAME = 'Submitted employee policy';
const trust = { id: TRUST_ID, organization_id: 'org-1', name: 'Employee Trust',
  status: 'ACTIVE', trust_framework_type: 'custom', supported_formats: ['SD_JWT_VC'] };
const template = { id: TEMPLATE_ID, organization_id: 'org-1', name: 'Employee Credential',
  status: 'ACTIVE', trust_profile_id: TRUST_ID, credential_payload_format: 'SD_JWT_VC',
  vct: 'urn:example:employee', claims: [{ name: 'employee_id', required: true }] };

type HeldStage = 'trust-check' | 'template-check' | 'create' | 'readback' | 'activate';

function installRequests(stage: HeldStage = 'create', organization = 'org-1') {
  let resolve!: (value: Response) => void;
  const response = new Promise<Response>(done => { resolve = done; });
  const writes: Array<{ endpoint: string; body: Record<string, unknown>; key: string | null }> = [];
  const reads: string[] = [];
  let createdBody: Record<string, unknown> = {};
  let armed = false;
  let heldResponse: Response | null = null;
  const maybeHold = (at: HeldStage, reply: Response) => {
    if (armed && at === stage && !heldResponse) { heldResponse = reply; return response; }
    return reply;
  };
  const currentTrust = { ...trust, organization_id: organization,
    id: organization === 'org-1' ? TRUST_ID : '44444444-4444-4444-8444-444444444444' };
  const currentTemplate = { ...template, organization_id: organization, trust_profile_id: currentTrust.id,
    id: organization === 'org-1' ? TEMPLATE_ID : '55555555-5555-4555-8555-555555555555' };
  server.use(
    http.get('*/v1/organizations/:id/defaults', () => HttpResponse.json({
      default_trust_profile_id: currentTrust.id, default_template_id: currentTemplate.id,
    })),
    http.get('*/v1/trust-profiles', () => HttpResponse.json([currentTrust])),
    http.get('*/v1/trust-profiles/:id', () => {
      reads.push('trust-check'); return maybeHold('trust-check', HttpResponse.json(currentTrust));
    }),
    http.get('*/v1/credential-templates', () => HttpResponse.json([currentTemplate])),
    http.get('*/v1/credential-templates/:id', () => {
      reads.push('template-check'); return maybeHold('template-check', HttpResponse.json(currentTemplate));
    }),
    http.post('*/v1/presentation-policies', async ({ request }) => {
      createdBody = await request.json() as Record<string, unknown>;
      writes.push({ endpoint: 'create', body: createdBody, key: request.headers.get('Idempotency-Key') });
      return maybeHold('create', HttpResponse.json({ ...createdBody, id: POLICY_ID, status: 'DRAFT' }));
    }),
    http.get('*/v1/presentation-policies/:id', () => {
      reads.push('readback');
      return maybeHold('readback', HttpResponse.json({ ...createdBody, id: POLICY_ID, status: 'DRAFT' }));
    }),
    http.post('*/v1/presentation-policies/:id/activate', async ({ request }) => {
      writes.push({ endpoint: 'activate', body: await request.json() as Record<string, unknown>, key: request.headers.get('Idempotency-Key') });
      return maybeHold('activate', HttpResponse.json({ ...createdBody, id: POLICY_ID, status: 'ACTIVE' }));
    }),
  );
  return { writes, reads, arm: () => { armed = true; }, isHeld: () => Boolean(heldResponse), async settle(reply?: Response) {
    await act(async () => { resolve(reply || heldResponse!); });
  } };
}

async function reachClaims(user: ReturnType<typeof renderWithoutRouter>['user']) {
  await waitFor(() => expect(screen.getByRole('button', { name: 'Select Employee Trust trust profile' }))
    .toHaveAttribute('aria-pressed', 'true'));
  await user.click(screen.getByTestId('wizard.policy.next'));
  await waitFor(() => expect(screen.getByRole('button', { name: 'Select Employee Credential presentation policy template' }))
    .toHaveAttribute('aria-pressed', 'true'));
  await user.click(screen.getByTestId('wizard.policy.next'));
  const name = await screen.findByRole('textbox', { name: /Policy Name/i });
  await user.clear(name); await user.type(name, NAME);
}

async function reachReview(user: ReturnType<typeof renderWithoutRouter>['user']) {
  await reachClaims(user);
  await user.click(screen.getByTestId('wizard.policy.next'));
  await user.click(screen.getByTestId('wizard.policy.next'));
  await waitFor(() => expect(screen.getByTestId('wizard.policy.submit')).toBeEnabled());
}

beforeEach(() => {
  vi.stubGlobal('crypto', webcrypto); sessionStorage.clear();
  scope.organization = 'org-1'; scope.principal = 'principal-1';
  window.history.replaceState({}, '', '/console/org/policies/presentation/new');
});

describe('presentation policy pending review intent', () => {
  it('keeps blank and whitespace-only claim names at the claims step until corrected', async () => {
    const requests = installRequests();
    const { user } = renderWithoutRouter(<BrowserRouter><PresentationPolicyWizard /></BrowserRouter>);
    await reachClaims(user);
    const claimName = screen.getByRole('combobox', { name: /Claim Name/i });
    await user.clear(claimName);
    expect(screen.getByText('Enter a claim name.')).toBeInTheDocument();
    expect(screen.getByTestId('wizard.policy.next')).toBeDisabled();
    await user.type(claimName, '   ');
    expect(screen.getByTestId('wizard.policy.next')).toBeDisabled();
    expect(requests.writes).toEqual([]);
    await user.clear(claimName); await user.type(claimName, 'employee_id');
    await user.tab();
    expect(screen.queryByText('Enter a claim name.')).not.toBeInTheDocument();
    expect(screen.getByTestId('wizard.policy.next')).toBeEnabled();
    await user.click(screen.getByTestId('wizard.policy.next'));
    expect(screen.getByRole('group', { name: 'Freshness & Binding' })).toBeInTheDocument();
  });

  it('requires each claim to use an accepted credential type and recovers after reselection', async () => {
    const requests = installRequests();
    const { user } = renderWithoutRouter(<BrowserRouter><PresentationPolicyWizard /></BrowserRouter>);
    await reachClaims(user);
    const type = screen.getByRole('combobox', { name: /From Credential Type/i });
    await user.click(type);
    await user.click(within(type.parentElement!).getByRole('button', { name: 'Clear' }));
    expect(screen.getByText('Select one of the accepted credential types.')).toBeInTheDocument();
    expect(screen.getByTestId('wizard.policy.next')).toBeDisabled();
    await user.type(type, 'urn:example:employee');
    await user.click(await screen.findByRole('option', { name: 'urn:example:employee' }));
    expect(screen.getByTestId('wizard.policy.next')).toBeEnabled();
    const acceptedType = screen.getByRole('button', { name: 'urn:example:employee' });
    await user.click(acceptedType); await user.keyboard('{Delete}');
    expect(screen.getByText('Select one of the accepted credential types.')).toBeInTheDocument();
    expect(screen.getByTestId('wizard.policy.next')).toBeDisabled();
    const addType = screen.getByRole('combobox', { name: 'Add credential type' });
    await user.type(addType, '  urn:example:employee  '); await user.keyboard('{Enter}');
    expect(screen.getByRole('button', { name: 'urn:example:employee' })).toBeInTheDocument();
    expect(screen.getByTestId('wizard.policy.next')).toBeEnabled();
    expect(requests.writes).toEqual([]);
  });

  it.each([false, true])('keeps displayed activation intent consistent with the real submitted chain (attempt pending edit: %s)', async (attemptEdit) => {
    // All steps, useWizard, the durable operation, API helpers and transport are
    // real. Only server responses and the selected session scope are fixtures.
    const requests = installRequests();
    const { user } = renderWithoutRouter(<BrowserRouter><PresentationPolicyWizard /></BrowserRouter>);
    await reachReview(user);
    requests.arm();
    await user.click(screen.getByTestId('wizard.policy.submit'));
    await waitFor(() => expect(requests.writes).toHaveLength(1));
    if (attemptEdit) await user.click(screen.getByRole('switch', { name: /Activate immediately/i }));
    await requests.settle();
    await screen.findByText('🎉 Presentation Policy Created!');
    expect(requests.writes.map(({ endpoint }) => endpoint)).toEqual(['create', 'activate']);
    expect(requests.writes[0].body).toMatchObject({ organization_id: 'org-1', name: NAME,
      trust_profile_id: TRUST_ID, credential_requirements: [{ credential_template_id: TEMPLATE_ID, trust_profile_id: TRUST_ID }] });
    expect(requests.writes[0].body).not.toHaveProperty('activate_immediately');
    expect(screen.getByText(new RegExp(NAME)).textContent, `REQUEST_TRACE=${JSON.stringify(requests.writes)}`)
      .toBe('"' + NAME + '" is active and ready to use.');
    expect(screen.queryByText(/saved as draft/)).not.toBeInTheDocument();
  });

  it.each(['trust-check', 'template-check', 'create', 'readback', 'activate'] as const)('locks review edits throughout the pending %s stage', async (stage) => {
    const requests = installRequests(stage);
    const { user } = renderWithoutRouter(<BrowserRouter><PresentationPolicyWizard /></BrowserRouter>);
    await reachReview(user); requests.arm();
    await user.click(screen.getByTestId('wizard.policy.submit'));
    await waitFor(() => expect(requests.isHeld()).toBe(true));
    const toggle = screen.getByRole('switch', { name: /Activate immediately/i });
    expect(toggle).toBeDisabled(); expect(toggle).toBeChecked();
    const edits = screen.getAllByRole('button', { name: 'Edit' });
    expect(edits).toHaveLength(6);
    for (const edit of edits) { expect(edit).toBeDisabled(); fireEvent.click(edit); }
    expect(screen.getByTestId('wizard.policy.back')).toBeDisabled();
    expect(screen.getByTestId('wizard.policy.submit')).toBeDisabled();
    fireEvent.click(toggle); fireEvent.click(screen.getByTestId('wizard.policy.back'));
    expect(screen.getByRole('group', { name: 'Review' })).toBeInTheDocument();
    expect(toggle).toBeChecked();
    await requests.settle();
    await screen.findByText('"' + NAME + '" is active and ready to use.');
    expect(requests.writes.map(({ endpoint }) => endpoint)).toEqual(['create', 'activate']);
  });

  it('guards same-turn edits and Back before loading commits while preserving duplicate-submit protection', async () => {
    const requests = installRequests();
    const { user } = renderWithoutRouter(<BrowserRouter><PresentationPolicyWizard /></BrowserRouter>);
    await reachReview(user); requests.arm();
    const toggle = screen.getByRole('switch', { name: /Activate immediately/i });
    const edit = screen.getAllByRole('button', { name: 'Edit' })[0];
    const submit = screen.getByTestId('wizard.policy.submit');
    const back = screen.getByTestId('wizard.policy.back');
    act(() => {
      fireEvent.click(submit);
      expect(toggle).not.toBeDisabled();
      fireEvent.click(toggle); fireEvent.click(edit); fireEvent.click(back); fireEvent.click(submit);
    });
    await waitFor(() => expect(requests.writes).toHaveLength(1));
    expect(screen.getByRole('group', { name: 'Review' })).toBeInTheDocument();
    expect(toggle).toBeChecked();
    await requests.settle();
    await screen.findByText('"' + NAME + '" is active and ready to use.');
    expect(requests.writes.map(({ endpoint }) => endpoint)).toEqual(['create', 'activate']);
  });

  it.each([false, true])('preserves draft intent chosen before submission (attempt pending edit: %s)', async (attemptEdit) => {
    const requests = installRequests();
    const { user } = renderWithoutRouter(<BrowserRouter><PresentationPolicyWizard /></BrowserRouter>);
    await reachReview(user);
    await user.click(screen.getByRole('switch', { name: /Activate immediately/i }));
    requests.arm(); await user.click(screen.getByTestId('wizard.policy.submit'));
    await waitFor(() => expect(requests.writes).toHaveLength(1));
    if (attemptEdit) await user.click(screen.getByRole('switch', { name: /Activate immediately/i }));
    await requests.settle();
    await screen.findByText('"' + NAME + '" is saved as draft.');
    expect(requests.writes.map(({ endpoint }) => endpoint)).toEqual(['create']);
    expect(requests.reads).not.toContain('readback');
    expect(sessionStorage.getItem('marty:policy-create:v1:org-1')).toBeNull();
  });

  it('dismisses a definitive rejection without discarding the review and uses revised intent on explicit retry', async () => {
    const requests = installRequests();
    const { user } = renderWithoutRouter(<BrowserRouter><PresentationPolicyWizard /></BrowserRouter>);
    await reachReview(user); requests.arm();
    await user.click(screen.getByTestId('wizard.policy.submit'));
    await waitFor(() => expect(requests.writes).toHaveLength(1));
    await requests.settle(HttpResponse.json({ error: { message: 'Policy validation rejected the request' } }, { status: 422 }));
    const error = await screen.findByText(/Policy validation rejected the request/);
    await user.click(within(error.closest('[role="alert"]')!).getByRole('button', { name: 'Close' }));
    expect(screen.queryByText(/Policy validation rejected the request/)).not.toBeInTheDocument();
    expect(screen.getByRole('group', { name: 'Review' })).toBeInTheDocument();
    expect(requests.writes).toHaveLength(1);
    const toggle = screen.getByRole('switch', { name: /Activate immediately/i });
    expect(toggle).toBeEnabled();
    for (const edit of screen.getAllByRole('button', { name: 'Edit' })) expect(edit).toBeEnabled();
    expect(sessionStorage.getItem('marty:policy-create:v1:org-1')).toBeNull();
    await user.click(toggle); await user.click(screen.getByTestId('wizard.policy.submit'));
    await screen.findByText('"' + NAME + '" is saved as draft.');
    expect(requests.writes.map(({ endpoint }) => endpoint)).toEqual(['create', 'create']);
    expect(requests.writes[0].key).toBeTruthy();
    expect(requests.writes[1].key).not.toBe(requests.writes[0].key);
    expect(requests.writes[1].body).toEqual(requests.writes[0].body);
  });

  it('dismisses the activation error while retaining the acknowledged draft and retrying without another create', async () => {
    const requests = installRequests('activate');
    const { user } = renderWithoutRouter(<BrowserRouter><PresentationPolicyWizard /></BrowserRouter>);
    await reachReview(user); requests.arm();
    await user.click(screen.getByTestId('wizard.policy.submit'));
    await waitFor(() => expect(requests.isHeld()).toBe(true));
    await requests.settle(HttpResponse.json({ error: { message: 'Activation temporarily unavailable' } }, { status: 503 }));
    const error = await screen.findByText(/was created, but activation is incomplete/);
    await user.click(within(error.closest('[role="alert"]')!).getByRole('button', { name: 'Close' }));
    expect(screen.queryByText(/was created, but activation is incomplete/)).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Open created draft' })).toBeEnabled();
    expect(screen.getByRole('switch', { name: /Activate immediately/i })).toBeEnabled();
    expect(JSON.parse(sessionStorage.getItem('marty:policy-create:v1:org-1')!).resourceId).toBe(POLICY_ID);
    await user.click(screen.getByRole('button', { name: 'Retry activation' }));
    await screen.findByText('"' + NAME + '" is active and ready to use.');
    expect(requests.writes.map(({ endpoint }) => endpoint)).toEqual(['create', 'activate', 'activate']);
    expect(requests.reads.filter(kind => kind === 'readback')).toHaveLength(2);
    expect(sessionStorage.getItem('marty:policy-create:v1:org-1')).toBeNull();
  });

  it('preserves the existing draft reconciliation requirement after configuration edits', async () => {
    const requests = installRequests('activate');
    const { user } = renderWithoutRouter(<BrowserRouter><PresentationPolicyWizard /></BrowserRouter>);
    await reachReview(user); requests.arm();
    await user.click(screen.getByTestId('wizard.policy.submit'));
    await waitFor(() => expect(requests.isHeld()).toBe(true));
    await requests.settle(HttpResponse.json({ error: { message: 'Activation temporarily unavailable' } }, { status: 503 }));
    await screen.findByText(/was created, but activation is incomplete/);
    await user.click(screen.getAllByRole('button', { name: 'Edit' })[0]);
    const name = await screen.findByRole('textbox', { name: /Policy Name/i });
    await user.clear(name); await user.type(name, 'Edited after draft creation');
    await user.click(screen.getByTestId('wizard.policy.next'));
    await user.click(screen.getByTestId('wizard.policy.next'));
    await user.click(screen.getByRole('button', { name: 'Retry activation' }));
    await screen.findByText(/was already created\. Open that draft to edit it before activation/);
    expect(requests.writes.map(({ endpoint }) => endpoint)).toEqual(['create', 'activate']);
    expect(JSON.parse(sessionStorage.getItem('marty:policy-create:v1:org-1')!).resourceId).toBe(POLICY_ID);
    expect(screen.getByRole('switch', { name: /Activate immediately/i })).toBeEnabled();
  });

  it('keeps ordinary review editing available before submission', async () => {
    const requests = installRequests();
    const { user } = renderWithoutRouter(<BrowserRouter><PresentationPolicyWizard /></BrowserRouter>);
    await reachReview(user);
    await user.click(screen.getAllByRole('button', { name: 'Edit' })[0]);
    const name = await screen.findByRole('textbox', { name: /Policy Name/i });
    expect(name).toBeEnabled();
    await user.clear(name); await user.type(name, 'Edited before submission');
    expect(name).toHaveValue('Edited before submission');
    expect(requests.writes).toHaveLength(0);
  });

  it.each(['organization', 'principal'] as const)('releases the form for a new %s scope while the previous create is pending', async (field) => {
    const requests = installRequests();
    const view = renderWithoutRouter(<BrowserRouter><PresentationPolicyWizard /></BrowserRouter>);
    await reachReview(view.user); requests.arm();
    await view.user.click(screen.getByTestId('wizard.policy.submit'));
    await waitFor(() => expect(requests.writes).toHaveLength(1));
    scope[field] = 'new-scope';
    const currentRequests = installRequests('create', scope.organization);
    view.rerender(<BrowserRouter><PresentationPolicyWizard /></BrowserRouter>);
    await reachReview(view.user);
    const toggle = screen.getByRole('switch', { name: /Activate immediately/i });
    expect(toggle).toBeEnabled(); await view.user.click(toggle); expect(toggle).not.toBeChecked();
    await requests.settle();
    await waitFor(() => expect(JSON.parse(sessionStorage.getItem('marty:policy-create:v1:org-1')!).resourceId).toBe(POLICY_ID));
    expect(screen.getByRole('group', { name: 'Review' })).toBeInTheDocument();
    expect(toggle).not.toBeChecked();
    expect(currentRequests.writes).toHaveLength(0);
    expect(screen.queryByText('🎉 Presentation Policy Created!')).not.toBeInTheDocument();
  });
});

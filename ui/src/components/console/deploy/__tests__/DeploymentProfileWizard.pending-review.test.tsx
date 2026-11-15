import { beforeEach, describe, expect, it, vi } from 'vitest';
import { webcrypto } from 'node:crypto';
import { BrowserRouter } from 'react-router';
import { act, fireEvent, waitFor } from '@testing-library/react';
import { http, HttpResponse } from 'msw';
import { server } from '@test/mocks/server';
import { renderWithoutRouter, screen } from '@test/utils';
import DeploymentProfileWizard from '../DeploymentProfileWizard';

const scope = vi.hoisted(() => ({ organization: 'org-1' }));
vi.mock('../../../../contexts/ConsoleContext', () => ({ useConsole: () => ({ activeOrgId: scope.organization }) }));

const PROFILE_ID = '11111111-1111-4111-8111-111111111111';
const POLICY_ID = '22222222-2222-4222-8222-222222222222';
const TRUST_ID = '33333333-3333-4333-8333-333333333333';
const NAME = 'Submitted API deployment';

// Native DeploymentProfileResponse serializes lowercase status and returns the
// created profile directly, without the request-only activate_immediately flag.
function nativeProfile(body: Record<string, unknown>) {
  return {
    id: PROFILE_ID, organization_id: body.organization_id, name: body.name,
    description: body.description, status: body.status, trust_profile_id: body.trust_profile_id,
    presentation_policy_ids: body.presentation_policy_ids, credential_template_ids: body.credential_template_ids,
    default_policy_id: body.default_policy_id, network_mode: body.network_mode, key_access_mode: 'KEY_VAULT',
    environment_config: { language: 'en-US', signage_text: {}, operator_mode: false, accessibility_mode: false,
      ...body.environment_config as Record<string, unknown>, offline_cache_ttl_seconds: 86400 },
    enabled_flow_ids: body.enabled_flow_ids, update_channel: 'stable', update_policy: { auto_update: true, channel: 'stable' },
    offline_cache_ttl_hours: 24, operator_biometric_authentication_required: false, audit_all_events: true,
    canvas_feature_flags: Object.fromEntries(Object.entries(body.feature_flags as Record<string, unknown>)
      .filter(([key]) => key.startsWith('enable_canvas_'))),
    lanes: [], created_at: '2026-11-09T16:00:00Z', updated_at: '2026-11-09T16:00:00Z',
  };
}

function installRequests(organization = 'org-1', retryFirstAttempt = false) {
  let resolve!: (value: Response) => void;
  const response = new Promise<Response>(done => { resolve = done; });
  const writes: Array<{ body: Record<string, unknown>; key: string | null }> = [];
  let heldResponse: Response | null = null;
  server.use(
    http.get('*/v1/organizations/:id/defaults', () => HttpResponse.json({})),
    http.get('*/v1/presentation-policies', () => HttpResponse.json([
      { id: POLICY_ID, organization_id: organization, name: 'Employee policy', status: 'ACTIVE', trust_profile_id: TRUST_ID },
    ])),
    http.get('*/v1/credential-templates', () => HttpResponse.json([])),
    http.get('*/v1/flows/definitions', () => HttpResponse.json([])),
    http.post('*/v1/deployment-profiles', async ({ request }) => {
      const body = await request.json() as Record<string, unknown>;
      writes.push({ body, key: request.headers.get('Idempotency-Key') });
      if (retryFirstAttempt && writes.length === 1) return HttpResponse.error();
      const reply = HttpResponse.json(nativeProfile(body));
      if (!heldResponse) { heldResponse = reply; return response; }
      return reply;
    }),
  );
  return { writes, async settle(reply?: Response) {
    await act(async () => { resolve(reply || heldResponse!); });
  } };
}

async function reachReview(user: ReturnType<typeof renderWithoutRouter>['user']) {
  await user.type(screen.getByRole('textbox', { name: /Profile Name/i }), NAME);
  await user.click(screen.getByTestId('wizard.deployment.next'));
  await waitFor(() => expect(screen.getByTestId('wizard.deployment.next')).toBeEnabled());
  await user.click(screen.getByTestId('wizard.deployment.next'));
  await user.click(screen.getByTestId('wizard.deployment.next'));
  await waitFor(() => expect(screen.getByTestId('wizard.deployment.submit')).toBeEnabled());
}

beforeEach(() => {
  vi.stubGlobal('crypto', webcrypto); sessionStorage.clear(); scope.organization = 'org-1';
  window.history.replaceState({}, '', '/console/org/deploy/profiles/new');
});

describe('deployment profile pending review intent', () => {
  it.each([false, true])('keeps displayed activation intent consistent with the real submitted profile (attempt pending edit: %s)', async (attemptEdit) => {
    // The steps, useWizard, create API, idempotency helper and transport are real.
    // Only server responses and the selected organization are fixtures.
    const requests = installRequests();
    const { user } = renderWithoutRouter(<BrowserRouter><DeploymentProfileWizard /></BrowserRouter>);
    await reachReview(user);
    await user.click(screen.getByTestId('wizard.deployment.submit'));
    await waitFor(() => expect(requests.writes).toHaveLength(1));
    if (attemptEdit) await user.click(screen.getByRole('switch', { name: /Activate immediately/i }));
    await requests.settle();
    await screen.findByText('Deployment Profile Created Successfully!');
    expect(requests.writes).toHaveLength(1);
    expect(requests.writes[0].body).toMatchObject({ organization_id: 'org-1', name: NAME,
      trust_profile_id: TRUST_ID, default_policy_id: POLICY_ID, presentation_policy_ids: [POLICY_ID],
      status: 'active', activate_immediately: true });
    expect(requests.writes[0].key).toBeTruthy();
    expect(screen.getByText(new RegExp(NAME)).textContent, `REQUEST_TRACE=${JSON.stringify(requests.writes)}`)
      .toBe('"' + NAME + '" is now active and ready to use.');
    expect(screen.queryByText(/saved as draft/)).not.toBeInTheDocument();
  });

  it('locks review edits and navigation throughout the pending create', async () => {
    const requests = installRequests();
    const { user } = renderWithoutRouter(<BrowserRouter><DeploymentProfileWizard /></BrowserRouter>);
    await reachReview(user);
    await user.click(screen.getByTestId('wizard.deployment.submit'));
    await waitFor(() => expect(requests.writes).toHaveLength(1));
    const toggle = screen.getByRole('switch', { name: /Activate immediately/i });
    expect(toggle).toBeDisabled(); expect(toggle).toBeChecked();
    const edits = screen.getAllByRole('button', { name: 'Edit' });
    expect(edits).toHaveLength(3);
    for (const edit of edits) { expect(edit).toBeDisabled(); fireEvent.click(edit); }
    expect(screen.getByTestId('wizard.deployment.back')).toBeDisabled();
    expect(screen.getByTestId('wizard.deployment.submit')).toBeDisabled();
    fireEvent.click(toggle); fireEvent.click(screen.getByTestId('wizard.deployment.back'));
    expect(screen.getByRole('group', { name: 'Review & Activate' })).toBeInTheDocument();
    expect(toggle).toBeChecked();
    await requests.settle();
    await screen.findByText('"' + NAME + '" is now active and ready to use.');
    expect(requests.writes).toHaveLength(1);
  });

  it('guards same-turn edits and Back before loading commits while preserving duplicate-submit protection', async () => {
    const requests = installRequests();
    const { user } = renderWithoutRouter(<BrowserRouter><DeploymentProfileWizard /></BrowserRouter>);
    await reachReview(user);
    const toggle = screen.getByRole('switch', { name: /Activate immediately/i });
    const edits = screen.getAllByRole('button', { name: 'Edit' });
    const submit = screen.getByTestId('wizard.deployment.submit');
    const back = screen.getByTestId('wizard.deployment.back');
    act(() => {
      fireEvent.click(submit);
      expect(toggle).not.toBeDisabled();
      fireEvent.click(toggle);
      for (const edit of edits) fireEvent.click(edit);
      fireEvent.click(back); fireEvent.click(submit);
    });
    await waitFor(() => expect(requests.writes).toHaveLength(1));
    expect(screen.getByRole('group', { name: 'Review & Activate' })).toBeInTheDocument();
    expect(toggle).toBeChecked();
    await requests.settle();
    await screen.findByText('"' + NAME + '" is now active and ready to use.');
    expect(requests.writes).toHaveLength(1);
  });

  it.each([false, true])('preserves draft intent chosen before submission (attempt pending edit: %s)', async (attemptEdit) => {
    const requests = installRequests();
    const { user } = renderWithoutRouter(<BrowserRouter><DeploymentProfileWizard /></BrowserRouter>);
    await reachReview(user);
    await user.click(screen.getByRole('switch', { name: /Activate immediately/i }));
    await user.click(screen.getByTestId('wizard.deployment.submit'));
    await waitFor(() => expect(requests.writes).toHaveLength(1));
    if (attemptEdit) await user.click(screen.getByRole('switch', { name: /Activate immediately/i }));
    await requests.settle();
    await screen.findByText('"' + NAME + '" is now saved as draft.');
    expect(requests.writes).toHaveLength(1);
    expect(requests.writes[0].body).toMatchObject({ status: 'draft', activate_immediately: false });
    expect(screen.queryByText(/now active and ready/)).not.toBeInTheDocument();
  });

  it('restores review editing after a definitive rejection and submits the revised intent on explicit retry', async () => {
    const requests = installRequests();
    const { user } = renderWithoutRouter(<BrowserRouter><DeploymentProfileWizard /></BrowserRouter>);
    await reachReview(user);
    await user.click(screen.getByTestId('wizard.deployment.submit'));
    await waitFor(() => expect(requests.writes).toHaveLength(1));
    await requests.settle(HttpResponse.json({ detail: 'Deployment profile validation rejected the request' }, { status: 422 }));
    await screen.findByText(/Deployment profile validation rejected the request/);
    const toggle = screen.getByRole('switch', { name: /Activate immediately/i });
    expect(toggle).toBeEnabled();
    for (const edit of screen.getAllByRole('button', { name: 'Edit' })) expect(edit).toBeEnabled();
    await user.click(screen.getAllByRole('button', { name: 'Edit' })[0]);
    const name = await screen.findByRole('textbox', { name: /Profile Name/i });
    await user.clear(name); await user.type(name, 'Revised API deployment');
    await user.click(screen.getByTestId('wizard.deployment.next'));
    await waitFor(() => expect(screen.getByTestId('wizard.deployment.next')).toBeEnabled());
    await user.click(screen.getByTestId('wizard.deployment.next'));
    await user.click(screen.getByTestId('wizard.deployment.next'));
    await user.click(screen.getByRole('switch', { name: /Activate immediately/i }));
    await user.click(screen.getByTestId('wizard.deployment.submit'));
    await screen.findByText('"Revised API deployment" is now saved as draft.');
    expect(requests.writes).toHaveLength(2);
    expect(requests.writes[1].body).toEqual({ ...requests.writes[0].body,
      name: 'Revised API deployment', status: 'draft', activate_immediately: false });
    expect(requests.writes[1].key).toBeTruthy();
    expect(requests.writes[1].key).not.toBe(requests.writes[0].key);
  });

  it('keeps reviewed intent locked during the existing same-key network retry', async () => {
    const requests = installRequests('org-1', true);
    const { user } = renderWithoutRouter(<BrowserRouter><DeploymentProfileWizard /></BrowserRouter>);
    await reachReview(user);
    await user.click(screen.getByTestId('wizard.deployment.submit'));
    await waitFor(() => expect(requests.writes).toHaveLength(2));
    const toggle = screen.getByRole('switch', { name: /Activate immediately/i });
    expect(toggle).toBeDisabled(); expect(toggle).toBeChecked();
    await user.click(toggle);
    for (const edit of screen.getAllByRole('button', { name: 'Edit' })) expect(edit).toBeDisabled();
    expect(requests.writes[1]).toEqual(requests.writes[0]);
    await requests.settle();
    await screen.findByText('"' + NAME + '" is now active and ready to use.');
    expect(requests.writes).toHaveLength(2);
  });

  it('releases pending controls and preserves the existing unknown-status guidance after an ambiguous retry failure', async () => {
    const requests = installRequests('org-1', true);
    const { user } = renderWithoutRouter(<BrowserRouter><DeploymentProfileWizard /></BrowserRouter>);
    await reachReview(user);
    await user.click(screen.getByTestId('wizard.deployment.submit'));
    await waitFor(() => expect(requests.writes).toHaveLength(2));
    await requests.settle(HttpResponse.error());
    const error = await screen.findByText(/Operation status unknown/);
    expect(error).toHaveTextContent('Refresh the page before creating another artifact.');
    expect(error).toHaveTextContent(requests.writes[0].key!);
    expect(requests.writes[1]).toEqual(requests.writes[0]);
    expect(requests.writes).toHaveLength(2);
    expect(screen.getByRole('switch', { name: /Activate immediately/i })).toBeEnabled();
    expect(screen.getByTestId('wizard.deployment.back')).toBeEnabled();
    expect(screen.queryByText('Deployment Profile Created Successfully!')).not.toBeInTheDocument();
  });

  it('keeps ordinary review editing available before submission', async () => {
    const requests = installRequests();
    const { user } = renderWithoutRouter(<BrowserRouter><DeploymentProfileWizard /></BrowserRouter>);
    await reachReview(user);
    await user.click(screen.getAllByRole('button', { name: 'Edit' })[0]);
    const name = await screen.findByRole('textbox', { name: /Profile Name/i });
    expect(name).toBeEnabled();
    await user.clear(name); await user.type(name, 'Edited before submission');
    expect(name).toHaveValue('Edited before submission');
    expect(requests.writes).toHaveLength(0);
  });

  it('keeps the new organization form editable while the previous organization create settles', async () => {
    const requests = installRequests();
    const view = renderWithoutRouter(<BrowserRouter><DeploymentProfileWizard /></BrowserRouter>);
    await reachReview(view.user);
    await view.user.click(screen.getByTestId('wizard.deployment.submit'));
    await waitFor(() => expect(requests.writes).toHaveLength(1));
    scope.organization = 'org-2';
    const currentRequests = installRequests(scope.organization);
    view.rerender(<BrowserRouter><DeploymentProfileWizard /></BrowserRouter>);
    await reachReview(view.user);
    const toggle = screen.getByRole('switch', { name: /Activate immediately/i });
    expect(toggle).toBeEnabled(); await view.user.click(toggle); expect(toggle).not.toBeChecked();
    await requests.settle();
    expect(screen.getByRole('group', { name: 'Review & Activate' })).toBeInTheDocument();
    expect(toggle).not.toBeChecked(); expect(toggle).toBeEnabled();
    expect(currentRequests.writes).toHaveLength(0);
    expect(screen.queryByText('Deployment Profile Created Successfully!')).not.toBeInTheDocument();
  });

  it('does not release the current organization pending guard when an earlier form settles', async () => {
    const requests = installRequests();
    const view = renderWithoutRouter(<BrowserRouter><DeploymentProfileWizard /></BrowserRouter>);
    await reachReview(view.user);
    await view.user.click(screen.getByTestId('wizard.deployment.submit'));
    await waitFor(() => expect(requests.writes).toHaveLength(1));
    scope.organization = 'org-2';
    const currentRequests = installRequests(scope.organization);
    view.rerender(<BrowserRouter><DeploymentProfileWizard /></BrowserRouter>);
    await reachReview(view.user);
    await view.user.click(screen.getByRole('switch', { name: /Activate immediately/i }));
    await view.user.click(screen.getByTestId('wizard.deployment.submit'));
    await waitFor(() => expect(currentRequests.writes).toHaveLength(1));
    await requests.settle();
    const toggle = screen.getByRole('switch', { name: /Activate immediately/i });
    expect(toggle).toBeDisabled(); expect(toggle).not.toBeChecked();
    fireEvent.click(toggle); fireEvent.click(screen.getAllByRole('button', { name: 'Edit' })[0]);
    expect(screen.getByRole('group', { name: 'Review & Activate' })).toBeInTheDocument();
    expect(toggle).not.toBeChecked();
    expect(screen.queryByText('Deployment Profile Created Successfully!')).not.toBeInTheDocument();
    await currentRequests.settle();
    await screen.findByText('"' + NAME + '" is now saved as draft.');
    expect(currentRequests.writes[0].body).toMatchObject({ organization_id: 'org-2', status: 'draft', activate_immediately: false });
    expect(currentRequests.writes).toHaveLength(1);
  });
});

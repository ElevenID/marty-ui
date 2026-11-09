import { beforeEach, describe, expect, it, vi } from 'vitest';
import { webcrypto } from 'node:crypto';
import { BrowserRouter } from 'react-router';
import { act, fireEvent, waitFor } from '@testing-library/react';
import { http, HttpResponse } from 'msw';
import { server } from '@test/mocks/server';
import { renderWithoutRouter, screen } from '@test/utils';
import CredentialTemplateWizard from '../CredentialTemplateWizard';

const { submission } = vi.hoisted(() => ({ submission: { pending: null as Promise<unknown> | null } }));
vi.mock('../../../../hooks/useAuth', () => ({ useAuth: () => ({ user: { user_id: 'principal-1' } }) }));
vi.mock('../../../../contexts/ConsoleContext', () => ({ useConsole: () => ({ activeOrgId: 'org-1' }) }));
// Keep the actual hook and durable creation operation; capture only the actual
// onSubmit promise so assertions wait for the complete create/read/activate chain.
vi.mock('../../../../hooks/useWizard', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../../../hooks/useWizard')>();
  return { ...actual, useWizard: (config: any) => actual.useWizard({ ...config,
    onSubmit: (data: unknown) => { submission.pending = config.onSubmit(data); return submission.pending; },
  }) };
});

const TEMPLATE_ID = '11111111-1111-4111-8111-111111111111';
const TRUST_ID = '22222222-2222-4222-8222-222222222222';
const COMPLIANCE_ID = '33333333-3333-4333-8333-333333333333';
const REVOCATION_ID = '44444444-4444-4444-8444-444444444444';
const DID = 'did:web:issuer.example.test';
const NAME = 'Submitted employee template';

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>(done => { resolve = done; });
  return { promise, resolve };
}

function installRequests(stage: 'compatibility' | 'create' | 'readback' | 'activate' = 'create') {
  const reply = deferred<Response>();
  const writes: Array<{ endpoint: string; body: Record<string, unknown> }> = [];
  const reads: string[] = [];
  let createdBody: Record<string, unknown> = {};
  let heldResponse: Response | null = null;
  const maybeHold = (at: typeof stage, response: Response) => {
    if (at === stage && !heldResponse) { heldResponse = response; return reply.promise; }
    return response;
  };
  server.use(
    http.get('*/v1/organizations/:id/defaults', () => HttpResponse.json({})),
    http.get('*/v1/trust-profiles', () => HttpResponse.json([{ id: TRUST_ID, organization_id: 'org-1',
      name: 'Employee Trust', status: 'ACTIVE', supported_formats: ['SD_JWT_VC'] }])),
    http.get('*/v1/compliance-profiles', () => HttpResponse.json([{ id: COMPLIANCE_ID, organization_id: null,
      name: 'OID4VC Core', compliance_code: 'OID4VC', credential_format: 'SD_JWT_VC',
      issuance_protocol: 'OID4VCI_PRE_AUTH', status: 'ACTIVE', is_system: true, discoverable: true }])),
    http.get('*/v1/revocation-profiles', () => HttpResponse.json([{ id: REVOCATION_ID, organization_id: 'org-1',
      name: 'Employee Revocation', status: 'ACTIVE', check_mode: 'ALWAYS' }])),
    http.get('*/v1/wallet-registry', () => HttpResponse.json([])),
    http.get('*/v1/credential-templates', () => HttpResponse.json([])),
    http.post('*/v1/credential-templates/issuer-options', () => {
      reads.push('compatibility');
      const response = HttpResponse.json({ organization_id: 'org-1',
        compliance_profile_id: COMPLIANCE_ID, credential_payload_format: 'SD_JWT_VC', supported_formats: ['SD_JWT_VC'],
        issuance_protocol: 'OID4VCI_PRE_AUTH', requirements: { vct: true, doctype: false, revocation_profile: true, x509_certificate: false },
        identities: [{ issuer_did: DID, bindings: [{ credential_format: 'SD_JWT_VC', key_purpose: 'vc_jwt_issuer', algorithm: 'ES256' }] }],
        rejected_issuers: [],
      });
      return submission.pending ? maybeHold('compatibility', response) : response;
    }),
    http.post('*/v1/credential-templates', async ({ request }) => {
      createdBody = await request.json() as Record<string, unknown>;
      writes.push({ endpoint: 'create', body: createdBody });
      return maybeHold('create', HttpResponse.json({ ...createdBody, id: TEMPLATE_ID, status: 'DRAFT' }));
    }),
    http.get('*/v1/credential-templates/:id', () => {
      reads.push('readback');
      return maybeHold('readback', HttpResponse.json({ ...createdBody, id: TEMPLATE_ID, status: 'DRAFT' }));
    }),
    http.post('*/v1/credential-templates/:id/activate', async ({ request }) => {
      writes.push({ endpoint: 'activate', body: await request.json() as Record<string, unknown> });
      return maybeHold('activate', HttpResponse.json({ ...createdBody, id: TEMPLATE_ID, status: 'ACTIVE' }));
    }),
  );
  return { writes, reads, isHeld: () => Boolean(heldResponse), async settle(response?: Response) {
    await act(async () => {
      reply.resolve(response || heldResponse!);
      await submission.pending?.catch(() => undefined);
    });
  } };
}

async function reachReview(user: ReturnType<typeof renderWithoutRouter>['user']) {
  await user.type(screen.getByLabelText(/Template Name/i), NAME);
  await user.type(screen.getByLabelText(/VCT/i), 'org.example.employee');
  await user.click(screen.getByTestId('wizard.template.next'));
  await user.click(await screen.findByRole('button', { name: /employee/i }));
  await user.click(screen.getByTestId('wizard.template.next'));
  await waitFor(() => expect(screen.getByRole('combobox', { name: 'Issuer DID' })).not.toHaveAttribute('aria-disabled', 'true'));
  await user.click(screen.getByRole('combobox', { name: 'Issuer DID' }));
  await user.click(await screen.findByRole('option', { name: DID }));
  await waitFor(() => expect(screen.getByTestId('wizard.template.next')).toBeEnabled());
  await user.click(screen.getByTestId('wizard.template.next'));
  await user.click(await screen.findByLabelText(/revocation profile/i));
  await user.click(await screen.findByRole('option', { name: /Employee Revocation/ }));
  await user.click(screen.getByTestId('wizard.template.next'));
  await waitFor(() => expect(screen.getByTestId('wizard.template.submit')).toBeEnabled());
}

beforeEach(() => {
  vi.stubGlobal('crypto', webcrypto); sessionStorage.clear(); submission.pending = null;
  window.history.replaceState({}, '', '/console/org/templates/credentials/new');
});

describe('credential template pending review intent', () => {
  it.each([false, true])('keeps displayed activation intent consistent with the real submitted chain (attempt pending edit: %s)', async (attemptEdit) => {
    const requests = installRequests();
    const { user } = renderWithoutRouter(<BrowserRouter><CredentialTemplateWizard /></BrowserRouter>);
    await reachReview(user);
    await user.click(screen.getByTestId('wizard.template.submit'));
    await waitFor(() => expect(requests.writes).toHaveLength(1));
    if (attemptEdit) await user.click(screen.getByRole('switch', { name: /Activate immediately/i }));
    await requests.settle();
    expect(requests.writes.map(({ endpoint }) => endpoint)).toEqual(['create', 'activate']);
    expect(requests.writes[0].body).toMatchObject({ organization_id: 'org-1', name: NAME, issuer_did: DID,
      trust_profile_id: TRUST_ID, compliance_profile_id: COMPLIANCE_ID, revocation_profile_id: REVOCATION_ID });
    expect(requests.writes[0].body).not.toHaveProperty('activate_immediately');
    expect(screen.getByText(new RegExp(NAME)).textContent, `REQUEST_TRACE=${JSON.stringify(requests.writes)}`)
      .toBe('"' + NAME + '" is now active.');
    expect(screen.queryByText(/saved as draft/)).not.toBeInTheDocument();
  });

  it.each(['compatibility', 'create', 'readback', 'activate'] as const)('locks review controls throughout the pending %s stage', async (stage) => {
    const requests = installRequests(stage);
    const { user } = renderWithoutRouter(<BrowserRouter><CredentialTemplateWizard /></BrowserRouter>);
    await reachReview(user); await user.click(screen.getByTestId('wizard.template.submit'));
    await waitFor(() => expect(requests.isHeld()).toBe(true));
    const toggle = screen.getByRole('switch', { name: /Activate immediately/i });
    expect(toggle).toBeDisabled(); expect(toggle).toBeChecked();
    const edits = screen.getAllByRole('button', { name: 'Edit' });
    expect(edits).toHaveLength(4);
    for (const edit of edits) {
      expect(edit).toBeDisabled(); fireEvent.click(edit);
    }
    expect(screen.getByTestId('wizard.template.back')).toBeDisabled();
    expect(screen.getByTestId('wizard.template.submit')).toBeDisabled();
    fireEvent.click(toggle); fireEvent.click(screen.getByTestId('wizard.template.back'));
    expect(screen.getByRole('group', { name: 'Review & Activate' })).toBeInTheDocument();
    expect(toggle).toBeChecked();
    await requests.settle();
    expect(requests.writes.map(({ endpoint }) => endpoint)).toEqual(['create', 'activate']);
    expect(screen.getByText('"' + NAME + '" is now active.')).toBeInTheDocument();
  });

  it('guards data and review navigation before loading commits, and retains duplicate-submit protection', async () => {
    const requests = installRequests();
    const { user } = renderWithoutRouter(<BrowserRouter><CredentialTemplateWizard /></BrowserRouter>);
    await reachReview(user);
    const toggle = screen.getByRole('switch', { name: /Activate immediately/i });
    const edit = screen.getAllByRole('button', { name: 'Edit' })[0];
    const submit = screen.getByTestId('wizard.template.submit');
    const back = screen.getByTestId('wizard.template.back');
    act(() => {
      fireEvent.click(submit);
      // The DOM is still the enabled review. The synchronous ref, rather than
      // the later disabled fieldset, must reject these same-turn events.
      expect(toggle).not.toBeDisabled();
      fireEvent.click(toggle); fireEvent.click(edit); fireEvent.click(back); fireEvent.click(submit);
    });
    await waitFor(() => expect(requests.writes).toHaveLength(1));
    expect(screen.getByRole('group', { name: 'Review & Activate' })).toBeInTheDocument();
    expect(toggle).toBeChecked(); await requests.settle();
    expect(requests.writes.map(({ endpoint }) => endpoint)).toEqual(['create', 'activate']);
    expect(screen.getByText('"' + NAME + '" is now active.')).toBeInTheDocument();
  });

  it.each([false, true])('preserves draft intent chosen before submission (attempt pending edit: %s)', async (attemptEdit) => {
    const requests = installRequests();
    const { user } = renderWithoutRouter(<BrowserRouter><CredentialTemplateWizard /></BrowserRouter>);
    await reachReview(user);
    await user.click(screen.getByRole('switch', { name: /Activate immediately/i }));
    await user.click(screen.getByTestId('wizard.template.submit'));
    await waitFor(() => expect(requests.writes).toHaveLength(1));
    if (attemptEdit) await user.click(screen.getByRole('switch', { name: /Activate immediately/i }));
    await requests.settle();
    expect(requests.writes.map(({ endpoint }) => endpoint)).toEqual(['create']);
    expect(requests.reads).not.toContain('readback');
    expect(screen.getByText('"' + NAME + '" is saved as draft.')).toBeInTheDocument();
    expect(sessionStorage.getItem('marty:template-create:v1:org-1')).toBeNull();
  });

  it('restores review edits after a rejected create and uses the new intent on explicit retry', async () => {
    const requests = installRequests();
    const { user } = renderWithoutRouter(<BrowserRouter><CredentialTemplateWizard /></BrowserRouter>);
    await reachReview(user); await user.click(screen.getByTestId('wizard.template.submit'));
    await waitFor(() => expect(requests.writes).toHaveLength(1));
    await requests.settle(HttpResponse.json({ error: { message: 'Template policy rejected the request' } }, { status: 422 }));
    expect(screen.getByText(/Template policy rejected the request/)).toBeInTheDocument();
    const toggle = screen.getByRole('switch', { name: /Activate immediately/i });
    expect(toggle).toBeEnabled();
    for (const edit of screen.getAllByRole('button', { name: 'Edit' })) expect(edit).toBeEnabled();
    expect(sessionStorage.getItem('marty:template-create:v1:org-1')).toBeNull();
    await user.click(toggle); await user.click(screen.getByTestId('wizard.template.submit'));
    await screen.findByText('"' + NAME + '" is saved as draft.');
    expect(requests.writes.map(({ endpoint }) => endpoint)).toEqual(['create', 'create']);
  });

  it('preserves the acknowledged draft and retries only activation after its current failure', async () => {
    const requests = installRequests('activate');
    const { user } = renderWithoutRouter(<BrowserRouter><CredentialTemplateWizard /></BrowserRouter>);
    await reachReview(user); await user.click(screen.getByTestId('wizard.template.submit'));
    await waitFor(() => expect(requests.isHeld()).toBe(true));
    await requests.settle(HttpResponse.json({ error: { message: 'Activation policy temporarily unavailable' } }, { status: 503 }));
    expect(screen.getByText(/was created, but activation is incomplete/)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Open created draft' })).toBeEnabled();
    expect(screen.getByRole('switch', { name: /Activate immediately/i })).toBeEnabled();
    expect(JSON.parse(sessionStorage.getItem('marty:template-create:v1:org-1')!).resourceId).toBe(TEMPLATE_ID);
    await user.click(screen.getByRole('button', { name: 'Retry activation' }));
    await screen.findByText('"' + NAME + '" is now active.');
    expect(requests.writes.map(({ endpoint }) => endpoint)).toEqual(['create', 'activate', 'activate']);
    expect(requests.reads.filter(kind => kind === 'readback')).toHaveLength(2);
    expect(sessionStorage.getItem('marty:template-create:v1:org-1')).toBeNull();
  });

  it('keeps ordinary review editing available before submission', async () => {
    const requests = installRequests();
    const { user } = renderWithoutRouter(<BrowserRouter><CredentialTemplateWizard /></BrowserRouter>);
    await reachReview(user);
    await user.click(screen.getAllByRole('button', { name: 'Edit' })[0]);
    expect(screen.getByLabelText(/Template Name/i)).toBeEnabled();
    await user.clear(screen.getByLabelText(/Template Name/i));
    await user.type(screen.getByLabelText(/Template Name/i), 'Changed before submission');
    expect(screen.getByLabelText(/Template Name/i)).toHaveValue('Changed before submission');
    expect(requests.writes).toHaveLength(0);
  });
});

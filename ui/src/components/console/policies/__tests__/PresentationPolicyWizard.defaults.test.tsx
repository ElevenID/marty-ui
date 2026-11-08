import { webcrypto } from 'node:crypto';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { screen, waitFor } from '@testing-library/react';
import { http, HttpResponse } from 'msw';
import { render } from '@test/utils';
import { server } from '@test/mocks/server';
import Wizard from '../PresentationPolicyWizard';

vi.mock('../../../../contexts/ConsoleContext', () => ({ useConsole: () => ({ activeOrgId: 'org-a' }) }));
vi.mock('../../../../hooks/useAuth', () => ({ useAuth: () => ({ user: { user_id: 'user-a' } }) }));

const profiles = [
  { id: 'trust-a', name: 'Trust A', organization_id: 'org-a', status: 'ACTIVE', trust_framework_type: 'custom', supported_formats: ['SD_JWT_VC'] },
  { id: 'trust-b', name: 'Trust B', organization_id: 'org-a', status: 'ACTIVE', trust_framework_type: 'custom', supported_formats: ['MDOC'] },
];
const templates = [
  { id: 'template-a', name: 'Template A', organization_id: 'org-a', status: 'ACTIVE', trust_profile_id: 'trust-a',
    credential_payload_format: 'SD_JWT_VC', vct: 'urn:template-a', claims: [{ name: 'employee_id', required: true }] },
  { id: 'template-b', name: 'Template B', organization_id: 'org-a', status: 'ACTIVE', trust_profile_id: 'trust-b',
    credential_payload_format: 'MDOC', vct: 'urn:template-b', claims: [{ name: 'family_name', required: true }] },
];
let submitted: Record<string, any> | undefined;

beforeEach(() => {
  vi.stubGlobal('crypto', webcrypto); sessionStorage.clear(); submitted = undefined;
  server.use(
    http.get('*/v1/organizations/org-a/defaults', () => HttpResponse.json({ default_trust_profile_id: 'trust-a', default_template_id: 'template-a' })),
    http.get('*/v1/trust-profiles', () => HttpResponse.json(profiles)),
    http.get('*/v1/trust-profiles/:id', ({ params }) => HttpResponse.json(profiles.find((profile) => profile.id === params.id))),
    http.get('*/v1/credential-templates', () => HttpResponse.json(templates)),
    http.get('*/v1/credential-templates/:id', ({ params }) => HttpResponse.json(templates.find((template) => template.id === params.id))),
    http.post('*/v1/presentation-policies', async ({ request }) => {
      submitted = await request.json() as Record<string, any>;
      return HttpResponse.json({ ...submitted, id: 'created-policy', status: 'draft' }, { status: 201 });
    }),
    http.get('*/v1/presentation-policies/created-policy', () => HttpResponse.json({ ...submitted, id: 'created-policy', status: 'draft' })),
    http.post('*/v1/presentation-policies/created-policy/activate', () => HttpResponse.json({ ...submitted, id: 'created-policy', status: 'active' })),
  );
});

async function openAutomaticTemplate() {
  const view = render(<Wizard />);
  await waitFor(() => expect(screen.getByRole('button', { name: 'Select Trust A trust profile' })).toHaveAttribute('aria-pressed', 'true'));
  await view.user.click(screen.getByTestId('wizard.policy.next'));
  await waitFor(() => expect(screen.getByRole('button', { name: 'Select Template A presentation policy template' })).toHaveAttribute('aria-pressed', 'true'));
  return view;
}

async function finishFromClaims(user: ReturnType<typeof render>['user']) {
  await user.click(screen.getByTestId('wizard.policy.next'));
  await user.click(screen.getByTestId('wizard.policy.next'));
  await user.click(screen.getByTestId('wizard.policy.submit'));
  await waitFor(() => expect(submitted).toBeDefined());
}

describe('policy wizard automatic-template provenance', () => {
  it('clears incompatible automatic requirements after Back/change trust, preserving edits through Custom and its POST', async () => {
    const { user } = await openAutomaticTemplate();
    await user.click(screen.getByTestId('wizard.policy.next'));
    const name = await screen.findByRole('textbox', { name: /Policy Name/i });
    await user.clear(name); await user.type(name, 'Edited policy name');
    const purpose = screen.getByRole('textbox', { name: /Purpose Statement/i });
    await user.clear(purpose); await user.type(purpose, 'Edited purpose');

    await user.click(screen.getByTestId('wizard.policy.back'));
    await user.click(screen.getByTestId('wizard.policy.back'));
    await user.click(await screen.findByRole('button', { name: 'Select Trust B trust profile' }));
    await user.click(screen.getByTestId('wizard.policy.next'));
    const oldTemplate = await screen.findByRole('button', { name: 'Select Template A presentation policy template' });
    expect(oldTemplate).toHaveAttribute('aria-pressed', 'false');
    expect(screen.getByTestId('wizard.policy.next')).toBeDisabled();

    await user.click(screen.getByRole('button', { name: /Select Custom.*presentation policy template/i }));
    await user.click(screen.getByTestId('wizard.policy.next'));
    expect(await screen.findByRole('textbox', { name: /Policy Name/i })).toHaveValue('Edited policy name');
    expect(screen.getByRole('textbox', { name: /Purpose Statement/i })).toHaveValue('Edited purpose');
    expect(screen.queryByText('urn:template-a')).not.toBeInTheDocument();
    expect(screen.queryByRole('combobox', { name: /Claim Name/i })).not.toBeInTheDocument();

    await user.type(screen.getByRole('combobox', { name: /Add credential type/i }), 'urn:manual{Enter}');
    await user.click(screen.getByRole('button', { name: 'Add Claim' }));
    await user.type(screen.getByRole('combobox', { name: /Claim Name/i }), 'manual_claim');
    await finishFromClaims(user);
    expect(submitted).toMatchObject({
      name: 'Edited policy name', purpose: 'Edited purpose', trust_profile_id: 'trust-b',
      accepted_credential_types: ['urn:manual'], credential_requirements: [],
      required_claims: [{ claim_name: 'manual_claim', credential_type: 'urn:manual' }],
    });
    expect(JSON.stringify(submitted)).not.toContain('template-a');
    expect(JSON.stringify(submitted)).not.toContain('_organizationDefault');
  });

  it('preserves an explicitly chosen template when trust changes later', async () => {
    const { user } = await openAutomaticTemplate();
    // Clicking the card explicitly adopts the selection and removes its automatic origin.
    await user.click(screen.getByRole('button', { name: 'Select Template A presentation policy template' }));
    await user.click(screen.getByTestId('wizard.policy.back'));
    await user.click(await screen.findByRole('button', { name: 'Select Trust B trust profile' }));
    await user.click(screen.getByTestId('wizard.policy.next'));
    expect(await screen.findByRole('button', { name: 'Select Template A presentation policy template' })).toHaveAttribute('aria-pressed', 'true');
    expect(screen.getByTestId('wizard.policy.next')).toBeEnabled();
  });

  it('submits the valid automatically selected template without its UI-only provenance', async () => {
    const { user } = await openAutomaticTemplate();
    await user.click(screen.getByTestId('wizard.policy.next'));
    await screen.findByRole('textbox', { name: /Policy Name/i });
    await finishFromClaims(user);
    expect(submitted).toMatchObject({ trust_profile_id: 'trust-a',
      credential_requirements: [{ credential_template_id: 'template-a', trust_profile_id: 'trust-a' }],
      accepted_credential_types: ['urn:template-a'],
    });
    expect(JSON.stringify(submitted)).not.toContain('_organizationDefault');
    expect(JSON.stringify(submitted)).not.toContain('generatedConfig');
    expect(JSON.stringify(submitted)).not.toContain('previousConfig');
  });
});

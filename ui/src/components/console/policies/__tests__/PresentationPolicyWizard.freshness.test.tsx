import { webcrypto } from 'node:crypto';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { http, HttpResponse } from 'msw';
import { render, screen, waitFor } from '@test/utils';
import { server } from '@test/mocks/server';
import PresentationPolicyWizard from '../PresentationPolicyWizard';

vi.mock('../../../../contexts/ConsoleContext', () => ({ useConsole: () => ({ activeOrgId: 'org-a' }) }));
vi.mock('../../../../hooks/useAuth', () => ({ useAuth: () => ({ user: { user_id: 'user-a' } }) }));

const trust = {
  id: 'trust-a', organization_id: 'org-a', name: 'Employee Trust', status: 'ACTIVE',
  trust_framework_type: null, supported_formats: ['SD_JWT_VC', 'MDOC'],
};
const template = {
  id: 'template-a', organization_id: 'org-a', name: 'Employee Credential', status: 'ACTIVE',
  trust_profile_id: 'trust-a', credential_payload_format: 'SD_JWT_VC', vct: 'urn:employee',
  claims: [{ name: 'employee_id', display_name: 'Employee ID', required: true }],
};
let writes: Array<Record<string, any>>;

beforeEach(() => {
  vi.stubGlobal('crypto', webcrypto);
  sessionStorage.clear();
  writes = [];
  window.history.replaceState({}, '', '/console/org/policies/presentation/new');
  server.use(
    http.get('*/v1/organizations/org-a/defaults', () => HttpResponse.json({ default_trust_profile_id: 'trust-a', default_template_id: 'template-a' })),
    http.get('*/v1/trust-profiles', () => HttpResponse.json([trust])),
    http.get('*/v1/trust-profiles/trust-a', () => HttpResponse.json(trust)),
    http.get('*/v1/credential-templates', () => HttpResponse.json([template])),
    http.get('*/v1/credential-templates/template-a', () => HttpResponse.json(template)),
    http.post('*/v1/presentation-policies', async ({ request }) => {
      const body = await request.json() as Record<string, any>;
      writes.push(body);
      return HttpResponse.json({ ...body, id: 'created-policy', status: 'draft' }, { status: 201 });
    }),
  );
});

async function openFreshness(templateName = 'Employee Credential') {
  const view = render(<PresentationPolicyWizard />);
  const { user } = view;
  await waitFor(() => expect(screen.getByRole('button', { name: 'Select Employee Trust trust profile' })).toHaveAttribute('aria-pressed', 'true'));
  await user.click(screen.getByTestId('wizard.policy.next'));
  await waitFor(() => expect(screen.getByRole('button', { name: 'Select Employee Credential presentation policy template' })).toHaveAttribute('aria-pressed', 'true'));
  await user.click(screen.getByRole('button', { name: `Select ${templateName} presentation policy template` }));
  await user.click(screen.getByTestId('wizard.policy.next'));

  const name = (await screen.findByRole('textbox', { name: 'Policy Name' }) as HTMLInputElement).value;
  const description = (screen.getByRole('textbox', { name: 'Description' }) as HTMLInputElement).value;
  const purpose = (screen.getByRole('textbox', { name: 'Purpose Statement' }) as HTMLInputElement).value;
  expect(screen.queryByRole('switch', { name: 'Require Single Presentation' })).not.toBeInTheDocument();
  await user.click(screen.getByTestId('wizard.policy.next'));
  return { ...view, name, description, purpose };
}

describe('presentation policy settings in the complete wizard', () => {
  it.each([
    {
      templateName: 'Employee Credential', standard: 'SD_JWT_VC', binding: 'Authenticated Session',
      seconds: 86401, duration: '1 day, 1 second',
      nativeBinding: {
        required: true, binding_methods: ['SESSION_BINDING'], proof_profiles: ['OID4VP_VERIFIABLE_PRESENTATION'],
        proof_freshness: { challenge_required: true, audience_binding_required: true, replay_detection_required: true },
      },
    },
    {
      templateName: 'Age Verification (mDL)', standard: 'ISO 18013-5:2021', binding: 'None',
      seconds: 43200, duration: '12 hours',
      nativeBinding: { required: false },
    },
  ])('reviews and submits only saved settings for $templateName', async ({ templateName, standard, binding, nativeBinding, seconds, duration }) => {
    const { user, name, description, purpose } = await openFreshness(templateName);

    expect(screen.queryByRole('spinbutton', { name: 'Maximum Proof Age' })).not.toBeInTheDocument();
    expect(screen.queryByRole('textbox', { name: 'Standard Reference' })).not.toBeInTheDocument();
    const age = screen.getByRole('spinbutton', { name: 'Maximum Credential Age' });
    await user.clear(age);
    await user.type(age, String(seconds));
    await user.click(screen.getByRole('radio', { name: binding }));
    await user.click(screen.getByRole('switch', { name: 'Require Revocation Check' }));
    await user.click(screen.getByTestId('wizard.policy.next'));

    expect(screen.getByText(duration)).toBeInTheDocument();
    expect(screen.getByText(binding)).toBeInTheDocument();
    expect(screen.getByText('Not Required')).toBeInTheDocument();
    expect(screen.getByText(standard)).toBeInTheDocument();
    expect(screen.queryByText('Max Proof Age')).not.toBeInTheDocument();
    expect(screen.queryByText('Compliance Standard')).not.toBeInTheDocument();
    expect(screen.queryByText('Single Presentation')).not.toBeInTheDocument();

    await user.click(screen.getByTestId('wizard.policy.back'));
    expect(screen.getByRole('spinbutton', { name: 'Maximum Credential Age' })).toHaveValue(seconds);
    expect(screen.getByRole('radio', { name: binding })).toBeChecked();
    expect(screen.getByRole('switch', { name: 'Require Revocation Check' })).not.toBeChecked();
    await user.click(screen.getByTestId('wizard.policy.next'));
    await user.click(screen.getByRole('switch', { name: /Activate immediately/i }));
    await user.click(screen.getByTestId('wizard.policy.submit'));
    await screen.findByText(`"${name}" is saved as draft.`);

    expect(writes).toHaveLength(1);
    expect(writes[0].holder_binding).toEqual(nativeBinding);
    expect(writes[0].freshness).toEqual({ max_age_seconds: seconds, require_not_revoked: false });
    expect(writes[0].display_metadata).toEqual({
      title: name, description, purpose: 'identity_verification', purpose_description: purpose,
    });
    expect(JSON.stringify(writes[0])).not.toMatch(/max_proof_age_seconds|standard_reference|single_presentation/);
    expect(writes[0]).not.toHaveProperty('metadata');
  });

  it('keeps invalid drafts visible, prevents Next and Skip, and saves zero without replacing it', async () => {
    const { user, name } = await openFreshness();
    const age = screen.getByRole('spinbutton', { name: 'Maximum Credential Age' });
    for (const value of ['', '-1', '0.5', '0.99999999999999999', '9007199254740992']) {
      await user.clear(age);
      if (value) await user.type(age, value);
      expect(age).toHaveValue(value ? Number(value) : null);
      expect((age as HTMLInputElement).value).toBe(value);
      expect(age).toHaveAttribute('aria-invalid', 'true');
      expect(age).toHaveAccessibleDescription('Enter a valid whole number of seconds, 0 or greater.');
      expect(screen.getByTestId('wizard.policy.next')).toBeDisabled();
      expect(screen.getByTestId('wizard.policy.skip')).toBeDisabled();
      expect(writes).toHaveLength(0);
    }
    await user.clear(age);
    await user.type(age, '0');
    expect(age).toHaveValue(0);
    expect(age).not.toHaveAttribute('aria-invalid', 'true');
    expect(screen.getByTestId('wizard.policy.next')).toBeEnabled();
    expect(screen.getByTestId('wizard.policy.skip')).toBeEnabled();
    await user.click(screen.getByTestId('wizard.policy.skip'));
    expect(screen.getByText('0 seconds')).toBeInTheDocument();
    await user.click(screen.getByRole('switch', { name: /Activate immediately/i }));
    await user.click(screen.getByTestId('wizard.policy.submit'));
    await screen.findByText(`"${name}" is saved as draft.`);
    expect(writes).toHaveLength(1);
    expect(writes[0].freshness).toEqual({ max_age_seconds: 0, require_not_revoked: true });
  });
});

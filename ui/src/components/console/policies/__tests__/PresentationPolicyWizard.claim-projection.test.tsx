import { beforeEach, describe, expect, it, vi } from 'vitest';
import { webcrypto } from 'node:crypto';
import { http, HttpResponse } from 'msw';
import { act, render, screen, waitFor } from '@test/utils';
import { server } from '@test/mocks/server';
import i18n from '@test/i18nTestSetup';
import consoleFr from '../../../../../public/locales/fr/console.json';
import consoleDe from '../../../../../public/locales/de/console.json';
import * as claimsProjection from '../projectTemplatePolicyClaims';
import PresentationPolicyWizard from '../PresentationPolicyWizard';

vi.mock('../../../../contexts/ConsoleContext', () => ({ useConsole: () => ({ activeOrgId: 'org-a' }) }));
vi.mock('../../../../hooks/useAuth', () => ({ useAuth: () => ({ user: { user_id: 'user-a' } }) }));

const trust = { id: 'trust-a', organization_id: 'org-a', name: 'Employee Trust', status: 'ACTIVE', trust_framework_type: null, supported_formats: ['SD_JWT_VC'] };
const template = {
  id: 'template-a', organization_id: 'org-a', name: 'Employee Credential', status: 'ACTIVE',
  trust_profile_id: 'trust-a', credential_payload_format: 'SD_JWT_VC', vct: 'urn:employee',
  claims: [
    { name: 'employee_id', display_name: 'Employee ID', required: true },
    { name: 'role', display_name: 'Role', required: true, selectively_disclosable: false },
  ],
};
let writes: Array<Record<string, any>>;

beforeEach(() => {
  vi.stubGlobal('crypto', webcrypto); sessionStorage.clear(); writes = [];
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

async function configureClaims(explicitSelection = false) {
  const view = render(<PresentationPolicyWizard />);
  await waitFor(() => expect(screen.getByRole('button', { name: 'Select Employee Trust trust profile' })).toHaveAttribute('aria-pressed', 'true'));
  await view.user.click(screen.getByTestId('wizard.policy.next'));
  await waitFor(() => expect(screen.getByRole('button', { name: 'Select Employee Credential presentation policy template' })).toHaveAttribute('aria-pressed', 'true'));
  if (explicitSelection) await view.user.click(screen.getByRole('button', { name: 'Select Employee Credential presentation policy template' }));
  await view.user.click(screen.getByTestId('wizard.policy.next'));
  await screen.findByRole('textbox', { name: 'Policy Name' });
  return view;
}

describe('template policy claim projection in the complete wizard', () => {
  it('posts the edited claim set and required value in the native request actually used for verification', async () => {
    const { user } = await configureClaims();
    await user.click(screen.getByRole('button', { name: 'Remove claim 1' }));
    await user.type(screen.getByRole('textbox', { name: 'Required Value (Optional)' }), 'staff');
    await user.click(screen.getByTestId('wizard.policy.next'));
    await user.click(screen.getByTestId('wizard.policy.next'));
    expect(screen.getByText('Employee Trust')).toBeInTheDocument();
    expect(screen.queryByText('No trust profile selected')).not.toBeInTheDocument();
    expect(screen.getByText('Required value: "staff"')).toBeInTheDocument();
    await user.click(screen.getByRole('switch', { name: /Activate immediately/i }));
    await user.click(screen.getByTestId('wizard.policy.submit'));
    await screen.findByText('"Employee Credential Verification Policy" is saved as draft.');
    expect(writes).toHaveLength(1);
    expect(writes[0].trust_profile_id).toBe(trust.id);
    expect(writes[0].required_claims).toEqual([{
      claim_name: 'role', credential_type: 'urn:employee', value_constraint: 'staff', predicate_spec: null,
    }]);
    expect(writes[0].credential_requirements).toEqual([{
      credential_template_id: 'template-a', display_name: 'Employee Credential', description: '', required: true,
      credential_payload_format: 'SD_JWT_VC', trust_profile_id: 'trust-a',
      requested_claims: [{
        claim_name: 'role', display_name: 'Role', required: true, selective_disclosure: false,
        accept_derived: false, constraints: [{ claim_name: 'role', constraint_type: 'equals', value: 'staff' }],
      }],
    }]);
    expect(writes[0].accepted_credential_types).toEqual(['urn:employee']);
  });

  it('explains unsupported template type and claim changes in Configure Claims and recovers after correction', async () => {
    const { user } = await configureClaims();
    await user.type(screen.getByRole('combobox', { name: 'Add credential type' }), 'urn:other{Enter}');
    expect(screen.getByText(/This policy is bound to the selected credential template/)).toBeInTheDocument();
    expect(screen.getByTestId('wizard.policy.next')).toBeDisabled();
    await user.click(screen.getByRole('button', { name: 'urn:other' })); await user.keyboard('{Delete}');
    expect(screen.getByTestId('wizard.policy.next')).toBeEnabled();
    const claimName = screen.getAllByRole('combobox', { name: 'Claim Name' })[0];
    await user.clear(claimName); await user.type(claimName, 'unsupported_claim'); await user.tab();
    expect(screen.getByText(/is not a claim in the selected credential template/)).toBeInTheDocument();
    expect(screen.getByTestId('wizard.policy.next')).toBeDisabled();
    await user.clear(claimName); await user.type(claimName, 'employee_id'); await user.tab();
    expect(screen.getByTestId('wizard.policy.next')).toBeEnabled();
    expect(writes).toEqual([]);
  });

  it('translates an existing projection error and its claim name when the language changes', async () => {
    const { user, unmount } = await configureClaims();
    try {
      const claimName = screen.getAllByRole('combobox', { name: 'Claim Name' })[0];
      await user.clear(claimName); await user.type(claimName, 'unknown_claim'); await user.tab();
      i18n.addResourceBundle('fr', 'console', consoleFr, true, true);
      await act(async () => { await i18n.changeLanguage('fr'); });
      expect(screen.getByText('« unknown_claim » n’est pas un attribut du modèle d’attestation sélectionné. Sélectionnez un attribut du modèle ou créez une nouvelle politique personnalisée.')).toBeInTheDocument();
      expect(screen.getByTestId('wizard.policy.next')).toBeDisabled();
      i18n.addResourceBundle('de', 'console', consoleDe, true, true);
      await act(async () => { await i18n.changeLanguage('de'); });
      expect(screen.getByText('„unknown_claim“ ist kein Claim der ausgewählten Nachweisvorlage. Wählen Sie einen Claim aus der Vorlage oder erstellen Sie eine neue benutzerdefinierte Richtlinie.')).toBeInTheDocument();
      expect(screen.getByTestId('wizard.policy.next')).toBeDisabled();
    } finally {
      unmount();
      await i18n.changeLanguage('en');
    }
  });

  it('uses the translated projection message when the final submission guard rejects the request', async () => {
    const { user, unmount } = await configureClaims();
    const projection = vi.spyOn(claimsProjection, 'projectTemplatePolicyClaims');
    try {
      await user.click(screen.getByTestId('wizard.policy.next'));
      await user.click(screen.getByTestId('wizard.policy.next'));
      i18n.addResourceBundle('fr', 'console', consoleFr, true, true);
      await act(async () => { await i18n.changeLanguage('fr'); });
      projection.mockImplementationOnce(() => {
        throw new claimsProjection.TemplatePolicyClaimsError(
          'templateValueConflict',
          'The required value for “role” conflicts with a constraint from the selected template.',
          { claimName: 'role' },
        );
      });
      await user.click(screen.getByTestId('wizard.policy.submit'));
      expect(await screen.findByText('La valeur requise pour « role » est incompatible avec une contrainte du modèle sélectionné.')).toBeInTheDocument();
      expect(writes).toEqual([]);
    } finally {
      projection.mockRestore();
      unmount();
      await i18n.changeLanguage('en');
    }
  });

  it.each(['Custom Policy', 'Age Verification (mDL)'])('removes a manually selected template binding when switching to %s', async (nextTemplate) => {
    const { user } = await configureClaims(true);
    const name = screen.getByRole('textbox', { name: 'Policy Name' });
    await user.clear(name); await user.type(name, 'Reviewed inline policy');
    await user.type(screen.getAllByRole('textbox', { name: 'Required Value (Optional)' })[0], 'employee-007');
    await user.click(screen.getByTestId('wizard.policy.back'));
    await user.click(screen.getByRole('button', { name: `Select ${nextTemplate} presentation policy template` }));
    await user.click(screen.getByTestId('wizard.policy.next'));
    expect(screen.getByTestId('wizard.policy.next')).toBeEnabled();
    if (nextTemplate === 'Custom Policy') {
      expect(screen.getByRole('textbox', { name: 'Policy Name' })).toHaveValue('Reviewed inline policy');
      expect(screen.getAllByRole('textbox', { name: 'Required Value (Optional)' })[0]).toHaveValue('employee-007');
    }
    await user.click(screen.getByTestId('wizard.policy.next'));
    await user.click(screen.getByTestId('wizard.policy.next'));
    await user.click(screen.getByRole('switch', { name: /Activate immediately/i }));
    await user.click(screen.getByTestId('wizard.policy.submit'));
    await waitFor(() => expect(writes).toHaveLength(1));
    expect(writes[0].credential_requirements).toEqual([]);
    expect(writes[0].trust_profile_id).toBe('trust-a');
    expect(JSON.stringify(writes[0])).not.toContain('template-a');
    if (nextTemplate === 'Custom Policy') {
      expect(writes[0].accepted_credential_types).toEqual(['urn:employee']);
      expect(writes[0].required_claims[0]).toMatchObject({ claim_name: 'employee_id', value_constraint: 'employee-007' });
    } else {
      expect(writes[0].accepted_credential_types).toEqual(['org.iso.18013.5.1.mDL']);
      expect(writes[0].required_claims.map((claim) => claim.claim_name)).toEqual(['age_over_21', 'age_over_18']);
    }
  });
});

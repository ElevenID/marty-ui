import { useState } from 'react';
import { act, screen, waitFor } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render } from '@test/utils';
import TrustProfileStep from '../steps/TrustProfileStep';
import TemplateSelectionStep from '../steps/TemplateSelectionStep';
import { getOrganizationDefaults } from '../../../../services/organizationsApi';
import { listCredentialTemplates, listTrustProfiles } from '../../../../services/presentationPolicyApi';

const scope = vi.hoisted(() => ({ organizationId: 'org-a' }));
vi.mock('../../../../contexts/ConsoleContext', () => ({ useConsole: () => ({ activeOrgId: scope.organizationId }) }));
vi.mock('../../../../services/organizationsApi', () => ({ getOrganizationDefaults: vi.fn() }));
vi.mock('../../../../services/presentationPolicyApi', () => ({ listCredentialTemplates: vi.fn(), listTrustProfiles: vi.fn() }));

const trust = (id: string, overrides = {}) => ({ id, name: id, organization_id: 'org-a', status: 'ACTIVE',
  trust_framework_type: 'custom', supported_formats: ['SD_JWT_VC'], ...overrides });
const template = (id: string, overrides = {}) => ({ id, name: id, organization_id: 'org-a', status: 'ACTIVE',
  trust_profile_id: 'trust-default', credential_payload_format: 'SD_JWT_VC', vct: `urn:example:${id}`,
  claims: [{ name: 'employee_id', required: true }], ...overrides });
function deferred() {
  let resolve!: (value: Record<string, unknown>) => void;
  const promise = new Promise<Record<string, unknown>>((complete) => { resolve = complete; });
  return { promise, resolve };
}
function TrustHarness({ initial = null }: { initial?: any }) {
  const [selected, setSelected] = useState(initial);
  return <><TrustProfileStep selectedTrustProfile={selected} onSelectTrustProfile={setSelected} />
    <output data-testid="selection">{JSON.stringify(selected)}</output></>;
}
function TemplateHarness({ selectedTrust = trust('trust-default') }: { selectedTrust?: any }) {
  const [selected, setSelected] = useState<any>(null);
  return <><TemplateSelectionStep trustProfile={selectedTrust} selectedTemplate={selected} onSelectTemplate={setSelected} />
    <output data-testid="selection">{JSON.stringify(selected)}</output></>;
}
const selection = () => JSON.parse(screen.getByTestId('selection').textContent!);

beforeEach(() => {
  scope.organizationId = 'org-a'; vi.resetAllMocks();
  vi.mocked(getOrganizationDefaults).mockResolvedValue({});
  vi.mocked(listTrustProfiles).mockResolvedValue([trust('trust-first'), trust('trust-default')]);
  vi.mocked(listCredentialTemplates).mockResolvedValue([template('template-first'), template('template-default')]);
});

describe('policy trust defaults', () => {
  it('preselects the configured active trust profile among multiple choices', async () => {
    vi.mocked(getOrganizationDefaults).mockResolvedValue({ default_trust_profile_id: 'trust-default' });
    render(<TrustHarness />);
    await waitFor(() => expect(selection()?.id).toBe('trust-default'));
    expect(screen.getByRole('button', { name: 'Select trust-default trust profile' })).toHaveAttribute('aria-pressed', 'true');
  });

  it('preserves an existing trust selection', async () => {
    vi.mocked(getOrganizationDefaults).mockResolvedValue({ default_trust_profile_id: 'trust-default' });
    render(<TrustHarness initial={trust('trust-first')} />);
    await screen.findByRole('button', { name: 'Select trust-default trust profile' });
    expect(selection().id).toBe('trust-first');
  });

  it('preserves a manual trust choice made before defaults arrive', async () => {
    const pending = deferred(); vi.mocked(getOrganizationDefaults).mockReturnValue(pending.promise);
    const { user } = render(<TrustHarness />);
    await user.click(await screen.findByRole('button', { name: 'Select trust-first trust profile' }));
    await act(async () => { pending.resolve({ default_trust_profile_id: 'trust-default' }); await pending.promise; });
    expect(selection().id).toBe('trust-first');
  });

  it.each([
    ['inactive', { status: 'DRAFT' }], ['foreign', { organization_id: 'org-other' }],
  ])('ignores an %s configured trust profile', async (_label, overrides) => {
    vi.mocked(getOrganizationDefaults).mockResolvedValue({ default_trust_profile_id: 'trust-default' });
    vi.mocked(listTrustProfiles).mockResolvedValue([trust('trust-first'), trust('trust-default', overrides)]);
    const { user } = render(<TrustHarness />);
    const choice = await screen.findByRole('button', { name: 'Select trust-first trust profile' });
    expect(selection()).toBeNull();
    await user.click(choice);
    expect(selection().id).toBe('trust-first');
  });

  it('does not select late defaults from the previous organization', async () => {
    const old = deferred();
    vi.mocked(getOrganizationDefaults).mockImplementation((id) => id === 'org-a' ? old.promise : Promise.resolve({ default_trust_profile_id: 'trust-b' }));
    vi.mocked(listTrustProfiles).mockImplementation(({ organization_id }) => Promise.resolve([
      trust(`trust-${organization_id === 'org-a' ? 'a' : 'b'}`, { organization_id }), trust(`other-${organization_id}`, { organization_id }),
    ]));
    const view = render(<TrustHarness />);
    await screen.findByRole('button', { name: 'Select trust-a trust profile' });
    scope.organizationId = 'org-b'; view.rerender(<TrustHarness />);
    await waitFor(() => expect(selection()?.id).toBe('trust-b'));
    await act(async () => { old.resolve({ default_trust_profile_id: 'trust-a' }); await old.promise; });
    expect(selection().id).toBe('trust-b');
  });

  it('keeps trust selection available when loading defaults fails', async () => {
    vi.mocked(getOrganizationDefaults).mockRejectedValue(new Error('defaults unavailable'));
    const { user } = render(<TrustHarness />);
    await user.click(await screen.findByRole('button', { name: 'Select trust-first trust profile' }));
    expect(selection().id).toBe('trust-first');
  });
});

describe('policy credential-template defaults', () => {
  it('uses a compatible default template to prefill actual credential type and claims', async () => {
    vi.mocked(getOrganizationDefaults).mockResolvedValue({ default_template_id: 'template-default' });
    render(<TemplateHarness />);
    await waitFor(() => expect(selection()?.id).toBe('credential-template:template-default'));
    expect(selection().config).toMatchObject({
      accepted_credential_types: ['urn:example:template-default'],
      credential_requirements: [{ credential_template_id: 'template-default', requested_claims: [{ claim_name: 'employee_id' }] }],
    });
  });

  it.each([
    ['inactive', { status: 'DRAFT' }],
    ['foreign', { organization_id: 'org-other' }],
    ['different trust', { trust_profile_id: 'trust-other' }],
    ['unsupported format', { credential_payload_format: 'MDOC' }],
  ])('ignores a %s template default', async (_label, overrides) => {
    const pending = deferred(); vi.mocked(getOrganizationDefaults).mockReturnValue(pending.promise);
    vi.mocked(listCredentialTemplates).mockResolvedValue([template('template-first'), template('template-default', overrides)]);
    render(<TemplateHarness />);
    await screen.findByRole('button', { name: /Select template-first presentation policy template/ });
    await act(async () => { pending.resolve({ default_template_id: 'template-default' }); await pending.promise; });
    expect(selection()).toBeNull();
  });

  it('does not replace a custom policy choice with a late default template', async () => {
    const pending = deferred(); vi.mocked(getOrganizationDefaults).mockReturnValue(pending.promise);
    const { user } = render(<TemplateHarness />);
    await user.click(await screen.findByRole('button', { name: /Select Custom.*presentation policy template/i }));
    await act(async () => { pending.resolve({ default_template_id: 'template-default' }); await pending.promise; });
    expect(selection().id).toBe('custom');
  });
});

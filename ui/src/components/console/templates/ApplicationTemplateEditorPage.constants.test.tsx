import { beforeEach, describe, expect, it, vi } from 'vitest';
import { Route, Routes } from 'react-router';
import { fireEvent, renderWithRouter, screen, waitFor } from '@test/utils';
import ApplicationTemplateEditorPage from './ApplicationTemplateEditorPage';
import { listCredentialTemplates } from '../../../services/presentationPolicyApi';
import { createApplicationTemplate, getApplicationTemplate, updateApplicationTemplate } from '../../../services/applicationTemplatesApi';

vi.mock('../../../contexts/ConsoleContext', () => ({ useConsole: () => ({ activeOrgId: 'org-1' }) }));
vi.mock('../../../hooks/usePermissions', () => ({ usePermissions: () => ({ can: () => true, isLoading: false }) }));
vi.mock('../../../hooks/useAuth', () => ({ useAuth: () => ({ user: { user_id: 'operator-1' }, isAuthenticated: true }) }));
vi.mock('../../../services/presentationPolicyApi', () => ({ listCredentialTemplates: vi.fn() }));
vi.mock('../../../services/policySetsApi', () => ({ listPolicySets: vi.fn().mockResolvedValue([]) }));
vi.mock('../../../services/applicationTemplatesApi', () => ({
  createApplicationTemplate: vi.fn(), getApplicationTemplate: vi.fn(), updateApplicationTemplate: vi.fn(),
}));

const criteria = { narrative: 'Complete the course and assessment.', id: 'https://issuer.example.test/criteria' };
type ClaimRuleFixture = { claim_name: string, source: string, source_config: Record<string, unknown> };
const constant = (name: string, value: unknown): ClaimRuleFixture => ({
  claim_name: name, source: 'SYSTEM', source_config: { system_field: 'constant', value },
});
const badge = (name = 'achievement_criteria', type = 'object') => ({
  id: 'credential-1', organization_id: 'org-1', name: 'Safety Badge', status: 'ACTIVE',
  credential_type: 'open_badge_v3', revocation_profile_id: 'revocation-1',
  claims: [
    { name: 'achievement_name', type: 'string', required: true },
    { name: 'achievement_description', type: 'string' },
    { name, claim_type: type, required: true },
  ],
});
const application = (rules: ClaimRuleFixture[] = [constant('achievement_criteria', criteria)]) => ({
  id: 'application-1', organization_id: 'org-1', name: 'Safety application', status: 'DRAFT',
  credential_template_id: 'credential-1',
  form_fields: [{ field_id: 'email', label: 'Email', field_type: 'EMAIL', required: true }],
  claim_collection_rules: rules,
});

function editor(path = '/console/org/templates/applications/application-1/edit') {
  return renderWithRouter(<Routes>
    <Route path="/console/org/templates/applications/new" element={<ApplicationTemplateEditorPage />} />
    <Route path="/console/org/templates/applications/:templateId/edit" element={<ApplicationTemplateEditorPage />} />
    <Route path="/console/org/templates/applications/:templateId" element={<h1>Saved template</h1>} />
  </Routes>, { initialEntries: [path] });
}

describe('Application Template typed claim constants', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    window.history.replaceState({}, '', '/');
    vi.mocked(listCredentialTemplates).mockResolvedValue([badge()]);
    vi.mocked(getApplicationTemplate).mockResolvedValue(application());
    vi.mocked(createApplicationTemplate).mockResolvedValue({ id: 'saved-draft' });
    vi.mocked(updateApplicationTemplate).mockResolvedValue({ id: 'application-1' });
  });

  it('keeps a new badge draft and configures object criteria without creating a text form field', async () => {
    const { user } = editor('/console/org/templates/applications/new');
    await user.type(screen.getByRole('textbox', { name: /^name/i }), 'New safety application');
    await user.click(await screen.findByRole('combobox', { name: 'Credential Template' }));
    await user.click(await screen.findByRole('option', { name: 'Safety Badge' }));
    expect(screen.getByRole('textbox', { name: /^name/i })).toHaveValue('New safety application');
    expect(screen.getAllByRole('textbox', { name: 'Field ID' }).map((field) => (field as HTMLInputElement).value))
      .toEqual(['achievement_name', 'achievement_description']);
    expect(screen.getByText(/Object and array claims need issuer-configured JSON/)).toHaveTextContent('achievement_criteria');
    await user.click(screen.getByRole('button', { name: 'Add rule' }));
    await user.type(screen.getByRole('textbox', { name: 'Claim name' }), 'achievement_criteria');
    await user.click(screen.getByRole('combobox', { name: 'Source' }));
    await user.click(screen.getByRole('option', { name: 'SYSTEM' }));
    await user.click(screen.getByRole('combobox', { name: 'System value' }));
    await user.click(screen.getByRole('option', { name: 'constant' }));
    expect(screen.getByRole('combobox', { name: 'Constant value format' })).toHaveTextContent('JSON');
    expect(screen.getByRole('button', { name: /save draft/i })).toBeDisabled();
    const input = screen.getByRole('textbox', { name: 'Constant value (JSON)' });
    expect(input).toHaveValue('');
    fireEvent.change(input, { target: { value: JSON.stringify(criteria) } });
    await user.click(screen.getByRole('button', { name: /save draft/i }));
    await waitFor(() => expect(createApplicationTemplate).toHaveBeenCalledWith(expect.objectContaining({
      name: 'New safety application', claim_collection_rules: [constant('achievement_criteria', criteria)],
      form_fields: expect.not.arrayContaining([expect.objectContaining({ field_id: 'achievement_criteria' })]),
    }), expect.any(Object)));
  });

  it('displays and edits an existing object without converting its JSON values into strings', async () => {
    const { user } = editor();
    const input = await screen.findByRole('textbox', { name: 'Constant value (JSON)' });
    expect(input).toHaveValue(JSON.stringify(criteria, null, 2));
    const updated = { ...criteria, extension: { enabled: false, score: 0, tags: ['course', 'assessment'] } };
    fireEvent.change(input, { target: { value: JSON.stringify(updated, null, 2) } });
    await user.click(screen.getByRole('button', { name: /save draft/i }));
    expect(updateApplicationTemplate).toHaveBeenCalledWith('application-1', expect.objectContaining({
      claim_collection_rules: [constant('achievement_criteria', updated)],
    }));
  });

  it.each([
    ['literal JSON-looking text', '{"narrative":"keep this text"}', 'string', 'Text'],
    ['false', false, 'boolean', 'JSON'],
    ['zero', 0, 'number', 'JSON'],
    ['array', ['course', { approved: true }], 'array', 'JSON'],
    ['object', criteria, 'object', 'JSON'],
  ])('preserves an untouched %s constant and its actual type', async (_label, value, type, format) => {
    vi.mocked(listCredentialTemplates).mockResolvedValue([badge('custom_value', type as string)]);
    vi.mocked(getApplicationTemplate).mockResolvedValue(application([constant('custom_value', value)]));
    const { user } = editor('/console/org/templates/applications/application-1/edit?mode=advanced');
    expect(await screen.findByRole('combobox', { name: 'Constant value format' })).toHaveTextContent(format as string);
    await user.click(screen.getByRole('button', { name: /save draft/i }));
    expect(updateApplicationTemplate).toHaveBeenCalledWith('application-1', expect.objectContaining({
      claim_collection_rules: [constant('custom_value', value)],
    }));
  });

  it.each(['{', 'null', '[]', '"a string"', '{"score":1e400}'])('retains invalid object draft %s and blocks saving until corrected', async (text) => {
    const { user } = editor();
    const input = await screen.findByRole('textbox', { name: 'Constant value (JSON)' });
    fireEvent.change(input, { target: { value: text } });
    expect(input).toHaveValue(text);
    expect(input).toHaveAttribute('aria-invalid', 'true');
    expect(input).toHaveAccessibleDescription(/JSON/);
    const save = screen.getByRole('button', { name: /save draft/i });
    expect(save).toBeDisabled();
    fireEvent.click(save);
    expect(updateApplicationTemplate).not.toHaveBeenCalled();
    fireEvent.change(input, { target: { value: JSON.stringify(criteria) } });
    expect(input).toHaveAttribute('aria-invalid', 'false');
    await user.click(save);
    expect(updateApplicationTemplate).toHaveBeenCalledWith('application-1', expect.objectContaining({
      claim_collection_rules: [constant('achievement_criteria', criteria)],
    }));
  });

  it('accepts a nested achievement object and requires an array for array claims', async () => {
    vi.mocked(listCredentialTemplates).mockResolvedValue([{
      ...badge(), claims: [{ name: 'achievement', type: 'object', required: true }, { name: 'tags', type: 'array' }],
    }]);
    const achievement = { name: 'Safety', criteria };
    vi.mocked(getApplicationTemplate).mockResolvedValue(application([
      constant('achievement', achievement), constant('tags', ['safety']),
    ]));
    const { user } = editor();
    const inputs = await screen.findAllByRole('textbox', { name: 'Constant value (JSON)' });
    expect(inputs[0]).toHaveValue(JSON.stringify(achievement, null, 2));
    fireEvent.change(inputs[1], { target: { value: '{}' } });
    expect(inputs[1]).toHaveAccessibleDescription(/requires a JSON array/);
    expect(screen.getByRole('button', { name: /save draft/i })).toBeDisabled();
    fireEvent.change(inputs[1], { target: { value: '["safety","training"]' } });
    await user.click(screen.getByRole('button', { name: /save draft/i }));
    expect(updateApplicationTemplate).toHaveBeenCalledWith('application-1', expect.objectContaining({
      claim_collection_rules: [constant('achievement', achievement), constant('tags', ['safety', 'training'])],
    }));
  });

  it('clears an abandoned JSON error when the operator selects another canonical source', async () => {
    const { user } = editor();
    const input = await screen.findByRole('textbox', { name: 'Constant value (JSON)' });
    fireEvent.change(input, { target: { value: '{' } });
    await user.click(screen.getByRole('combobox', { name: 'Source' }));
    await user.click(screen.getByRole('option', { name: 'EVIDENCE_EXTRACTION' }));
    await user.type(screen.getByRole('textbox', { name: 'Evidence fact type' }), 'achievement.criteria');
    await user.type(screen.getByRole('textbox', { name: 'Evidence value path' }), '/assertion/criteria');
    expect(screen.queryByRole('textbox', { name: 'Constant value (JSON)' })).not.toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: /save draft/i }));
    expect(updateApplicationTemplate).toHaveBeenCalledWith('application-1', expect.objectContaining({
      claim_collection_rules: [{ claim_name: 'achievement_criteria', source: 'EVIDENCE_EXTRACTION',
        source_config: { fact_type: 'achievement.criteria', json_pointer: '/assertion/criteria' } }],
    }));
  });

  it('shows a missing scalar constant in the basic editor and requires an entered value', async () => {
    vi.mocked(listCredentialTemplates).mockResolvedValue([badge('custom_value', 'string')]);
    vi.mocked(getApplicationTemplate).mockResolvedValue(application([{
      claim_name: 'custom_value', source: 'SYSTEM', source_config: { system_field: 'constant' },
    }]));
    const { user } = editor();
    const input = await screen.findByRole('textbox', { name: 'Constant value' });
    expect(input).toHaveAccessibleDescription('Enter a constant value.');
    expect(screen.getByRole('button', { name: /save draft/i })).toBeDisabled();
    fireEvent.change(input, { target: { value: '{"keep":"literal text"}' } });
    expect(input).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: /save draft/i }));
    expect(updateApplicationTemplate).toHaveBeenCalledWith('application-1', expect.objectContaining({
      claim_collection_rules: [constant('custom_value', '{"keep":"literal text"}')],
    }));
  });

  it('lets the operator correct stored text criteria without silently parsing the text', async () => {
    vi.mocked(getApplicationTemplate).mockResolvedValue(application([constant('achievement_criteria', JSON.stringify(criteria))]));
    const { user } = editor();
    const input = await screen.findByRole('textbox', { name: 'Constant value (JSON)' });
    expect(input).toHaveValue(JSON.stringify(JSON.stringify(criteria), null, 2));
    expect(input).toHaveAccessibleDescription(/requires a JSON object/);
    expect(screen.getByRole('button', { name: /save draft/i })).toBeDisabled();
    fireEvent.change(input, { target: { value: JSON.stringify(criteria) } });
    await user.click(screen.getByRole('button', { name: /save draft/i }));
    expect(updateApplicationTemplate).toHaveBeenCalledWith('application-1', expect.objectContaining({
      claim_collection_rules: [constant('achievement_criteria', criteria)],
    }));
  });

  it('changes a text constant to a boolean only after the operator selects JSON', async () => {
    vi.mocked(listCredentialTemplates).mockResolvedValue([badge('custom_value', 'boolean')]);
    vi.mocked(getApplicationTemplate).mockResolvedValue(application([constant('custom_value', 'false')]));
    const { user } = editor();
    expect(await screen.findByRole('textbox', { name: 'Constant value' })).toHaveValue('false');
    await user.click(screen.getByRole('combobox', { name: 'Constant value format' }));
    await user.click(screen.getByRole('option', { name: 'JSON' }));
    expect(screen.getByRole('textbox', { name: 'Constant value (JSON)' })).toHaveValue('false');
    await user.click(screen.getByRole('button', { name: /save draft/i }));
    expect(updateApplicationTemplate).toHaveBeenCalledWith('application-1', expect.objectContaining({
      claim_collection_rules: [constant('custom_value', false)],
    }));
  });

  it('preserves another constant draft when an invalid rule before it is removed', async () => {
    vi.mocked(getApplicationTemplate).mockResolvedValue(application([
      constant('achievement_criteria', criteria), constant('achievement_description', 'Original description'),
    ]));
    const { user } = editor();
    fireEvent.change(await screen.findByRole('textbox', { name: 'Constant value (JSON)' }), { target: { value: '{' } });
    const text = screen.getByRole('textbox', { name: 'Constant value' });
    await user.clear(text);
    await user.type(text, 'Edited description');
    await user.click(screen.getByRole('button', { name: 'Delete achievement_criteria' }));
    expect(screen.getByRole('textbox', { name: 'Constant value' })).toBe(text);
    await user.click(screen.getByRole('button', { name: /save draft/i }));
    expect(updateApplicationTemplate).toHaveBeenCalledWith('application-1', expect.objectContaining({
      claim_collection_rules: [constant('achievement_description', 'Edited description')],
    }));
  });
});

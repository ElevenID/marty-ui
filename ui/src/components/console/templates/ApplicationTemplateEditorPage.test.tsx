import { beforeEach, describe, expect, it, vi } from 'vitest'
import { Link, Route, Routes } from 'react-router'
import { act, fireEvent, render, renderWithRouter, screen, waitFor } from '@test/utils'

import ApplicationTemplateEditorPage from './ApplicationTemplateEditorPage'
import { formatFieldOptions, parseFieldOptions } from './applicationFieldOptions'
import {
  createApplicationTemplate,
  getApplicationTemplate,
  updateApplicationTemplate,
} from '../../../services/applicationTemplatesApi'

const { scope } = vi.hoisted(() => ({ scope: {
  activeOrgId: 'org-1', principal: 'principal-1', permitted: true, permissionsLoading: false, authenticated: true,
} }))
vi.mock('../../../contexts/ConsoleContext', () => ({
  useConsole: () => scope,
}))

vi.mock('../../../hooks/usePermissions', () => ({
  usePermissions: () => ({ can: () => scope.permitted, isLoading: scope.permissionsLoading }),
}))
vi.mock('../../../hooks/useAuth', () => ({
  useAuth: () => ({ user: { user_id: scope.principal }, isAuthenticated: scope.authenticated }),
}))

vi.mock('../../../services/presentationPolicyApi', () => ({
  listCredentialTemplates: vi.fn(async ({ organization_id }) => [
    {
      id: 'credential-1',
      organization_id,
      name: 'Membership Badge',
      status: 'ACTIVE',
      revocation_profile_id: 'revocation-1',
      claims: [
        {
          name: 'member_id',
          display_name: 'Member ID',
          type: 'STRING',
          required: true,
        },
      ],
    },
  ]),
}))

vi.mock('../../../services/policySetsApi', () => ({
  listPolicySets: vi.fn().mockResolvedValue([]),
}))

vi.mock('../../../services/applicationTemplatesApi', () => ({
  createApplicationTemplate: vi.fn(),
  getApplicationTemplate: vi.fn(),
  updateApplicationTemplate: vi.fn(),
}))

function draftTemplate(id = 'application-template-1', organizationId = 'org-1') {
  return {
    id, organization_id: organizationId, name: `Draft ${id} ${organizationId}`, status: 'DRAFT',
    credential_template_id: 'credential-1',
    form_fields: [{ field_id: 'email', label: 'Email', field_type: 'EMAIL' }],
  };
}

function deferred() {
  let resolve!: (value: unknown) => void;
  let reject!: (reason: Error) => void;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}

function EditorRoutes() {
  return <Routes>
    <Route path="/console/org/templates/applications/new" element={<ApplicationTemplateEditorPage />} />
    <Route path="/console/org/templates/applications/:templateId/edit" element={<>
      <Link to="/console/org/templates/applications/other-template/edit">Other template</Link>
      <ApplicationTemplateEditorPage />
    </>} />
    <Route path="/console/org/templates/applications/:templateId" element={<h1>Saved template</h1>} />
    <Route path="/console/org/templates/applications" element={<h1>Template list</h1>} />
  </Routes>;
}

describe('ApplicationTemplateEditorPage', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    window.history.replaceState({}, '', '/');
    Object.assign(scope, { activeOrgId: 'org-1', principal: 'principal-1', permitted: true, permissionsLoading: false, authenticated: true });
    vi.mocked(getApplicationTemplate).mockReset().mockImplementation(async (id, organizationId) => draftTemplate(id, organizationId));
    vi.mocked(createApplicationTemplate).mockReset().mockResolvedValue({ id: 'saved-draft' });
    vi.mocked(updateApplicationTemplate).mockReset().mockResolvedValue({ id: 'application-template-1' });
  })

  it('rejects an existing foreign template before showing editable values', async () => {
    vi.mocked(getApplicationTemplate).mockResolvedValueOnce({ id: 'application-template-1', organization_id: 'org-2', name: 'Foreign draft', status: 'DRAFT' })
    renderWithRouter(<Routes><Route path="/applications/:templateId/edit" element={<ApplicationTemplateEditorPage />} /></Routes>,
      { initialEntries: ['/applications/application-template-1/edit'] })
    expect(await screen.findByRole('alert')).toHaveTextContent(/selected organization/i)
    expect(screen.queryByDisplayValue('Foreign draft')).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /save draft/i })).not.toBeInTheDocument()
    expect(updateApplicationTemplate).not.toHaveBeenCalled()
  })

  it('clears an unsaved draft when the selected organization changes', async () => {
    const { user, rerender } = renderWithRouter(<ApplicationTemplateEditorPage />)
    await user.type(screen.getByRole('textbox', { name: /^name/i }), 'Old organization draft')
    scope.activeOrgId = 'org-2'
    rerender(<ApplicationTemplateEditorPage />)
    expect(screen.getByRole('textbox', { name: /^name/i })).toHaveValue('')
    expect(screen.queryByDisplayValue('Old organization draft')).not.toBeInTheDocument()
  })

  it.each(['resolve', 'reject'] as const)('does not leave the template list when a cancelled creation completes (%s)', async (outcome) => {
    const pending = deferred();
    vi.mocked(createApplicationTemplate).mockReturnValueOnce(pending.promise);
    const { user } = renderWithRouter(<EditorRoutes />, { initialEntries: ['/console/org/templates/applications/new'] });
    await user.type(screen.getByRole('textbox', { name: /^name/i }), 'New membership');
    await user.click(await screen.findByRole('combobox', { name: /credential template/i }));
    await user.click(await screen.findByRole('option', { name: 'Membership Badge' }));
    await user.click(screen.getByRole('button', { name: /save draft/i }));
    expect(createApplicationTemplate).toHaveBeenCalledTimes(1);
    expect(screen.getByRole('button', { name: 'Cancel' })).toBeEnabled();
    expect(screen.getByRole('button', { name: 'Back' })).toBeEnabled();
    await user.click(screen.getByRole('button', { name: 'Cancel' }));
    expect(screen.getByRole('heading', { name: 'Template list' })).toBeInTheDocument();

    await act(async () => {
      if (outcome === 'resolve') pending.resolve({ id: 'saved-draft' });
      else pending.reject(new Error('Late old editor error'));
      await pending.promise.catch(() => undefined);
    });
    expect(screen.getByRole('heading', { name: 'Template list' })).toBeInTheDocument();
    expect(screen.queryByRole('heading', { name: 'Saved template' })).not.toBeInTheDocument();
    expect(screen.queryByText('Late old editor error')).not.toBeInTheDocument();
  });

  it.each(['organization', 'principal', 'permission', 'permissions-loading', 'template'] as const)(
    'ignores a pending edit response after the %s changes', async (change) => {
      const pending = deferred();
      vi.mocked(updateApplicationTemplate).mockReturnValueOnce(pending.promise);
      const view = renderWithRouter(<EditorRoutes />, {
        initialEntries: ['/console/org/templates/applications/application-template-1/edit'],
      });
      await screen.findByDisplayValue(draftTemplate().name);
      await view.user.click(screen.getByRole('button', { name: /save draft/i }));
      expect(updateApplicationTemplate).toHaveBeenCalledTimes(1);

      if (change === 'template') {
        await view.user.click(screen.getByRole('link', { name: 'Other template' }));
        await screen.findByDisplayValue(draftTemplate('other-template').name);
      } else {
        if (change === 'organization') scope.activeOrgId = 'org-2';
        if (change === 'principal') scope.principal = 'principal-2';
        if (change === 'permission') scope.permitted = false;
        if (change === 'permissions-loading') scope.permissionsLoading = true;
        view.rerender(<EditorRoutes />);
        if (change === 'organization' || change === 'principal') {
          await screen.findByDisplayValue(draftTemplate('application-template-1', scope.activeOrgId).name);
        } else if (change === 'permission') {
          expect(screen.getByRole('alert')).toHaveTextContent(/do not have permission/i);
        } else {
          expect(screen.getByRole('progressbar')).toBeInTheDocument();
        }
      }

      await act(async () => {
        if (change === 'permission') pending.reject(new Error('Late old permission error'));
        else pending.resolve({ id: 'application-template-1' });
        await pending.promise.catch(() => undefined);
      });
      expect(screen.queryByRole('heading', { name: 'Saved template' })).not.toBeInTheDocument();
      expect(screen.queryByText('Late old permission error')).not.toBeInTheDocument();
      if (change === 'template') expect(screen.getByDisplayValue(draftTemplate('other-template').name)).toBeInTheDocument();
      if (change === 'organization' || change === 'principal') {
        expect(screen.getByDisplayValue(draftTemplate('application-template-1', scope.activeOrgId).name)).toBeInTheDocument();
        expect(screen.getByRole('button', { name: /save draft/i })).toBeEnabled();
      }
    },
  );

  it('freezes the submitted values and rejects duplicate saves before and after loading renders', async () => {
    const pending = deferred();
    vi.mocked(updateApplicationTemplate).mockReturnValueOnce(pending.promise);
    const { user } = renderWithRouter(<EditorRoutes />, {
      initialEntries: ['/console/org/templates/applications/application-template-1/edit'],
    });
    const name = await screen.findByRole('textbox', { name: /^name/i });
    const save = screen.getByRole('button', { name: /save draft/i });
    const addField = screen.getByRole('button', { name: 'Add field' });
    act(() => {
      fireEvent.click(save);
      expect(save).toBeEnabled();
      fireEvent.change(name, { target: { value: 'Late unsaved title' } });
      fireEvent.click(addField);
      fireEvent.click(save);
    });

    expect(updateApplicationTemplate).toHaveBeenCalledTimes(1);
    expect(name).toBeDisabled();
    expect(name).toHaveValue(draftTemplate().name);
    expect(addField).toBeDisabled();
    expect(save).toBeDisabled();
    await user.click(screen.getByRole('combobox', { name: /credential template/i }));
    expect(screen.queryByRole('listbox')).not.toBeInTheDocument();
    fireEvent.click(save);
    expect(updateApplicationTemplate).toHaveBeenCalledTimes(1);
    expect(updateApplicationTemplate).toHaveBeenCalledWith('application-template-1', expect.objectContaining({
      name: draftTemplate().name,
      form_fields: draftTemplate().form_fields,
    }));

    await act(async () => { pending.resolve({ id: 'application-template-1' }); await pending.promise; });
    expect(screen.getByRole('heading', { name: 'Saved template' })).toBeInTheDocument();
  });

  it('unlocks the current editor after a failed save so it can be corrected and retried', async () => {
    vi.mocked(updateApplicationTemplate).mockRejectedValueOnce(new Error('Save temporarily unavailable'));
    const { user } = renderWithRouter(<EditorRoutes />, {
      initialEntries: ['/console/org/templates/applications/application-template-1/edit'],
    });
    const name = await screen.findByRole('textbox', { name: /^name/i });
    await user.click(screen.getByRole('button', { name: /save draft/i }));
    expect(await screen.findByRole('alert')).toHaveTextContent('Save temporarily unavailable');
    expect(name).toBeEnabled();
    await user.clear(name);
    await user.type(name, 'Corrected membership');
    await user.click(screen.getByRole('button', { name: /save draft/i }));
    expect(updateApplicationTemplate).toHaveBeenCalledTimes(2);
    expect(updateApplicationTemplate).toHaveBeenLastCalledWith('application-template-1', expect.objectContaining({ name: 'Corrected membership' }));
    expect(await screen.findByRole('heading', { name: 'Saved template' })).toBeInTheDocument();
  });

  it('round trips structured and legacy select options without losing stable values', () => {
    const options = [
      'PENDING',
      { label: 'Cleared', value: 'CLEARED' },
      { label: 'Manual review', value: 'MANUAL_REVIEW' },
    ]

    const editable = formatFieldOptions(options)

    expect(editable).toBe('PENDING, Cleared=CLEARED, Manual review=MANUAL_REVIEW')
    expect(parseFieldOptions(editable)).toEqual(options)
    expect(parseFieldOptions('legacy=value=with-equals')).toEqual([
      { label: 'legacy', value: 'value=with-equals' },
    ])
  })

  it('edits and saves structured select options without collapsing typed separators', async () => {
    vi.mocked(getApplicationTemplate).mockResolvedValueOnce({
      id: 'application-template-1',
      organization_id: 'org-1',
      name: 'Pre-boarding clearance',
      description: '',
      status: 'DRAFT',
      credential_template_id: 'credential-1',
      form_fields: [{
        field_id: 'clearance_status',
        label: 'Clearance status',
        field_type: 'SELECT',
        required: true,
        options: [{ label: 'Cleared', value: 'CLEARED' }],
      }],
      evidence_requirements: [],
      required_checks: [],
      claim_collection_rules: [],
      approval_strategy: 'MANUAL',
      notification_config: {},
      ui_config: {},
    })
    vi.mocked(updateApplicationTemplate).mockResolvedValueOnce({ id: 'application-template-1' })
    const { user } = renderWithRouter(
      <Routes>
        <Route
          path="/console/org/templates/applications/:templateId/edit"
          element={<ApplicationTemplateEditorPage />}
        />
      </Routes>,
      { initialEntries: ['/console/org/templates/applications/application-template-1/edit'] },
    )

    const options = await screen.findByRole('textbox', { name: /options/i })
    expect(options).toHaveValue('Cleared=CLEARED')

    await user.clear(options)
    await user.type(options, 'Pending=PENDING, Cleared=CLEARED')
    expect(options).toHaveValue('Pending=PENDING, Cleared=CLEARED')
    await user.click(screen.getByRole('button', { name: /save draft/i }))

    await waitFor(() => {
      expect(updateApplicationTemplate).toHaveBeenCalledWith(
        'application-template-1',
        expect.objectContaining({
          form_fields: [expect.objectContaining({
            options: [
              { label: 'Pending', value: 'PENDING' },
              { label: 'Cleared', value: 'CLEARED' },
            ],
          })],
        }),
      )
    })
  })

  it('keeps editable field and claim identities stable while typing and removing earlier rows', async () => {
    const secondField = { field_id: 'department', label: 'Department', field_type: 'SELECT', options: ['SALES'] };
    const secondRule = { claim_name: 'department', source: 'FORM_FIELD', source_config: { field_id: 'department' } };
    vi.mocked(getApplicationTemplate).mockResolvedValueOnce({
      id: 'application-template-1', organization_id: 'org-1', name: 'Membership', status: 'DRAFT',
      credential_template_id: 'credential-1',
      form_fields: [{ field_id: 'member', label: 'Member', field_type: 'TEXT' }, secondField],
      claim_collection_rules: [
        { claim_name: 'member', source: 'FORM_FIELD', source_config: { field_id: 'member' } }, secondRule,
      ],
    });
    vi.mocked(updateApplicationTemplate).mockResolvedValueOnce({ id: 'application-template-1' });
    const { user } = renderWithRouter(
      <Routes><Route path="/console/org/templates/applications/:templateId/edit" element={<ApplicationTemplateEditorPage />} /></Routes>,
      { initialEntries: ['/console/org/templates/applications/application-template-1/edit?mode=advanced'] },
    );

    const firstField = (await screen.findAllByRole('textbox', { name: 'Field ID' }))[0];
    await user.clear(firstField);
    await user.type(firstField, 'membership_code');
    expect(firstField).toHaveFocus();
    expect(firstField).toHaveValue('membership_code');
    expect(screen.getAllByRole('textbox', { name: 'Field ID' })[0]).toBe(firstField);

    const firstClaim = screen.getAllByRole('textbox', { name: 'Claim name' })[0];
    await user.clear(firstClaim);
    await user.type(firstClaim, 'membership_claim');
    expect(firstClaim).toHaveFocus();
    expect(firstClaim).toHaveValue('membership_claim');

    const remainingField = screen.getAllByRole('textbox', { name: 'Field ID' })[1];
    const remainingClaim = screen.getAllByRole('textbox', { name: 'Claim name' })[1];
    const options = screen.getByRole('textbox', { name: 'Options' });
    await user.clear(options);
    await user.type(options, 'Sales=SALES,Support=SUPPORT');
    await user.click(screen.getByRole('button', { name: 'Delete Member' }));
    await user.click(screen.getByRole('button', { name: 'Delete membership_claim' }));

    expect(screen.getByRole('textbox', { name: 'Field ID' })).toBe(remainingField);
    expect(screen.getByRole('textbox', { name: 'Claim name' })).toBe(remainingClaim);
    expect(screen.getByRole('textbox', { name: 'Options' })).toBe(options);
    expect(options).toHaveValue('Sales=SALES, Support=SUPPORT');
    await user.click(screen.getByRole('button', { name: /save draft/i }));

    await waitFor(() => expect(updateApplicationTemplate).toHaveBeenCalledWith('application-template-1', expect.objectContaining({
      form_fields: [{ ...secondField, options: [{ label: 'Sales', value: 'SALES' }, { label: 'Support', value: 'SUPPORT' }] }],
      claim_collection_rules: [secondRule],
    })));
  });

  it('commits typed required-check and evidence lists when saving the draft', async () => {
    vi.mocked(getApplicationTemplate).mockResolvedValueOnce({
      id: 'application-template-1', organization_id: 'org-1', name: 'Membership', status: 'DRAFT',
      credential_template_id: 'credential-1', form_fields: [{ field_id: 'email', label: 'Email', field_type: 'EMAIL' }],
      evidence_requirements: [{ evidence_id: 'document', evidence_type: 'DOCUMENT_SCAN', description: 'Photo ID', required: true, accepted_formats: [] }],
    });
    vi.mocked(updateApplicationTemplate).mockResolvedValueOnce({ id: 'application-template-1' });
    const { user } = renderWithRouter(
      <Routes><Route path="/console/org/templates/applications/:templateId/edit" element={<ApplicationTemplateEditorPage />} /></Routes>,
      { initialEntries: ['/console/org/templates/applications/application-template-1/edit?mode=advanced'] },
    );

    const formats = await screen.findByRole('textbox', { name: 'Accepted formats' });
    await user.type(formats, 'image/png,image/jpeg');
    expect(formats).toHaveValue('image/png,image/jpeg');
    const checks = screen.getByRole('textbox', { name: 'Required checks' });
    await user.type(checks, 'identity_verification,employment_verification');
    expect(checks).toHaveValue('identity_verification,employment_verification');
    await user.click(screen.getByRole('button', { name: /save draft/i }));

    await waitFor(() => expect(updateApplicationTemplate).toHaveBeenCalledWith('application-template-1', expect.objectContaining({
      evidence_requirements: [{ evidence_id: 'document', evidence_type: 'DOCUMENT_SCAN', description: 'Photo ID', required: true, accepted_formats: ['image/png', 'image/jpeg'] }],
      required_checks: [
        { check_type: 'identity_verification', is_required: true, order: 1 },
        { check_type: 'employment_verification', is_required: true, order: 2 },
      ],
    })));
  });

  it('names select controls and derives form fields from the active credential template', async () => {
    const { user } = render(<ApplicationTemplateEditorPage />)

    const credentialTemplate = await screen.findByRole('combobox', {
      name: /credential template/i,
    })
    expect(screen.getByRole('combobox', { name: /approval/i })).toBeInTheDocument()

    await user.click(credentialTemplate)
    await user.click(await screen.findByRole('option', { name: 'Membership Badge' }))

    await waitFor(() => {
      expect(screen.getByRole('textbox', { name: /field id/i })).toHaveValue('member_id')
      expect(screen.getByRole('textbox', { name: /^label/i })).toHaveValue('Member ID')
      expect(screen.getByRole('combobox', { name: /^type/i })).toHaveTextContent('TEXT')
    })
  })

  it.each([true, false])('saves evidence selectors and removes an unused date format (date=%s)', async (date) => {
    vi.mocked(getApplicationTemplate).mockResolvedValueOnce({
      id: 'application-template-1', name: 'Canvas achievement', status: 'DRAFT',
      organization_id: 'org-1',
      credential_template_id: 'credential-1',
      form_fields: [{ field_id: 'email', label: 'Email', field_type: 'EMAIL' }],
      evidence_requirements: [], required_checks: [], approval_strategy: 'MANUAL',
      claim_collection_rules: [{ claim_name: 'member_id', source: 'EVIDENCE_EXTRACTION',
        source_config: { requirement_id: 'old-requirement', json_pointer: '/effective_at', format: 'date' } }],
      notification_config: {}, ui_config: {},
    })
    vi.mocked(updateApplicationTemplate).mockResolvedValueOnce({ id: 'application-template-1' })
    const { user } = renderWithRouter(
      <Routes><Route path="/console/org/templates/applications/:templateId/edit" element={<ApplicationTemplateEditorPage />} /></Routes>,
      { initialEntries: ['/console/org/templates/applications/application-template-1/edit?mode=advanced'] },
    )
    const requirement = await screen.findByRole('textbox', { name: 'Evidence requirement ID' })
    await user.clear(requirement)
    await user.type(screen.getByRole('textbox', { name: 'Evidence fact type' }), 'canvas.quiz_score')
    const path = screen.getByRole('textbox', { name: 'Evidence value path' })
    await user.clear(path)
    await user.type(path, date ? '/effective_at' : '/assertion/score')
    if (!date) {
      await user.click(screen.getByRole('combobox', { name: 'Evidence format' }))
      await user.click(await screen.findByRole('option', { name: 'Original value' }))
    }
    await user.click(screen.getByRole('button', { name: /save draft/i }))
    await waitFor(() => expect(updateApplicationTemplate).toHaveBeenCalledWith(
      'application-template-1', expect.objectContaining({ claim_collection_rules: [{
        claim_name: 'member_id', source: 'EVIDENCE_EXTRACTION', source_config: {
          fact_type: 'canvas.quiz_score', json_pointer: date ? '/effective_at' : '/assertion/score',
          ...(date ? { format: 'date' } : {}),
        },
      }] }),
    ))
  })
})

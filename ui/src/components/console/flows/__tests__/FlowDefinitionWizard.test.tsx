import { beforeEach, describe, expect, it, vi } from 'vitest';
import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';

import { render } from '@test/utils';
import { server } from '@test/mocks/server';
import { mockDeploymentProfiles, mockTemplates } from '@test/mocks/fixtures';
import FlowDefinitionWizard, { buildFlowPayload } from '../FlowDefinitionWizard';

const mockNavigate = vi.fn();
const route = vi.hoisted(() => ({ search: '' }));
vi.mock('react-router', async () => {
  const actual = await vi.importActual('react-router');
  return { ...actual, useNavigate: () => mockNavigate, useSearchParams: () => [new URLSearchParams(route.search)] };
});

vi.mock('../../../../contexts/ConsoleContext', () => ({
  useConsole: () => ({ activeOrgId: 'org-1' }),
}));

describe('FlowDefinitionWizard', () => {
  beforeEach(() => {
    vi.clearAllMocks(); route.search = '';
    server.use(
      http.get('*/v1/organizations/:organizationId/defaults', () => HttpResponse.json({})),
      http.get('*/v1/deployment-profiles', () => HttpResponse.json([
        { ...mockDeploymentProfiles.valid, organization_id: 'org-1' },
      ])),
      http.get('*/v1/credential-templates', () => HttpResponse.json([
        { ...mockTemplates.valid, organization_id: 'org-1', trust_profile_id: 'trust-1',
          issuance_protocol: 'OID4VCI_PRE_AUTH', credential_payload_format: 'SD_JWT_VC' },
      ])),
    );
  });

  it('carries a validated template link into standard-flow dependencies', async () => {
    route.search = 'templateId=linked-template';
    const linked = { id: 'linked-template', organization_id: 'org-1', name: 'Linked template', status: 'ACTIVE', issuance_protocol: 'OID4VCI_PRE_AUTH', trust_profile_id: 'trust-1', claims: [] };
    server.use(
      http.get('*/v1/credential-templates/linked-template', () => HttpResponse.json(linked)),
      http.get('*/v1/credential-templates', () => HttpResponse.json([linked])),
    );
    const user = userEvent.setup();
    render(<FlowDefinitionWizard />);
    await waitFor(() => expect(screen.getByTestId('wizard.flow.next')).toBeEnabled());
    await user.click(screen.getByTestId('wizard.flow.next'));
    await user.type(await screen.findByLabelText(/Flow name/i), 'Linked flow');
    await user.click(screen.getByTestId('wizard.flow.next'));
    await waitFor(() => expect(screen.getByRole('combobox', { name: /credential template/i })).toHaveTextContent('Linked template'));
  });

  it('rejects a foreign template link before setting flow dependencies', async () => {
    route.search = 'templateId=foreign-template';
    server.use(http.get('*/v1/credential-templates/foreign-template', () => HttpResponse.json({
      id: 'foreign-template', organization_id: 'org-other', status: 'ACTIVE', issuance_protocol: 'OID4VCI_PRE_AUTH', trust_profile_id: 'trust-other',
    })));
    render(<FlowDefinitionWizard />);
    expect(await screen.findByText(/linked template is unavailable or incompatible/i)).toBeInTheDocument();
    expect(screen.getByTestId('wizard.flow.next')).toBeDisabled();
  });

  it('shows the draft-first standard workflow', async () => {
    render(<FlowDefinitionWizard />);
    expect(await screen.findByText('Choose a flow')).toBeInTheDocument();
    expect(screen.getByText('Flow type')).toBeInTheDocument();
    expect(screen.getByText('Definition')).toBeInTheDocument();
    expect(screen.getByText('Dependencies')).toBeInTheDocument();
    expect(screen.getByText('Review')).toBeInTheDocument();
  });

  it('keeps physical issuance visible with its capability blocker', async () => {
    render(<FlowDefinitionWizard />);
    const physical = await screen.findByTestId('flow-type-physical_document_issuance');
    expect(physical).toBeDisabled();
    expect(screen.getByText(/signer and production connector/i)).toBeInTheDocument();
  });

  it('opens the separate custom extension builder', async () => {
    const user = userEvent.setup();
    render(<FlowDefinitionWizard />);
    await user.click(await screen.findByRole('button', { name: /custom extension/i }));
    expect(mockNavigate).toHaveBeenCalledWith('/console/org/flows/definitions/new/custom');
  });

  it('renders a fixed standard sequence without graph controls', async () => {
    const user = userEvent.setup();
    render(<FlowDefinitionWizard />);
    await user.click(await screen.findByTestId('flow-type-oid4vci_pre_authorized'));
    await user.click(screen.getByTestId('wizard.flow.next'));
    expect(await screen.findByText('Create Offer')).toBeInTheDocument();
    expect(screen.getByText('Issue Credential')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /add step/i })).not.toBeInTheDocument();
  });

  it('submits only the MIP 0.4 standard-flow contract and creates a draft', async () => {
    const user = userEvent.setup();
    let submittedPayload: any;
    server.use(
      http.post('http://localhost:8000/v1/flows/definitions', async ({ request }) => {
        submittedPayload = await request.json();
        return HttpResponse.json({
          ...submittedPayload,
          id: 'flow-created',
          status: 'DRAFT',
          resolved_steps: ['create_offer', 'token_exchange', 'credential_request', 'issue_credential'],
        }, { status: 201 });
      }),
    );

    render(<FlowDefinitionWizard />);
    await user.click(await screen.findByTestId('flow-type-oid4vci_pre_authorized'));
    await user.click(screen.getByTestId('wizard.flow.next'));
    await user.type(await screen.findByLabelText(/Flow name/i), 'Employee credential');
    expect(screen.getByRole('combobox', { name: /approval/i })).toBeInTheDocument();
    expect(screen.getByRole('combobox', { name: /trigger/i })).toBeInTheDocument();
    await user.click(screen.getByTestId('wizard.flow.next'));
    await waitFor(() => expect(screen.getByTestId('wizard.flow.next')).not.toBeDisabled());
    expect(screen.getByRole('combobox', { name: /credential template/i })).toBeInTheDocument();
    expect(screen.getByRole('combobox', { name: /deployment profile/i })).toBeInTheDocument();
    await user.click(screen.getByTestId('wizard.flow.next'));
    expect(await screen.findByText('Review draft')).toBeInTheDocument();
    await user.click(screen.getByTestId('wizard.flow.submit'));

    await waitFor(() => expect(screen.getByText(/Draft created/i)).toBeInTheDocument());
    expect(submittedPayload).toMatchObject({
      organization_id: 'org-1',
      name: 'Employee credential',
      flow_type: 'oid4vci_pre_authorized',
      approval_strategy: 'AUTO',
      credential_template_id: 1,
      deployment_profile_ids: [1],
      trigger: { trigger_type: 'API_CALL', config: {} },
    });
    expect(submittedPayload).not.toHaveProperty('steps');
    expect(submittedPayload).not.toHaveProperty('transitions');
    expect(submittedPayload).not.toHaveProperty('preconditions');
    expect(submittedPayload).not.toHaveProperty('enabled');
    expect(submittedPayload).not.toHaveProperty('deployment_profile_id');
    expect(submittedPayload).not.toHaveProperty('_organization_default_bindings');
  });

  it.each([
    ['reselects the current type', 'application_approval_issuance', false],
    ['selects a different type', 'oid4vci_pre_authorized', true],
  ])('preserves or resets the authored draft intentionally when returning to flow type and the user %s', async (_label, nextType, resets) => {
    const writes: Array<Record<string, unknown>> = [];
    const sequence = ['accept_application', 'validate_evidence', 'approval_decision', 'issue_credential', 'deliver_credential'];
    server.use(
      http.get('*/v1/flows/capabilities', () => HttpResponse.json({
        sequences: {
          application_approval_issuance: sequence,
          oid4vci_pre_authorized: ['create_offer', 'token_exchange', 'credential_request', 'issue_credential'],
        },
        extensible_steps: { application_approval_issuance: ['approval_decision', 'deliver_credential'] },
      })),
      http.get('*/v1/application-templates', () => HttpResponse.json([
        { id: 'application-first', name: 'First application', organization_id: 'org-1', status: 'ACTIVE' },
        { id: 'application-chosen', name: 'Chosen application', organization_id: 'org-1', status: 'ACTIVE' },
      ])),
      http.get('*/v1/deployment-profiles', () => HttpResponse.json([
        { id: 'deployment-first', name: 'First deployment', organization_id: 'org-1', status: 'ACTIVE', trust_profile_id: 'trust-1' },
        { id: 'deployment-chosen', name: 'Chosen deployment', organization_id: 'org-1', status: 'ACTIVE', trust_profile_id: 'trust-1' },
      ])),
      http.get('*/v1/credential-templates', () => HttpResponse.json([
        { ...mockTemplates.valid, id: 'credential-new', organization_id: 'org-1', trust_profile_id: 'trust-1',
          issuance_protocol: 'OID4VCI_PRE_AUTH', credential_payload_format: 'SD_JWT_VC' },
      ])),
      http.post('*/v1/flows/definitions', async ({ request }) => {
        const payload = await request.json() as Record<string, unknown>;
        writes.push(payload);
        return HttpResponse.json({ ...payload, id: 'flow-created', status: 'DRAFT', resolved_steps: sequence }, { status: 201 });
      }),
    );

    const { user } = render(<FlowDefinitionWizard />);
    await user.click(await screen.findByTestId('flow-type-application_approval_issuance'));
    await user.click(screen.getByTestId('wizard.flow.next'));
    await user.type(await screen.findByLabelText(/Flow name/i), 'Reviewed application flow');
    await user.type(screen.getByLabelText('Description'), 'Retain the authored settings');
    await user.click(screen.getByRole('combobox', { name: 'Approval' }));
    await user.click(screen.getByRole('option', { name: 'Manual' }));
    await user.click(screen.getByRole('combobox', { name: 'Trigger' }));
    await user.click(screen.getByRole('option', { name: 'Application submitted' }));
    await user.type(screen.getByLabelText('After Approval Decision'), 'https://hooks.example.test/approval');
    await user.click(screen.getByTestId('wizard.flow.next'));
    await user.click(await screen.findByRole('combobox', { name: /Application template/i }));
    await user.click(screen.getByRole('option', { name: 'Chosen application' }));
    await user.click(screen.getByRole('combobox', { name: 'Deployment profile' }));
    await user.click(screen.getByRole('option', { name: 'Chosen deployment' }));
    await user.click(screen.getByTestId('wizard.flow.next'));
    expect(await screen.findByRole('heading', { name: 'Review draft' })).toBeInTheDocument();

    for (let step = 0; step < 3; step += 1) await user.click(screen.getByTestId('wizard.flow.back'));
    await user.click(screen.getByTestId(`flow-type-${nextType}`));
    await user.click(screen.getByTestId('wizard.flow.next'));

    expect(screen.getByLabelText(/Flow name/i)).toHaveValue(resets ? '' : 'Reviewed application flow');
    expect(screen.getByLabelText('Description')).toHaveValue(resets ? '' : 'Retain the authored settings');
    expect(screen.getByRole('combobox', { name: 'Approval' })).toHaveTextContent(resets ? 'Automatic' : 'Manual');
    expect(screen.getByRole('combobox', { name: 'Trigger' })).toHaveTextContent(resets ? 'API call' : 'Application submitted');
    if (resets) {
      expect(screen.queryByLabelText('After Approval Decision')).not.toBeInTheDocument();
      await user.type(screen.getByLabelText(/Flow name/i), 'New wallet flow');
    } else {
      expect(screen.getByLabelText('After Approval Decision')).toHaveValue('https://hooks.example.test/approval');
    }
    await user.click(screen.getByTestId('wizard.flow.next'));
    const deployment = await screen.findByRole('combobox', { name: 'Deployment profile' });
    if (resets) {
      expect(screen.queryByRole('combobox', { name: /Application template/i })).not.toBeInTheDocument();
      expect(deployment).not.toHaveTextContent('Chosen deployment');
    } else {
      expect(screen.getByRole('combobox', { name: /Application template/i })).toHaveTextContent('Chosen application');
      expect(deployment).toHaveTextContent('Chosen deployment');
    }
    await waitFor(() => expect(screen.getByTestId('wizard.flow.next')).toBeEnabled());
    await user.click(screen.getByTestId('wizard.flow.next'));
    await user.click(await screen.findByTestId('wizard.flow.submit'));
    await waitFor(() => expect(writes).toHaveLength(1));
    expect(writes[0]).toEqual({
      organization_id: 'org-1',
      name: resets ? 'New wallet flow' : 'Reviewed application flow',
      description: resets ? null : 'Retain the authored settings',
      flow_type: nextType,
      approval_strategy: resets ? 'AUTO' : 'MANUAL',
      hooks: resets ? {} : { post_approval_decision: [{ hook_type: 'WEBHOOK', url: 'https://hooks.example.test/approval', config: {} }] },
      trigger: { trigger_type: resets ? 'API_CALL' : 'APPLICATION_SUBMITTED', config: {} },
      trust_profile_id: resets ? null : 'trust-1',
      credential_template_id: resets ? 'credential-new' : null,
      application_template_id: resets ? null : 'application-chosen',
      presentation_policy_id: null,
      delivery_destination_profile_id: null,
      deployment_profile_ids: resets ? [] : ['deployment-chosen'],
    });
  });

  it('buildFlowPayload binds both references for physical issuance', () => {
    const payload = buildFlowPayload({
      ...{
        approvalStrategy: 'MANUAL', description: '', hooks: {}, name: 'Passport',
        selectedDeployment: null, triggerType: 'API_CALL', trustProfileId: null,
      },
      flowType: 'physical_document_issuance',
      credentialTemplateId: 'credential-1',
      applicationTemplateId: 'application-1',
      deliveryDestinationProfileId: 'bureau-1',
      defaultPolicyId: null,
    }, 'org-1');

    expect(payload).toMatchObject({
      credential_template_id: 'credential-1',
      application_template_id: 'application-1',
      delivery_destination_profile_id: 'bureau-1',
    });
  });

  it('surfaces create errors without showing success', async () => {
    const user = userEvent.setup();
    server.use(http.post('http://localhost:8000/v1/flows/definitions', () => HttpResponse.json(
      { error: 'validation_error', error_description: 'credential_template_id is required' },
      { status: 400 },
    )));
    render(<FlowDefinitionWizard />);
    await user.click(await screen.findByTestId('flow-type-oid4vci_pre_authorized'));
    await user.click(screen.getByTestId('wizard.flow.next'));
    await user.type(await screen.findByLabelText(/Flow name/i), 'Broken flow');
    await user.click(screen.getByTestId('wizard.flow.next'));
    await waitFor(() => expect(screen.getByTestId('wizard.flow.next')).not.toBeDisabled());
    await user.click(screen.getByTestId('wizard.flow.next'));
    await user.click(await screen.findByTestId('wizard.flow.submit'));
    expect(await screen.findByText(/credential_template_id is required/i)).toBeInTheDocument();
    expect(screen.queryByText(/Draft created/i)).not.toBeInTheDocument();
  });
});

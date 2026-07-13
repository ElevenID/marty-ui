import { beforeEach, describe, expect, it, vi } from 'vitest';
import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';

import { render } from '@test/utils';
import { server } from '@test/mocks/server';
import FlowDefinitionWizard, { buildFlowPayload } from '../FlowDefinitionWizard';

const mockNavigate = vi.fn();
vi.mock('react-router-dom', async () => {
  const actual = await vi.importActual('react-router-dom');
  return { ...actual, useNavigate: () => mockNavigate };
});

vi.mock('../../../../contexts/ConsoleContext', () => ({
  useConsole: () => ({ activeOrgId: 'org-1' }),
}));

describe('FlowDefinitionWizard', () => {
  beforeEach(() => vi.clearAllMocks());

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

  it('submits only the MIP 0.3 standard-flow contract and creates a draft', async () => {
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

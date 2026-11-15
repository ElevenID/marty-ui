import { describe, expect, it } from 'vitest';
import { screen, within } from '@testing-library/react';
import { render } from '@test/utils';
import { computeSetupReadiness, ReadinessState } from '../../../config/dashboardRules';
import { OrganizationHealthPanel } from './OrganizationHealthPanel';

const metricLabels = ['Active Trust Profiles', 'Active Templates', 'Active Policies', 'Active Deployments', 'Active Flows'];

function expectCount(label: string, count: number) {
  const card = screen.getByText(label).closest('.MuiCard-root');
  expect(card).not.toBeNull();
  expect(within(card as HTMLElement).getByRole('heading', { level: 4 })).toHaveTextContent(new RegExp(`^${count}$`));
}

const activeResources = {
  trustProfiles: [{ id: 'trust-1', status: 'active' }],
  templates: [{ id: 'template-1', status: 'active' }],
  policies: [{ id: 'policy-1', status: 'active', required_claims: ['given_name'] }],
  deployments: [{ id: 'deployment-1', status: 'active' }],
  flows: [{ id: 'flow-1', status: 'ACTIVE', flow_type: 'oid4vp_presentation', presentation_policy_id: 'policy-1' }],
};

describe('OrganizationHealthPanel', () => {
  it('counts the native ACTIVE definition shown ready by verification setup', () => {
    const data = { ...activeResources, templates: [], deployments: [], apiKeys: [], setupIntent: 'verify' };
    const readiness = computeSetupReadiness(data);
    expect(readiness.intents.verify.steps.flow.state).toBe(ReadinessState.READY);
    expect(readiness.intents.verify.steps.flow.message).toBe('1 active flow(s)');

    render(<OrganizationHealthPanel data={data} organizationName="Test Organization" />);

    expectCount('Active Flows', 1);
  });

  it('counts active status consistently without admitting other flow lifecycle states', () => {
    const flows = [
      { status: 'ACTIVE' },
      { status: 'active' },
      { status: ' Active ' },
      { status: 'DRAFT', enabled: true },
      { status: 'PAUSED' },
      { status: 'ARCHIVED' },
      { status: 'inactive' },
      { status: 'suspended' },
      { enabled: true },
      {},
    ];
    render(<OrganizationHealthPanel data={{ ...activeResources, flows }} organizationName="Test Organization" />);

    expectCount('Active Flows', 3);
    for (const label of metricLabels.slice(0, -1)) expectCount(label, 1);
    expect(screen.getByText('Operational', { exact: true })).toBeInTheDocument();
  });

  it.each(['DRAFT', 'PAUSED', 'ARCHIVED', 'INACTIVE', 'SUSPENDED', undefined])(
    'does not count %s as active or claim all resources are operational', (status) => {
      render(<OrganizationHealthPanel
        data={{ ...activeResources, flows: [{ status }] }}
        organizationName="Test Organization"
      />);

      expectCount('Active Flows', 0);
      expect(screen.getByText('Setup Required', { exact: true })).toBeInTheDocument();
      expect(screen.queryByText('Operational', { exact: true })).not.toBeInTheDocument();
    },
  );

  it('keeps adjacent resource counts limited to active status', () => {
    const resources = [{ status: 'active' }, { status: 'ACTIVE' }, { status: 'draft' }, { status: 'suspended' }, { status: 'archived' }];
    render(<OrganizationHealthPanel data={{
      trustProfiles: resources, templates: resources, policies: resources,
      deployments: resources, flows: resources,
    }} organizationName="Test Organization" />);

    for (const label of metricLabels) expectCount(label, 2);
  });

  it('shows zero for absent resource lists', () => {
    render(<OrganizationHealthPanel data={{}} organizationName="Test Organization" />);
    for (const label of metricLabels) expectCount(label, 0);
  });
});

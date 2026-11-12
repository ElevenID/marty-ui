import { describe, expect, it, vi } from 'vitest';
import { render, screen, within } from '@test/utils';
import ReviewStep from '../steps/ReviewStep';

function reviewData(claim = {}) {
  return {
    selectedTrustProfile: { id: 'trust-a', name: 'Employee Trust', trust_framework_type: null },
    selectedTemplate: null,
    activateImmediately: false,
    policyConfig: {
      name: 'Employee policy', description: '', purpose: 'Employee access',
      accepted_credential_types: ['urn:employee'],
      required_claims: [{ claim_name: 'role', credential_type: 'urn:employee', ...claim }],
      holder_binding: 'device_key',
      freshness_requirements: {
        require_revocation_check: true,
        max_credential_age_seconds: 86400,
        max_proof_age_seconds: 300,
      },
    },
  };
}

describe('presentation policy review', () => {
  it.each([
    [0, '0 seconds'],
    [43200, '12 hours'],
    [129600, '1 day, 12 hours'],
    ['86401', '1 day, 1 second'],
    [90061, '1 day, 1 hour, 1 minute, 1 second'],
  ])('shows every part of the %s-second age limit', (seconds, duration) => {
    const data = reviewData();
    render(<ReviewStep data={{ ...data, policyConfig: {
      ...data.policyConfig,
      freshness_requirements: { ...data.policyConfig.freshness_requirements, max_credential_age_seconds: seconds },
    } }} onEdit={vi.fn()} onToggleActivation={vi.fn()} />);
    expect(screen.getByText(duration)).toBeInTheDocument();
  });

  it('does not promise unsupported settings from an older draft will be saved', () => {
    const data = reviewData();
    render(<ReviewStep data={{ ...data, policyConfig: {
      ...data.policyConfig,
      single_presentation: true,
      metadata: { standard_reference: 'An unsaved standard' },
    } }} onEdit={vi.fn()} onToggleActivation={vi.fn()} />);
    expect(screen.getByText('1 day')).toBeInTheDocument();
    expect(screen.getByText('Required')).toBeInTheDocument();
    expect(screen.queryByText('Max Proof Age')).not.toBeInTheDocument();
    expect(screen.queryByText('Compliance Standard')).not.toBeInTheDocument();
    expect(screen.queryByText('An unsaved standard')).not.toBeInTheDocument();
    expect(screen.queryByText('Single Presentation')).not.toBeInTheDocument();
  });

  it.each([
    ['native zero overrides the legacy value', { value_constraint: 0, required_value: 'legacy' }, '0'],
    ['native false overrides the legacy value', { value_constraint: false, required_value: 'legacy' }, 'false'],
    ['string zero is distinct from numeric zero', { value_constraint: '0' }, '"0"'],
    ['string false is distinct from Boolean false', { value_constraint: 'false' }, '"false"'],
    ['a null native value falls back to the legacy value', { value_constraint: null, required_value: 'staff' }, '"staff"'],
    ['an array is rendered as JSON', { value_constraint: ['staff', 'contractor'] }, '["staff","contractor"]'],
    ['an object is rendered as JSON', { value_constraint: { role: 'staff', active: false } }, '{"role":"staff","active":false}'],
    ['markup stays ordinary text', { required_value: '<img src=x onerror=alert(1)>' }, '"<img src=x onerror=alert(1)>"'],
  ])('shows the submitted required value when %s', (_description, claim, expected) => {
    const { container } = render(<ReviewStep data={reviewData(claim)} onEdit={vi.fn()} onToggleActivation={vi.fn()} />);
    const row = screen.getByRole('listitem');
    expect(within(row).getByText(`Required value: ${expected}`)).toBeInTheDocument();
    expect(row).toHaveTextContent('From: urn:employee');
    expect(container.querySelector('img')).not.toBeInTheDocument();
  });

  it('preserves leading, trailing, and repeated spaces in an exact string value', () => {
    render(<ReviewStep data={reviewData({ required_value: '  senior  staff  ' })} onEdit={vi.fn()} onToggleActivation={vi.fn()} />);
    const value = within(screen.getByRole('listitem')).getByText(/^Required value:/);
    expect(value.textContent).toBe('Required value: "  senior  staff  "');
    expect(getComputedStyle(value).whiteSpace).toBe('pre-wrap');
    expect(getComputedStyle(value).overflowWrap).toBe('anywhere');
  });

  it.each([
    ['no value', {}],
    ['a null value', { required_value: null }],
    ['an empty native value that suppresses the legacy value', { value_constraint: '', required_value: 'legacy' }],
  ])('does not claim an equality requirement for %s', (_description, claim) => {
    render(<ReviewStep data={reviewData(claim)} onEdit={vi.fn()} onToggleActivation={vi.fn()} />);
    expect(screen.getByRole('listitem')).not.toHaveTextContent('Required value:');
  });
});

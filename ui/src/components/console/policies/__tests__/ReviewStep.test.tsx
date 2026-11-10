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

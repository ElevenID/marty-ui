import { useState } from 'react';
import { describe, expect, it, vi } from 'vitest';
import { render, screen, within } from '@test/utils';
import ClaimsStep from '../steps/ClaimsStep';

function ClaimsEditor({ credentialType = 'VerifiableCredential' } = {}) {
  const [data, setData] = useState({ credential_type: credentialType, claims: [] });
  return <ClaimsStep data={data} onChange={(updates: object) => setData((current) => ({ ...current, ...updates }))} />;
}

describe('credential claim preset isolation', () => {
  it('restores preset defaults after changing a claim and selecting another preset', async () => {
    const { user, unmount } = render(<ClaimsEditor />);
    await user.click(screen.getByRole('button', { name: /identity/i }));
    const required = within(screen.getByText('given_name').closest('li')!).getByRole('checkbox');
    expect(required).toBeChecked();
    await user.click(required);
    expect(required).not.toBeChecked();
    await user.click(screen.getByRole('button', { name: /employee/i }));
    await user.click(screen.getByRole('button', { name: /identity/i }));
    expect(within(screen.getByText('given_name').closest('li')!).getByRole('checkbox')).toBeChecked();
    unmount();

    const nextWizard = render(<ClaimsEditor />);
    await nextWizard.user.click(screen.getByRole('button', { name: /identity/i }));
    expect(within(screen.getByText('given_name').closest('li')!).getByRole('checkbox')).toBeChecked();
  });

  it('proposes a changed claim without mutating the current parent data', async () => {
    const claim = Object.freeze({ name: 'employee_id', type: 'string', required: true });
    const claims = Object.freeze([claim]);
    const change = vi.fn();
    const { user } = render(<ClaimsStep data={{ claims }} onChange={change} />);
    await user.click(within(screen.getByText('employee_id').closest('li')!).getByRole('checkbox'));
    expect(change).toHaveBeenCalledWith({ claims: [{ ...claim, required: false }] });
    expect(claim.required).toBe(true);
    expect(change.mock.calls[0][0].claims[0]).not.toBe(claim);
  });

  it('starts an Open Badge with object criteria and explains the issuer-owned mapping', async () => {
    const { user } = render(<ClaimsEditor credentialType="OpenBadgeCredential" />);
    expect(screen.getByText(/Add achievement_criteria as an Object claim/)).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Open Badges achievement' }));
    expect(screen.queryByText(/Add achievement_criteria as an Object claim/)).not.toBeInTheDocument();
    expect(screen.getByText(/map achievement details and criteria from issuer configuration or verified evidence/)).toBeInTheDocument();
    const criteria = within(screen.getByText('achievement_criteria').closest('li')!);
    expect(criteria.getByText('object')).toBeInTheDocument();
    expect(criteria.getByRole('checkbox', { name: 'Require achievement_criteria' })).toBeChecked();
    await user.click(screen.getByRole('button', { name: 'Move achievement_criteria up' }));
    expect(screen.getAllByRole('listitem').map((item) => item.textContent)).toEqual([
      expect.stringContaining('achievement_name'), expect.stringContaining('achievement_criteria'), expect.stringContaining('achievement_description'),
    ]);
    await user.click(screen.getByRole('button', { name: 'Remove achievement_criteria' }));
    expect(screen.getByText(/Add achievement_criteria as an Object claim/)).toBeInTheDocument();
  });

  it('explains a duplicate claim instead of leaving an enabled Add button with no effect', async () => {
    const { user } = render(<ClaimsEditor />);
    await user.click(screen.getByRole('button', { name: /identity/i }));
    await user.type(screen.getByRole('textbox', { name: 'Claim Name' }), 'given_name');
    expect(screen.getByRole('textbox', { name: 'Claim Name' })).toHaveAttribute('aria-invalid', 'true');
    expect(screen.getByText('A claim with this name already exists.')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Add', exact: true })).toBeDisabled();
    await user.clear(screen.getByRole('textbox', { name: 'Claim Name' }));
    await user.type(screen.getByRole('textbox', { name: 'Claim Name' }), 'preferred_name');
    expect(screen.getByRole('button', { name: 'Add', exact: true })).toBeEnabled();
    await user.click(screen.getByRole('button', { name: 'Add', exact: true }));
    expect(screen.getByText('preferred_name')).toBeInTheDocument();
  });
});

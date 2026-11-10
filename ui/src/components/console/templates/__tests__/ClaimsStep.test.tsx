import { useState } from 'react';
import { describe, expect, it, vi } from 'vitest';
import { render, screen, within } from '@test/utils';
import ClaimsStep from '../steps/ClaimsStep';

function ClaimsEditor() {
  const [data, setData] = useState({ claims: [] });
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
});

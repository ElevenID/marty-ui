import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';

import ApplicationEvidenceEditor, { newEvidenceRequirement } from './ApplicationEvidenceEditor';

describe('ApplicationEvidenceEditor', () => {
  it('creates canonical evidence requirements', async () => {
    const user = userEvent.setup();
    const onChange = vi.fn();
    render(<ApplicationEvidenceEditor requirements={[]} onChange={onChange} />);

    await user.click(screen.getByRole('button', { name: /add evidence/i }));

    expect(onChange).toHaveBeenCalledWith([
      {
        evidence_id: 'evidence_1',
        evidence_type: 'DOCUMENT_SCAN',
        description: '',
        required: true,
        accepted_formats: [],
      },
    ]);
  });

  it('updates only the canonical auto-issue field', async () => {
    const user = userEvent.setup();
    const requirement = {
      ...newEvidenceRequirement(1),
      evidence_type: 'EXTERNAL_FACT',
      provider: 'membership_registry',
      fact_type: 'membership.active',
    };
    const onChange = vi.fn();
    render(<ApplicationEvidenceEditor requirements={[requirement]} onChange={onChange} />);

    await user.click(screen.getByRole('checkbox', { name: /issue automatically/i }));

    const updated = onChange.mock.calls.at(-1)[0][0];
    expect(updated.auto_issue_on_permit).toBe(true);
    expect(updated).not.toHaveProperty('auto_approve_on_evidence');
  });
});

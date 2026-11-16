import { render, screen } from '@testing-library/react';
import { useState } from 'react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';

import ApplicationEvidenceEditor, { newEvidenceRequirement } from './ApplicationEvidenceEditor';

function ControlledEvidence({ initial, onChange = () => {} }) {
  const [requirements, setRequirements] = useState(initial);
  return <ApplicationEvidenceEditor requirements={requirements} onChange={(next) => {
    setRequirements(next);
    onChange(next);
  }} />;
}

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

  it('keeps identifier focus and the remaining list draft when an earlier row is removed', async () => {
    const user = userEvent.setup();
    const onChange = vi.fn();
    render(<ControlledEvidence initial={[newEvidenceRequirement(1), newEvidenceRequirement(2)]} onChange={onChange} />);

    const firstId = screen.getAllByRole('textbox', { name: 'Evidence ID' })[0];
    await user.clear(firstId);
    await user.type(firstId, 'identity_document');
    expect(firstId).toHaveFocus();
    expect(firstId).toHaveValue('identity_document');
    expect(screen.getAllByRole('textbox', { name: 'Evidence ID' })[0]).toBe(firstId);

    const remainingId = screen.getAllByRole('textbox', { name: 'Evidence ID' })[1];
    const formats = screen.getAllByRole('textbox', { name: 'Accepted formats' })[1];
    await user.type(formats, 'image/png,image/jpeg');
    expect(formats).toHaveValue('image/png,image/jpeg');
    await user.click(screen.getByRole('button', { name: 'Delete identity_document' }));

    expect(screen.getByRole('textbox', { name: 'Evidence ID' })).toBe(remainingId);
    expect(screen.getByRole('textbox', { name: 'Accepted formats' })).toBe(formats);
    expect(formats).toHaveValue('image/png, image/jpeg');
    expect(onChange.mock.calls.at(-1)[0]).toEqual([
      { ...newEvidenceRequirement(2), accepted_formats: ['image/png', 'image/jpeg'] },
    ]);
  });

  it('does not duplicate generated evidence IDs after deleting and adding a row', async () => {
    const user = userEvent.setup();
    const onChange = vi.fn();
    render(<ControlledEvidence initial={[newEvidenceRequirement(1), newEvidenceRequirement(2)]} onChange={onChange} />);

    await user.click(screen.getByRole('button', { name: 'Delete evidence_1' }));
    await user.click(screen.getByRole('button', { name: 'Add evidence' }));

    expect(onChange.mock.calls.at(-1)[0]).toEqual([newEvidenceRequirement(2), newEvidenceRequirement(1)]);
  });

  it('preserves typed status-code separators and verification values until blur', async () => {
    const user = userEvent.setup();
    const onChange = vi.fn();
    const requirement = { ...newEvidenceRequirement(1), evidence_type: 'EXTERNAL_API' };
    render(<ControlledEvidence initial={[requirement]} onChange={onChange} />);

    const codes = screen.getByRole('textbox', { name: 'Accepted status codes' });
    await user.clear(codes);
    await user.type(codes, '200,201');
    expect(codes).toHaveValue('200,201');
    expect(codes).toHaveFocus();
    expect(onChange).not.toHaveBeenCalled();

    const values = screen.getByRole('textbox', { name: 'Verified values' });
    await user.click(values);
    await user.type(values, 'verified,approved');
    expect(values).toHaveValue('verified,approved');
    await user.tab();

    expect(codes).toHaveValue('200, 201');
    expect(values).toHaveValue('verified, approved');
    expect(onChange.mock.calls.at(-1)[0]).toEqual([{
      ...requirement,
      expected_response: { status_codes: [200, 201] },
      response_mapping: { verification_verified_values: ['verified', 'approved'] },
    }]);
  });
});

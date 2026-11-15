import { useState } from 'react';
import { describe, expect, it, vi } from 'vitest';
import { render, screen } from '@test/utils';

import { DynamicFieldRenderer } from '../applicant/DynamicFieldRenderer';

describe('DynamicFieldRenderer numeric values', () => {
  it.each(['number', 'integer'])('preserves zero when a %s field is cleared and edited', async (type) => {
    const onChange = vi.fn();
    function Form() {
      const [value, setValue] = useState<number | string>(0);
      return <DynamicFieldRenderer
        field={{ name: 'count', label: 'Count', type }}
        value={value}
        onChange={(name: string, next: number | string) => { onChange(name, next); setValue(next); }}
        error={undefined}
        required={false}
        validation={{ minimum: 0, maximum: 10 }}
        fileInputRef={undefined}
      />;
    }
    const { user } = render(<Form />);
    const input = screen.getByRole('spinbutton', { name: 'Count' });
    expect(input).toHaveValue(0);
    expect(input).toHaveAttribute('min', '0');
    expect(input).toHaveAttribute('max', '10');
    await user.clear(input);
    expect(input).toHaveValue(null);
    expect(onChange).toHaveBeenLastCalledWith('count', '');
    await user.type(input, '0');
    expect(input).toHaveValue(0);
    expect(onChange).toHaveBeenLastCalledWith('count', 0);
  });

  it.each([undefined, null, ''])('keeps an absent numeric value empty: %s', (value) => {
    render(<DynamicFieldRenderer
      field={{ name: 'count', label: 'Count', type: 'number' }} value={value} onChange={vi.fn()}
      error={undefined} required={false} validation={undefined} fileInputRef={undefined}
    />);
    expect(screen.getByRole('spinbutton', { name: 'Count' })).toHaveValue(null);
  });
});

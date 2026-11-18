// Diagnostic baseline: imports no product component or modified hook.
import { it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import Dialog from '@mui/material/Dialog';

it.each([1, 2])('restores focus when bare MUI dialog %s unmounts', async () => {
  const events: unknown[] = [];
  const observe = (event: FocusEvent) => events.push({
    target: (event.target as Element)?.nodeName,
    related: (event.relatedTarget as Element)?.nodeName,
    focusType: typeof (event.relatedTarget as HTMLElement)?.focus,
  });
  document.addEventListener('focusin', observe);
  try {
    const { unmount } = render(<Dialog open><button>Baseline action</button></Dialog>);
    await screen.findByRole('button', { name: 'Baseline action' });
    expect(() => unmount()).not.toThrow();
    expect(document.activeElement).toBe(document.body);
  } finally { document.removeEventListener('focusin', observe); }
});

it('still restores focus to the actual dialog trigger', async () => {
  const trigger = document.createElement('button');
  document.body.appendChild(trigger);
  trigger.focus();
  try {
    const { unmount } = render(<Dialog open><button>Triggered dialog action</button></Dialog>);
    await screen.findByRole('button', { name: 'Triggered dialog action' });
    unmount();
    expect(document.activeElement).toBe(trigger);
  } finally { trigger.remove(); }
});

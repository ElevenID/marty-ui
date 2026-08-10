import { act, renderHook } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { useDialog } from './useDialog';

describe('useDialog', () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  it('cancels a delayed reset when the owner unmounts', () => {
    vi.useFakeTimers();
    const { result, unmount } = renderHook(() => useDialog());

    act(() => {
      result.current.open({ id: 'key-1' });
      result.current.close();
    });
    expect(vi.getTimerCount()).toBe(1);

    unmount();

    expect(vi.getTimerCount()).toBe(0);
  });

  it('does not let a stale close reset newly opened data', () => {
    vi.useFakeTimers();
    const { result } = renderHook(() => useDialog());

    act(() => {
      result.current.open({ id: 'key-1' });
      result.current.close();
      result.current.open({ id: 'key-2' });
      vi.advanceTimersByTime(150);
    });

    expect(result.current.isOpen).toBe(true);
    expect(result.current.data).toEqual({ id: 'key-2' });
    expect(vi.getTimerCount()).toBe(0);
  });
});

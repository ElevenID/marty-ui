import { act, renderHook } from '@testing-library/react';
import { afterEach, describe, expect, it } from 'vitest';
import { useBrowserEntry, useIsCurrentBrowserEntry } from './useBrowserEntry';

describe('committed browser entry ownership', () => {
  afterEach(() => window.history.replaceState(null, '', '/'));

  it('rejects suspended destinations, retains the committed entry on scope rerender, and renews on Back', () => {
    window.history.replaceState({ key: 'first' }, '', '/first');
    const location = { key: 'first', pathname: '/first', search: '', hash: '' };
    const { result, rerender, unmount } = renderHook(() => {
      const entry = useBrowserEntry(location);
      return { entry, current: useIsCurrentBrowserEntry(entry) };
    });
    expect(result.current.current()).toBe(true);
    window.history.replaceState({ key: 'next' }, '', '/next');
    rerender();
    expect(result.current.entry.href).toContain('/first');
    expect(result.current.current()).toBe(false);
    act(() => window.dispatchEvent(new PopStateEvent('popstate')));
    expect(result.current.entry.generation).toBe(0);
    window.history.replaceState({ key: 'first' }, '', '/first');
    act(() => window.dispatchEvent(new PopStateEvent('popstate')));
    expect(result.current.entry.generation).toBe(1);
    expect(result.current.current()).toBe(true);
    unmount();
  });

  it('preserves explicit route-key return matching for flow pages', () => {
    window.history.replaceState(null, '', '/first');
    const location = { key: 'default', pathname: '/first', search: '', hash: '' };
    const { result } = renderHook(() => ({
      exact: useBrowserEntry(location),
      route: useBrowserEntry(location, { matchReturnByRouteKey: true }),
    }));
    window.history.replaceState(null, '', '/other');
    act(() => window.dispatchEvent(new PopStateEvent('popstate')));
    expect(result.current.exact.generation).toBe(0);
    expect(result.current.route.generation).toBe(1);
  });
});

import { act, renderHook } from '@testing-library/react';
import { expect, it } from 'vitest';
import { useAsyncData } from '../useAsyncData';

it('clears previous organization data and ignores a late response from its catalog', async () => {
  let resolveOld!: (value: unknown) => void;
  const old = new Promise(resolve => { resolveOld = resolve; });
  const { result, rerender } = renderHook(({ org }) => useAsyncData(() => org === 'a' ? old : Promise.resolve(['tenant-b']), [org]), { initialProps: { org: 'a' } });
  rerender({ org: 'b' });
  await act(async () => { await Promise.resolve(); });
  expect(result.current.data).toEqual(['tenant-b']);
  await act(async () => { resolveOld(['tenant-a']); await old; });
  expect(result.current.data).toEqual(['tenant-b']);
  expect(result.current.loading).toBe(false);
});

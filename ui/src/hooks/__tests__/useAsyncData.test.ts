import { act, renderHook, waitFor } from '@testing-library/react';
import { expect, it, vi } from 'vitest';
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


it('dismisses a fetch error without another request and can retry successfully', async () => {
  const fetchData = vi.fn().mockRejectedValueOnce(new Error('Unavailable')).mockResolvedValue(['recovered']);
  const { result } = renderHook(() => useAsyncData(fetchData, []));
  await waitFor(() => expect(result.current.error?.message).toBe('Unavailable'));
  act(() => result.current.clearError());
  expect(result.current.error).toBeNull();
  expect(result.current.loading).toBe(false);
  expect(fetchData).toHaveBeenCalledTimes(1);
  await act(async () => { await result.current.reload(); });
  expect(result.current.data).toEqual(['recovered']);
  expect(result.current.error).toBeNull();
});

it('keeps the latest manual reload when an older request finishes last', async () => {
  let resolveOld!: (value: unknown) => void;
  const old = new Promise(resolve => { resolveOld = resolve; });
  const fetchData = vi.fn().mockResolvedValueOnce(['initial']).mockReturnValueOnce(old).mockResolvedValueOnce(['latest']);
  const { result } = renderHook(() => useAsyncData(fetchData, []));
  await waitFor(() => expect(result.current.data).toEqual(['initial']));
  act(() => { void result.current.reload(); });
  await act(async () => { await result.current.reload(); });
  await act(async () => { resolveOld(['outdated']); await old; });
  expect(result.current.data).toEqual(['latest']);
  expect(result.current.loading).toBe(false);
});

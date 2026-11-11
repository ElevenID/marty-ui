import { describe, expect, it, vi } from 'vitest'
import { act, fireEvent, renderWithoutRouter, screen, waitFor, within } from '@test/utils'
import ConfirmDeleteDialog from './ConfirmDeleteDialog'

function deferred() {
  let resolve!: () => void
  let reject!: (error: Error) => void
  const promise = new Promise<void>((done, fail) => { resolve = done; reject = fail })
  return { promise, resolve, reject }
}

describe('ConfirmDeleteDialog', () => {
  it('keeps a failed action open with an inline error and allows a successful retry', async () => {
    const onConfirm = vi.fn()
      .mockRejectedValueOnce(new Error('The key could not be revoked.'))
      .mockResolvedValueOnce(undefined)
    const onClose = vi.fn()
    const { user } = renderWithoutRouter(
      <ConfirmDeleteDialog open onConfirm={onConfirm} onClose={onClose}
        title="Revoke API Key" itemName="Partner key" confirmLabel="Revoke" />,
    )

    expect(screen.getByText(/Are you sure you want to revoke/)).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Revoke' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('The key could not be revoked.')
    expect(onClose).not.toHaveBeenCalled()
    expect(screen.getByRole('button', { name: 'Revoke' })).toBeEnabled()

    await user.click(screen.getByRole('button', { name: 'Revoke' }))
    await waitFor(() => expect(onClose).toHaveBeenCalledOnce())
    expect(onConfirm).toHaveBeenCalledTimes(2)
    expect(screen.queryByRole('alert')).not.toBeInTheDocument()
  })

  it('handles a synchronous action failure without dismissing the dialog', async () => {
    const onClose = vi.fn()
    const { user } = renderWithoutRouter(
      <ConfirmDeleteDialog open onClose={onClose} onConfirm={() => { throw new Error('Access denied') }} />,
    )
    await user.click(screen.getByRole('button', { name: 'Delete' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('Access denied')
    expect(onClose).not.toHaveBeenCalled()
  })

  it('blocks duplicate confirmation and dismissal while a request is pending', async () => {
    const request = deferred()
    const onConfirm = vi.fn(() => request.promise)
    const onClose = vi.fn()
    const { user } = renderWithoutRouter(
      <ConfirmDeleteDialog open onConfirm={onConfirm} onClose={onClose}
        itemName="Partner key" confirmLabel="Revoke" loading={false} />,
    )
    await user.click(screen.getByRole('button', { name: 'Revoke' }))
    expect(screen.getByRole('button', { name: 'Revoking…' })).toBeDisabled()
    expect(screen.getByRole('button', { name: 'Cancel' })).toBeDisabled()
    fireEvent.click(screen.getByRole('button', { name: 'Revoking…' }))
    await user.keyboard('{Escape}')
    expect(onConfirm).toHaveBeenCalledOnce()
    expect(onClose).not.toHaveBeenCalled()

    await act(async () => request.resolve())
    expect(onClose).toHaveBeenCalledOnce()
  })

  it('ignores completion from a closed request after a replacement dialog opens', async () => {
    const request = deferred()
    const onClose = vi.fn()
    const { user, rerender } = renderWithoutRouter(
      <ConfirmDeleteDialog open itemName="First endpoint" onConfirm={() => request.promise} onClose={onClose} />,
    )
    await user.click(screen.getByRole('button', { name: 'Delete' }))
    rerender(<ConfirmDeleteDialog open={false} itemName="First endpoint" onClose={onClose} />)
    rerender(<ConfirmDeleteDialog open itemName="Next endpoint" onClose={onClose} />)

    await act(async () => request.resolve())
    expect(onClose).not.toHaveBeenCalled()
    const dialog = screen.getByRole('dialog')
    expect(within(dialog).getByText('Next endpoint')).toBeInTheDocument()
    expect(within(dialog).getByRole('button', { name: 'Delete' })).toBeEnabled()
  })

  it('discards a late rejection when the confirmation target changes', async () => {
    const request = deferred()
    const { user, rerender } = renderWithoutRouter(
      <ConfirmDeleteDialog open itemName="First endpoint" onConfirm={() => request.promise} />,
    )
    await user.click(screen.getByRole('button', { name: 'Delete' }))
    rerender(<ConfirmDeleteDialog open itemName="Next endpoint" />)
    await act(async () => request.reject(new Error('First endpoint failed')))

    expect(screen.queryByRole('alert')).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Delete' })).toBeEnabled()
  })
})

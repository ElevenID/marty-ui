import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import sseService, { EVENT_TYPES } from '../sseService'

class MockEventSource {
  static instances: MockEventSource[] = []

  onopen: ((event: Event) => void) | null = null
  onerror: ((event: Event) => void) | null = null
  onmessage: ((event: MessageEvent) => void) | null = null
  url: string
  close = vi.fn()
  addEventListener = vi.fn()

  constructor(url: string) {
    this.url = url
    MockEventSource.instances.push(this)
  }
}

describe('sseService', () => {
  let consoleErrorSpy: ReturnType<typeof vi.spyOn>
  let consoleWarnSpy: ReturnType<typeof vi.spyOn>
  const unsubscribeCallbacks: Array<() => void> = []

  function observe(eventType: string) {
    const callback = vi.fn()
    unsubscribeCallbacks.push(sseService.on(eventType, callback))
    return callback
  }

  beforeEach(() => {
    vi.useFakeTimers()
    MockEventSource.instances = []
    vi.stubGlobal('EventSource', MockEventSource)
    consoleErrorSpy = vi.spyOn(console, 'error').mockImplementation(() => {})
    consoleWarnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {})
    sseService.disconnect()
    sseService.maxReconnectAttempts = 0
  })

  afterEach(() => {
    sseService.disconnect()
    unsubscribeCallbacks.splice(0).forEach(unsubscribe => unsubscribe())
    sseService.maxReconnectAttempts = 5
    vi.clearAllTimers()
    vi.useRealTimers()
    vi.unstubAllGlobals()
    consoleErrorSpy.mockRestore()
    consoleWarnSpy.mockRestore()
  })

  it('does not log stream reconnect failures as console errors', () => {
    sseService.connect({ organizationId: 'org_live' })

    expect(MockEventSource.instances).toHaveLength(1)
    MockEventSource.instances[0].onerror?.(new Event('error'))

    expect(consoleErrorSpy).not.toHaveBeenCalled()
  })

  it('uses organization_id instead of the legacy tenant_id selector', () => {
    sseService.connect({
      organizationId: 'org-a',
      userId: 'user-a',
      subscriptions: ['credential.issued'],
    })

    expect(MockEventSource.instances).toHaveLength(1)
    expect(MockEventSource.instances[0].url).toBe(
      '/v1/notifications/events/push'
        + '?organization_id=org-a'
        + '&user_id=user-a'
        + '&subscriptions=credential.issued',
    )
    expect(MockEventSource.instances[0].url).not.toContain('tenant_id')
  })

  it.each([false, true])('bounds retries with exponential delays even when the gateway briefly opens (opens=%s)', (opens) => {
    sseService.maxReconnectAttempts = 5
    const errors = observe('error')
    const connection = observe('connection')
    sseService.connect({ organizationId: 'org-a' })

    for (const [attempt, delay] of [1000, 2000, 4000, 8000, 16000].entries()) {
      const source = MockEventSource.instances[attempt]
      if (opens) {
        source.onopen?.(new Event('open'))
        source.onmessage?.(new MessageEvent('message', { data: '{"type":"connected"}' }))
        source.onmessage?.(new MessageEvent('message', { data: '{"error":"stream_error"}' }))
      }
      source.onerror?.(new Event('error'))
      expect(source.close).toHaveBeenCalledOnce()
      expect(sseService.isActive()).toBe(false)
      vi.advanceTimersByTime(delay - 1)
      expect(MockEventSource.instances).toHaveLength(attempt + 1)
      vi.advanceTimersByTime(1)
      expect(MockEventSource.instances).toHaveLength(attempt + 2)
    }

    const finalSource = MockEventSource.instances.at(-1)!
    if (opens) finalSource.onopen?.(new Event('open'))
    finalSource.onerror?.(new Event('error'))
    vi.runAllTimers()
    expect(MockEventSource.instances).toHaveLength(6)
    expect(finalSource.close).toHaveBeenCalledOnce()
    expect(errors).toHaveBeenCalledTimes(6)
    expect(connection).toHaveBeenLastCalledWith({ status: 'disconnected' })
  })

  it('cancels a pending reconnect when the owning page disconnects', () => {
    sseService.maxReconnectAttempts = 5
    const connection = observe('connection')
    sseService.connect({ organizationId: 'org-a' })
    MockEventSource.instances[0].onerror?.(new Event('error'))

    sseService.disconnect()
    vi.runAllTimers()

    expect(MockEventSource.instances).toHaveLength(1)
    expect(sseService.isActive()).toBe(false)
    expect(connection).toHaveBeenLastCalledWith({ status: 'disconnected' })
  })

  it('ignores stale source callbacks after switching organization and preserves current events', () => {
    sseService.maxReconnectAttempts = 5
    const errors = observe('error')
    const messages = observe('message')
    const issued = observe(EVENT_TYPES.CREDENTIAL_ISSUED)
    sseService.connect({ organizationId: 'org-a' })
    const oldSource = MockEventSource.instances[0]
    const oldIssued = oldSource.addEventListener.mock.calls.find(([type]) => type === EVENT_TYPES.CREDENTIAL_ISSUED)![1]
    oldSource.onerror?.(new Event('error'))
    sseService.disconnect()

    sseService.connect({ organizationId: 'org-b' })
    const currentSource = MockEventSource.instances[1]
    currentSource.onopen?.(new Event('open'))
    errors.mockClear()
    oldSource.onopen?.(new Event('open'))
    oldSource.onerror?.(new Event('error'))
    oldSource.onmessage?.(new MessageEvent('message', { data: '{"type":"credential.issued","id":"old"}' }))
    oldIssued(new MessageEvent(EVENT_TYPES.CREDENTIAL_ISSUED, { data: '{"id":"old"}' }))
    vi.runAllTimers()

    expect(MockEventSource.instances).toHaveLength(2)
    expect(currentSource.url).toContain('organization_id=org-b')
    expect(currentSource.close).not.toHaveBeenCalled()
    expect(sseService.isActive()).toBe(true)
    expect(errors).not.toHaveBeenCalled()
    expect(messages).not.toHaveBeenCalled()
    expect(issued).not.toHaveBeenCalled()

    currentSource.onmessage?.(new MessageEvent('message', { data: '{"type":"credential.issued","id":"current"}' }))
    expect(messages).toHaveBeenCalledWith({ type: 'credential.issued', id: 'current' })
    expect(issued).toHaveBeenCalledWith({ type: 'credential.issued', id: 'current' })
  })

  it('reports the original error once and does not reconnect after a listener disconnects', () => {
    sseService.maxReconnectAttempts = 5
    const errors = observe('error')
    unsubscribeCallbacks.push(sseService.on('error', () => sseService.disconnect()))
    sseService.connect({ organizationId: 'org-a' })
    const source = MockEventSource.instances[0]
    const error = new Event('error')
    source.onerror?.(error)
    source.onerror?.(error)
    vi.runAllTimers()

    expect(errors).toHaveBeenCalledExactlyOnceWith({ error })
    expect(MockEventSource.instances).toHaveLength(1)
    expect(source.close).toHaveBeenCalledOnce()
  })

  it('does not create a parallel connection when connect is repeated during backoff', () => {
    sseService.maxReconnectAttempts = 5
    sseService.connect({ organizationId: 'org-a' })
    MockEventSource.instances[0].onerror?.(new Event('error'))
    sseService.connect({ organizationId: 'org-b' })

    expect(MockEventSource.instances).toHaveLength(1)
    vi.advanceTimersByTime(1000)
    expect(MockEventSource.instances).toHaveLength(2)
    expect(MockEventSource.instances[1].url).toContain('organization_id=org-a')
  })

  it('resets the failure budget after a connection stays open', () => {
    sseService.maxReconnectAttempts = 1
    sseService.connect({ organizationId: 'org-a' })
    MockEventSource.instances[0].onerror?.(new Event('error'))
    vi.advanceTimersByTime(1000)
    const recoveredSource = MockEventSource.instances[1]
    recoveredSource.onopen?.(new Event('open'))
    vi.advanceTimersByTime(30000)
    recoveredSource.onerror?.(new Event('error'))

    vi.advanceTimersByTime(999)
    expect(MockEventSource.instances).toHaveLength(2)
    vi.advanceTimersByTime(1)
    expect(MockEventSource.instances).toHaveLength(3)
  })

  it('reports constructor failures during retry without throwing from the timer or retrying forever', () => {
    sseService.maxReconnectAttempts = 1
    const errors = observe('error')
    const connection = observe('connection')
    sseService.connect({ organizationId: 'org-a' })
    MockEventSource.instances[0].onerror?.(new Event('error'))
    const failure = new Error('EventSource unavailable')
    const failingConstructor = vi.fn(function () { throw failure })
    vi.stubGlobal('EventSource', failingConstructor)

    expect(() => vi.runAllTimers()).not.toThrow()
    expect(failingConstructor).toHaveBeenCalledOnce()
    expect(errors).toHaveBeenLastCalledWith({ error: failure })
    expect(connection).toHaveBeenLastCalledWith({ status: 'disconnected' })
    expect(sseService.isActive()).toBe(false)
  })
})

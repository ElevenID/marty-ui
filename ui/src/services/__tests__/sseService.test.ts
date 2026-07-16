import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import sseService from '../sseService'

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

  beforeEach(() => {
    MockEventSource.instances = []
    vi.stubGlobal('EventSource', MockEventSource)
    consoleErrorSpy = vi.spyOn(console, 'error').mockImplementation(() => {})
    consoleWarnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {})
    sseService.disconnect()
    sseService.maxReconnectAttempts = 0
  })

  afterEach(() => {
    sseService.disconnect()
    sseService.maxReconnectAttempts = 5
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
})

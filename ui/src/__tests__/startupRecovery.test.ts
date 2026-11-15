import fs from 'node:fs';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const projectRoot = path.resolve(__dirname, '../..');
const script = fs.readFileSync(path.join(projectRoot, 'public/startup.js'), 'utf8');
const html = fs.readFileSync(path.join(projectRoot, 'index.html'), 'utf8');
const shell = new DOMParser().parseFromString(html, 'text/html').querySelector('.app-loading-shell')!.outerHTML;

describe('startup recovery before the application module loads', () => {
  let reload: ReturnType<typeof vi.fn>;
  let reportRuntimeError: () => void;

  beforeEach(() => {
    vi.useFakeTimers();
    document.body.innerHTML = shell + '<div id="root"></div>';
    document.documentElement.className = '';
    reload = vi.fn();
    // Keep the real document and event stream, replacing only navigation so
    // recovery can be observed without leaving the test page.
    const startupWindow = {
      addEventListener(type: string, listener: EventListener, capture?: boolean) {
        if (type === 'error') {
          // A real runtime error targets the window passed to startup.js.
          reportRuntimeError = () => listener({ target: startupWindow } as unknown as Event);
        }
        window.addEventListener(type, listener, capture);
      },
      removeEventListener: window.removeEventListener.bind(window),
      location: { reload },
    };
    new Function('window', 'document', 'MutationObserver', 'setTimeout', 'clearTimeout', script)(
      startupWindow, document, MutationObserver, setTimeout, clearTimeout,
    );
  });

  afterEach(async () => {
    document.documentElement.classList.add('app-ready');
    await Promise.resolve();
    vi.useRealTimers();
    document.body.innerHTML = '';
  });

  it('offers one same-page reload after a failed module/WASM promise without displaying its error', () => {
    const rejection = new Event('unhandledrejection');
    Object.defineProperty(rejection, 'reason', { value: new Error('sensitive upstream detail') });
    window.dispatchEvent(rejection);
    window.dispatchEvent(rejection);
    const recovery = document.querySelector<HTMLElement>('[data-app-startup-recovery]')!;
    expect(recovery.hidden).toBe(false);
    expect(document.querySelector('.app-loading-shell')).toHaveAttribute('role', 'alert');
    expect(document.body).toHaveTextContent('ElevenID could not start');
    expect(document.body).not.toHaveTextContent('sensitive upstream detail');
    document.querySelector<HTMLButtonElement>('[data-app-startup-retry]')!.click();
    expect(reload).toHaveBeenCalledTimes(1);
  });

  it('offers recovery for a failed entry script while ignoring optional image failures', () => {
    const image = document.createElement('img');
    document.body.append(image);
    image.dispatchEvent(new Event('error'));
    expect(document.querySelector<HTMLElement>('[data-app-startup-recovery]')!.hidden).toBe(true);
    const entry = document.createElement('script');
    entry.type = 'module';
    document.body.append(entry);
    entry.dispatchEvent(new Event('error'));
    expect(document.body).toHaveTextContent('ElevenID could not start');
    expect(document.querySelector<HTMLElement>('[data-app-startup-recovery]')!.hidden).toBe(false);
  });

  it('offers recovery when execution fails before the application is ready', () => {
    reportRuntimeError();
    expect(document.querySelector('.app-loading-shell')).toHaveAttribute('role', 'alert');
    expect(document.querySelector<HTMLElement>('[data-app-startup-recovery]')!.hidden).toBe(false);
  });

  it('retains an early module failure until the loading shell has been parsed', () => {
    document.body.innerHTML = '';
    window.dispatchEvent(new Event('unhandledrejection'));
    document.body.innerHTML = shell + '<div id="root"></div>';
    document.dispatchEvent(new Event('DOMContentLoaded'));
    expect(document.body).toHaveTextContent('ElevenID could not start');
    vi.advanceTimersByTime(15000);
    expect(document.body).not.toHaveTextContent('ElevenID is taking longer to load');
    document.querySelector<HTMLButtonElement>('[data-app-startup-retry]')!.click();
    expect(reload).toHaveBeenCalledTimes(1);
  });

  it('gives a slow startup a retry action without claiming it has failed', () => {
    vi.advanceTimersByTime(15000);
    expect(document.body).toHaveTextContent('ElevenID is taking longer to load');
    expect(document.body).toHaveTextContent('Loading is still in progress');
    expect(document.querySelector('.app-loading-shell')).toHaveAttribute('role', 'status');
    expect(reload).not.toHaveBeenCalled();
  });

  it('stops startup recovery when the application becomes ready, including after a slow start', async () => {
    vi.advanceTimersByTime(15000);
    document.documentElement.classList.add('app-ready');
    await Promise.resolve();
    window.dispatchEvent(new Event('unhandledrejection'));
    vi.advanceTimersByTime(30000);
    expect(document.querySelector<HTMLElement>('[data-app-startup-recovery]')!.hidden).toBe(true);
    expect(reload).not.toHaveBeenCalled();
  });
});

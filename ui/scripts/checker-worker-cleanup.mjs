// Installed beside vite-plugin-checker by patch-checker-worker-cleanup.mjs.
// Worker.terminate() does not run the worker's exit handlers, so native checker
// children must be stopped and reaped before terminating their owning worker.
export const DISPOSE_REQUEST = 'marty:dispose-checker';
export const DISPOSE_COMPLETE = 'marty:checker-disposed';
export const DISPOSE_ERROR = 'marty:checker-dispose-error';

const processDisposals = new WeakMap();
const workerDisposals = new WeakMap();

export function stopOwnedProcess(child, { graceMs = 2_000, timeoutMs = 5_000 } = {}) {
  if (!child.pid || child.exitCode != null || child.signalCode != null) return Promise.resolve();
  if (processDisposals.has(child)) return processDisposals.get(child);

  const disposal = new Promise((resolve, reject) => {
    let forceTimer;
    let timeout;
    const finish = (error) => {
      clearTimeout(forceTimer);
      clearTimeout(timeout);
      child.off('close', onClose);
      child.off('error', onError);
      if (error) reject(error);
      else resolve();
    };
    const onClose = () => finish();
    const onError = (error) => finish(error);
    child.once('close', onClose);
    child.once('error', onError);
    forceTimer = setTimeout(() => {
      try { child.kill('SIGKILL'); } catch (error) { finish(error); }
    }, graceMs);
    timeout = setTimeout(() => finish(new Error('The native TypeScript checker did not exit after shutdown.')), timeoutMs);
    try { child.kill('SIGTERM'); } catch (error) { finish(error); }
  });
  processDisposals.set(child, disposal);
  return disposal;
}

export async function disposeDiagnostic(diagnostic, configuring, port) {
  try {
    // Closing during async setup must wait until any child has been registered.
    // A rejected setup must not prevent cleanup when shutdown is already pending.
    await Promise.resolve(configuring).catch(() => {});
    await diagnostic?.dispose?.();
    port.postMessage({ type: DISPOSE_COMPLETE });
  } catch (error) {
    port.postMessage({ type: DISPOSE_ERROR, payload: error instanceof Error ? error.message : String(error) });
  }
}

export function disposeCheckerWorker(worker, { timeoutMs = 60_000 } = {}) {
  if (worker.threadId === -1) return Promise.resolve();
  if (workerDisposals.has(worker)) return workerDisposals.get(worker);

  const disposal = (async () => {
    await new Promise((resolve, reject) => {
      let timeout;
      const finish = (error) => {
        clearTimeout(timeout);
        worker.off('message', onMessage);
        worker.off('exit', onExit);
        worker.off('error', onError);
        if (error) reject(error);
        else resolve();
      };
      const onMessage = (message) => {
        if (message?.type === DISPOSE_COMPLETE) finish();
        else if (message?.type === DISPOSE_ERROR) finish(new Error(`Checker shutdown failed: ${message.payload}`));
      };
      const onExit = () => finish(new Error('Checker exited before acknowledging child cleanup.'));
      const onError = (error) => finish(error);
      worker.on('message', onMessage);
      worker.once('exit', onExit);
      worker.once('error', onError);
      // Do not force-terminate on timeout: that would recreate the orphan-child
      // defect. The patched buildEnd reports this rejection even if Vite consumes
      // plugin-close failures while restarting.
      timeout = setTimeout(() => finish(new Error('Timed out waiting for checker child cleanup.')), timeoutMs);
      try { worker.postMessage({ type: DISPOSE_REQUEST }); } catch (error) { finish(error); }
    });
    await worker.terminate();
  })();
  workerDisposals.set(worker, disposal);
  return disposal;
}

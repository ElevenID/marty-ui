document.documentElement.classList.remove('app-ready');
document.documentElement.classList.add('app-loading');

// This script runs before the module graph, so failed module/WASM downloads
// can offer recovery even when React never starts.
(function watchStartup() {
  var root = document.documentElement;
  var finished = false;
  var pendingState = null;
  var retryBound = false;

  function completeIfReady() {
    if (!root.classList.contains('app-ready')) return false;
    finished = true;
    clearTimeout(watchdog);
    window.removeEventListener('error', onError, true);
    window.removeEventListener('unhandledrejection', onRejection);
    document.removeEventListener('DOMContentLoaded', onDomReady);
    observer.disconnect();
    var recovery = document.querySelector('[data-app-startup-recovery]');
    if (recovery) recovery.hidden = true;
    return true;
  }

  function showRecovery(state) {
    if (finished || completeIfReady()) return;
    if (state === 'failed' || pendingState === null) pendingState = state;
    var shell = document.querySelector('.app-loading-shell');
    var loading = document.querySelector('[data-app-startup-loading]');
    var recovery = document.querySelector('[data-app-startup-recovery]');
    var title = document.getElementById('app-startup-title');
    var message = document.getElementById('app-startup-message');
    var retry = document.querySelector('[data-app-startup-retry]');
    if (!shell || !loading || !recovery || !title || !message || !retry) return;

    var failed = pendingState === 'failed';
    title.textContent = failed ? 'ElevenID could not start' : 'ElevenID is taking longer to load';
    message.textContent = failed
      ? 'Part of the application could not be loaded. Reload this page to try again.'
      : 'Loading is still in progress. You can keep waiting or reload this page to try again.';
    loading.hidden = true;
    recovery.hidden = false;
    shell.setAttribute('role', failed ? 'alert' : 'status');
    shell.removeAttribute('aria-label');
    shell.setAttribute('aria-labelledby', 'app-startup-title');
    shell.setAttribute('aria-describedby', 'app-startup-message');
    if (!retryBound) {
      retry.addEventListener('click', function retryCurrentPage() {
        window.location.reload();
      });
      retryBound = true;
    }
  }

  function onError(event) {
    // Fonts, images and stylesheets are not proof that the app cannot start.
    if (event.target === window ||
        (event.target && event.target.tagName === 'SCRIPT' && event.target.type === 'module')) {
      showRecovery('failed');
    }
  }

  function onRejection() {
    showRecovery('failed');
  }

  function onDomReady() {
    if (pendingState) showRecovery(pendingState);
  }

  var observer = new MutationObserver(completeIfReady);
  observer.observe(root, { attributes: true, attributeFilter: ['class'] });
  window.addEventListener('error', onError, true);
  window.addEventListener('unhandledrejection', onRejection);
  document.addEventListener('DOMContentLoaded', onDomReady, { once: true });
  var watchdog = setTimeout(function showSlowStartup() {
    showRecovery('slow');
  }, 15000);
}());

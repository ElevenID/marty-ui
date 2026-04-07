import React from 'react';
import ReactDOM from 'react-dom/client';
import App from './App';
import './i18n';
import { configureApi } from '@marty/subscriptions';
import { get, post } from './services/api';

// Configure @marty/subscriptions API client before first render
configureApi({ get, post });

console.log('[DEBUG] index.jsx - Starting app render');

const rootElement = document.getElementById('root');
console.log('[DEBUG] Root element:', rootElement);

if (!rootElement) {
  console.error('[DEBUG] Root element not found!');
} else {
  const root = ReactDOM.createRoot(rootElement);
  console.log('[DEBUG] Root created, rendering App...');
  root.render(
    <React.StrictMode>
      <App />
    </React.StrictMode>
  );
  console.log('[DEBUG] App render called');

  const markAppReady = () => {
    document.documentElement.classList.remove('app-loading');
    document.documentElement.classList.add('app-ready');
    document.body.classList.remove('app-loading');
    document.body.classList.add('app-ready');
  };

  const awaitFonts =
    document.fonts && typeof document.fonts.ready?.then === 'function'
      ? document.fonts.ready.catch(() => {})
      : Promise.resolve();

  Promise.resolve()
    .then(() => awaitFonts)
    .then(() => {
      // Ensure we release loading state on next paint after render + fonts
      requestAnimationFrame(() => {
        requestAnimationFrame(markAppReady);
      });
    });
}

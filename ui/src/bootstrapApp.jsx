import React from 'react';
import ReactDOM from 'react-dom/client';
import { configureApi } from '@marty/subscriptions';

import './i18n';
import { get, post } from './services/api';

configureApi({ get, post });

function markAppReady() {
  document.documentElement.classList.remove('app-loading');
  document.documentElement.classList.add('app-ready');
  document.body.classList.remove('app-loading');
  document.body.classList.add('app-ready');
}

export function mountApp(RootComponent) {
  const rootElement = document.getElementById('root');

  if (!rootElement) {
    console.error('[DEBUG] Root element not found!');
    return;
  }

  const root = ReactDOM.createRoot(rootElement);
  root.render(
    <React.StrictMode>
      <RootComponent />
    </React.StrictMode>
  );

  const awaitFonts =
    document.fonts && typeof document.fonts.ready?.then === 'function'
      ? document.fonts.ready.catch(() => {})
      : Promise.resolve();

  Promise.resolve()
    .then(() => awaitFonts)
    .then(() => {
      requestAnimationFrame(() => {
        requestAnimationFrame(markAppReady);
      });
    });
}
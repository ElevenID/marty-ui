import React from 'react';
import ReactDOM from 'react-dom/client';

import './i18n';
import { waitForFonts } from './utils/waitForFonts';

function markAppReady() {
  document.documentElement.classList.remove('app-loading');
  document.documentElement.classList.add('app-ready');
  document.body.classList.remove('app-loading');
  document.body.classList.add('app-ready');
}

export function mountApp(RootComponent) {
  const rootElement = document.getElementById('root');

  if (!rootElement) {
    console.error('Root element not found.');
    return;
  }

  const root = ReactDOM.createRoot(rootElement);
  root.render(
    <React.StrictMode>
      <RootComponent />
    </React.StrictMode>
  );

  Promise.resolve()
    .then(() => waitForFonts())
    .then(() => {
      requestAnimationFrame(() => {
        requestAnimationFrame(markAppReady);
      });
    });
}

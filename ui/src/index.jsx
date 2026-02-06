import React from 'react';
import ReactDOM from 'react-dom/client';
import App from './App';

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
}

/**
 * Custom proxy configuration for Create React App
 * 
 * This file configures the webpack dev server to proxy certain requests
 * to the backend API server. This is necessary for:
 * - /auth/* routes (login, logout, callback) that need to go to the backend
 * - /api/* routes for API calls
 * 
 * The simple "proxy" field in package.json doesn't work for HTML navigation
 * requests because CRA serves the React app for those.
 */
const { createProxyMiddleware } = require('http-proxy-middleware');

module.exports = function(app) {
  const apiTarget = process.env.REACT_APP_API_URL || 'http://localhost:8000';
  
  // Common proxy options with error handling
  const commonOptions = {
    target: apiTarget,
    changeOrigin: true,
    logLevel: 'silent',
    onError: (err, req, res) => {
      console.error('Proxy error:', err.message);
      res.writeHead(502, { 'Content-Type': 'text/plain' });
      res.end('Proxy error: ' + err.message);
    },
    onProxyRes: (proxyRes, req, res) => {
      console.log(`[Proxy] ${req.method} ${req.url} -> ${proxyRes.statusCode}`);
    },
  };
  
  // Proxy /auth/* requests to the backend
  // These are OIDC login/logout/callback flows that must hit the API server
  app.use(
    '/auth',
    createProxyMiddleware({
      ...commonOptions,
      logLevel: 'debug',
      // Don't rewrite the path - keep /auth/login as-is
      pathRewrite: undefined,
      // Follow redirects is false so the browser handles the Keycloak redirect
      followRedirects: false,
    })
  );

  // Proxy /api/* requests to the backend  
  app.use(
    '/api',
    createProxyMiddleware({
      ...commonOptions,
      logLevel: 'debug',
    })
  );

  // Proxy health check
  app.use(
    '/health',
    createProxyMiddleware({
      ...commonOptions,
      logLevel: 'debug',
    })
  );
};

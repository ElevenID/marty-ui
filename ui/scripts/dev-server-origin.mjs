import { isIP } from 'node:net';

// Keep the browser, reverse proxy, and HMR client on the same public origin.
// A hostname alone loses nonstandard TLS ports such as a development edge's 8443.
export function devServerOrigin(env) {
  const value = env.VITE_DEV_PUBLIC_ORIGIN
    || (env.PUBLIC_DOMAIN ? `https://${env.PUBLIC_DOMAIN}` : '');
  if (!value) return { allowedHosts: ['localhost'] };

  let url;
  try {
    url = new URL(value);
  } catch {
    throw new Error('VITE_DEV_PUBLIC_ORIGIN must be an absolute HTTP(S) origin');
  }
  const hostname = url.hostname;
  const ip = isIP(hostname.replace(/^\[|\]$/g, ''));
  const dns = hostname.length <= 253 && hostname.split('.').every((label) => (
    label.length <= 63 && /^[a-z\d](?:[a-z\d-]*[a-z\d])?$/i.test(label)
  ));
  if (!/^https?:\/\/[^/]+\/?$/i.test(value) || /[?#@\\\s]/.test(value)
    || !['http:', 'https:'].includes(url.protocol)
    || url.username || url.password || url.pathname !== '/' || url.search || url.hash
    || (!ip && !dns) || url.port === '0') {
    throw new Error('VITE_DEV_PUBLIC_ORIGIN must contain only an HTTP(S) scheme, exact hostname, and optional port');
  }

  return {
    origin: url.origin,
    allowedHosts: [...new Set(['localhost', hostname])],
    cors: { origin: url.origin },
    hmr: {
      protocol: url.protocol === 'https:' ? 'wss' : 'ws',
      host: hostname,
      clientPort: Number(url.port || (url.protocol === 'https:' ? 443 : 80)),
    },
  };
}

import { get, withApiErrorHandling } from './api';

export async function getPhysicalDocumentCapabilities() {
  return withApiErrorHandling(() => get('/v1/passport/capabilities'));
}

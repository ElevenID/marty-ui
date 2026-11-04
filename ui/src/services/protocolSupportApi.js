import { get } from './api';
import { normalizeProtocolSupportCatalog, PROTOCOL_SUPPORT_PATH } from '../application/protocolSupportCatalog';
export { normalizeProtocolSupportCatalog, PROTOCOL_SUPPORT_PATH, PROTOCOL_SUPPORT_LEVELS } from '../application/protocolSupportCatalog';

export async function getProtocolSupportCatalog(options = {}) {
  return normalizeProtocolSupportCatalog(await get(PROTOCOL_SUPPORT_PATH, options));
}

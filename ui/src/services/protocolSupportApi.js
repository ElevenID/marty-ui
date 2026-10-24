import { get } from './api';

export const PROTOCOL_SUPPORT_PATH = '/v1/protocol-support';
export const PROTOCOL_SUPPORT_LEVELS = ['implemented', 'derived', 'partial', 'unsupported'];

function requireObject(value, name) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`Protocol support catalog ${name} must be an object.`);
  }
  return value;
}

function requireStringArray(value, name) {
  if (!Array.isArray(value) || value.some((entry) => typeof entry !== 'string')) {
    throw new Error(`Protocol support catalog ${name} must be a string array.`);
  }
  return value;
}

function requireString(value, name) {
  if (typeof value !== 'string' || !value.trim()) {
    throw new Error(`Protocol support catalog ${name} must be a non-empty string.`);
  }
  return value;
}

export function normalizeProtocolSupportCatalog(raw) {
  const catalog = requireObject(raw, 'response');
  if (catalog.schema_version !== 1 || catalog.discovery_path !== PROTOCOL_SUPPORT_PATH) {
    throw new Error('Protocol support catalog version or discovery path is unsupported.');
  }
  if (!/^[0-9a-f]{40}$/.test(catalog.protocol_revision || '')) {
    throw new Error('Protocol support catalog revision is invalid.');
  }
  requireObject(catalog.support_levels, 'support levels');
  requireObject(catalog.qualification_levels, 'qualification levels');
  if (!Array.isArray(catalog.entities)) {
    throw new Error('Protocol support catalog entities must be an array.');
  }
  const ids = new Set();
  const entities = catalog.entities.map((value) => {
    const entity = requireObject(value, 'entity');
    const id = requireString(entity.id, 'entity ID');
    if (ids.has(id)) {
      throw new Error('Protocol support catalog entity IDs must be present and unique.');
    }
    ids.add(id);
    requireString(entity.display_name, `${id} display name`);
    requireString(entity.kind, `${id} kind`);
    if (!PROTOCOL_SUPPORT_LEVELS.includes(entity.support_level)) {
      throw new Error(`Protocol support catalog level is invalid for ${id}.`);
    }
    if (!Object.hasOwn(catalog.qualification_levels, entity.qualification)) {
      throw new Error(`Protocol support catalog qualification is invalid for ${id}.`);
    }
    const apiPaths = requireStringArray(entity.api_paths, `${id} API paths`);
    const uiPaths = requireStringArray(entity.ui_paths, `${id} UI paths`);
    const schemaRefs = requireStringArray(entity.schema_refs, `${id} schema refs`);
    const limitations = requireStringArray(entity.limitations, `${id} limitations`);
    if (entity.support_level === 'unsupported'
      && (entity.owner_service !== null || apiPaths.length || uiPaths.length || schemaRefs.length || !limitations.length)) {
      throw new Error(`Unsupported protocol entity ${id} cannot advertise product surfaces.`);
    }
    return { ...entity, api_paths: apiPaths, ui_paths: uiPaths, schema_refs: schemaRefs, limitations };
  });
  return { ...catalog, entities };
}

export async function getProtocolSupportCatalog(options = {}) {
  return normalizeProtocolSupportCatalog(await get(PROTOCOL_SUPPORT_PATH, options));
}

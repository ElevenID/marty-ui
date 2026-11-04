// Pure shared route ownership. The edge generator and browser use the same data.
export function validateWebSurfaceContract(contract) {
  const keys = (value) => value && typeof value === 'object' && !Array.isArray(value)
    ? Object.keys(value).sort().join(',') : '';
  if (keys(contract) !== 'fallback,schema_version,website'
    || contract.schema_version !== 1 || contract.fallback !== 'application'
    || keys(contract.website) !== 'exact_paths,filename_patterns,path_prefixes') {
    throw new Error('Unsupported web surface route contract');
  }
  const { exact_paths: exact, path_prefixes: prefixes, filename_patterns: patterns } = contract.website;
  for (const entries of [exact, prefixes, patterns]) {
    if (!Array.isArray(entries) || entries.some((entry) => typeof entry !== 'string')
      || new Set(entries).size !== entries.length) throw new Error('Invalid web surface route list');
  }
  if (!exact.includes('/') || exact.some((entry) => !/^\/[a-z0-9/_.-]*$/.test(entry))
    || prefixes.some((entry) => !/^\/[a-z0-9_-]+\/$/.test(entry))
    || patterns.length !== 1 || patterns[0] !== '^/sitemap-[^/]+\\.xml$') {
    throw new Error('Invalid web surface path');
  }
  return contract;
}

export function webPathOwner(pathname, contract) {
  const website = contract.website;
  if (typeof pathname !== 'string' || !pathname.startsWith('/') || pathname.startsWith('//')
    || /[\\?#\u0000-\u0020\u007f]/u.test(pathname)) return contract.fallback;
  return website.exact_paths.includes(pathname)
    || website.path_prefixes.some((prefix) => pathname.startsWith(prefix))
    || website.filename_patterns.some((pattern) => new RegExp(pattern).test(pathname))
    ? 'website' : contract.fallback;
}

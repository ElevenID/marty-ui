/**
 * Shared query utilities for service modules.
 *
 * Note: `buildTruthyQueryString` intentionally preserves existing behavior in
 * many services where falsy values are omitted (e.g., 0/false/empty string).
 */

/**
 * Build a query string from key/value pairs, omitting falsy values.
 *
 * @param {Record<string, any>} params
 * @returns {string}
 */
export function buildTruthyQueryString(params = {}) {
  const searchParams = new URLSearchParams();

  Object.entries(params).forEach(([key, value]) => {
    if (value) {
      searchParams.append(key, String(value));
    }
  });

  return searchParams.toString();
}

/**
 * Build a query string from key/value pairs, omitting only undefined/null.
 *
 * @param {Record<string, any>} params
 * @returns {string}
 */
export function buildDefinedQueryString(params = {}) {
  const searchParams = new URLSearchParams();

  Object.entries(params).forEach(([key, value]) => {
    if (value !== undefined && value !== null) {
      searchParams.append(key, String(value));
    }
  });

  return searchParams.toString();
}

/**
 * Append query string to a path only when query has content.
 *
 * @param {string} path
 * @param {string} queryString
 * @returns {string}
 */
export function withQuery(path, queryString) {
  return queryString ? `${path}?${queryString}` : path;
}

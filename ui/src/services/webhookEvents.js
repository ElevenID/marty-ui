/**
 * Shared UI behavior for the Rust-owned webhook event catalog.
 *
 * The notification service remains the canonical source of supported event
 * types. These helpers keep every UI surface on the same catalog shape while
 * retaining one reviewed preset for common asynchronous gateway callbacks.
 */

export const ASYNC_GATEWAY_EVENT_PRESET = Object.freeze([
  'application.approved',
  'application.rejected',
  'credential.offered',
  'credential.issued',
  'credential.revoked',
  'verification.requested',
]);

export function flattenWebhookEventCatalog(categories = []) {
  return categories.flatMap((category) => (
    Array.isArray(category?.events)
      ? category.events.map((event) => ({
        id: event.type,
        label: event.description || event.type,
        category: category.name || 'Other',
      }))
      : []
  )).filter((event) => typeof event.id === 'string' && event.id.length > 0);
}

export function supportedPresetEvents(eventOptions, preset = ASYNC_GATEWAY_EVENT_PRESET) {
  const supported = new Set(eventOptions.map((event) => event.id));
  return preset.filter((eventType) => supported.has(eventType));
}

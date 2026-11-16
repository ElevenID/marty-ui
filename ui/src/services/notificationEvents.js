// Same-tab invalidation only: subscribers reload their own authoritative data.
const NOTIFICATION_CHANGED_EVENT = 'elevenid:notification-changed';

export function publishNotificationChange({ organizationId, recipientId }) {
  if (typeof window === 'undefined' || !organizationId || !recipientId) return;
  window.dispatchEvent(new CustomEvent(NOTIFICATION_CHANGED_EVENT, {
    detail: { organizationId, recipientId },
  }));
}

export function subscribeToNotificationChanges({ organizationId, recipientId }, onChange) {
  if (typeof window === 'undefined' || !organizationId || !recipientId) return () => {};
  const handleChange = (event) => {
    if (event.detail?.organizationId === organizationId && event.detail?.recipientId === recipientId) {
      onChange();
    }
  };
  window.addEventListener(NOTIFICATION_CHANGED_EVENT, handleChange);
  return () => window.removeEventListener(NOTIFICATION_CHANGED_EVENT, handleChange);
}

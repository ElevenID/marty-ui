/** Native policy ages are unsigned integer seconds; JSON numbers must remain exact. */
export function isValidPolicyCredentialAge(value) {
  // Validate the text before conversion so a long fraction cannot round to an integer.
  if (typeof value !== 'number' && (typeof value !== 'string' || !/^\d+$/.test(value.trim()))) return false;
  const seconds = Number(value);
  return Number.isSafeInteger(seconds) && seconds >= 0;
}

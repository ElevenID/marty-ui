/**
 * Pure helpers for passport operations.
 */

export function createPassportIssueError(message = 'Failed to issue passport') {
  return {
    error: message,
    result: null,
  };
}

export function createPassportInspectError(message = 'Failed to inspect passport') {
  return {
    error: message,
    inspectResult: null,
  };
}

export function resolvePassportIssueResult(data) {
  return {
    error: null,
    result: data,
  };
}

export function resolvePassportInspectResult(data) {
  return {
    error: null,
    inspectResult: data,
  };
}

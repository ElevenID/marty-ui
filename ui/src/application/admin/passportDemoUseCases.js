import { getErrorMessage, post } from '../../services/api';
import {
  createPassportInspectError,
  createPassportIssueError,
  resolvePassportInspectResult,
  resolvePassportIssueResult,
} from './passportDemoFlow';

async function defaultProcessPassport({ passportNumber }) {
  return post('/api/passport/process', {
    passport_number: passportNumber,
  });
}

async function defaultInspectPassport({ passportNumber }) {
  return post('/api/passport/inspect', {
    passport_number: passportNumber,
  });
}

export async function issuePassport({
  passportNumber,
  processPassport = defaultProcessPassport,
} = {}) {
  try {
    const result = await processPassport({ passportNumber });
    return resolvePassportIssueResult(result);
  } catch (error) {
    return createPassportIssueError(getErrorMessage(error) || 'Failed to issue passport');
  }
}

export async function inspectPassport({
  passportNumber,
  inspectPassportRequest = defaultInspectPassport,
} = {}) {
  try {
    const result = await inspectPassportRequest({ passportNumber });
    return resolvePassportInspectResult(result);
  } catch (error) {
    return createPassportInspectError(getErrorMessage(error) || 'Failed to inspect passport');
  }
}

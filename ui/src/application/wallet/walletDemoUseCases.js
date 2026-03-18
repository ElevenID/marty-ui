import { del, get, getErrorMessage, post } from '../../services/api';
import {
  buildWalletPresentationPayload,
  resolveWalletCredentials,
  resolveWalletDelete,
  resolveWalletPresentationResult,
} from './walletDemoFlow';

async function defaultLoadWalletCredentials() {
  return get('/v1/credentials/wallet/credentials');
}

async function defaultDeleteWalletCredential(credentialId) {
  return del(`/v1/credentials/wallet/credentials/${credentialId}`);
}

async function defaultCreateWalletPresentation(payload) {
  return post('/v1/credentials/wallet/present', payload);
}

export async function loadWalletDemoCredentials({
  loadCredentials = defaultLoadWalletCredentials,
} = {}) {
  try {
    const result = await loadCredentials();
    return {
      credentials: resolveWalletCredentials(result),
      error: null,
    };
  } catch (error) {
    return {
      credentials: resolveWalletCredentials({}),
      error: getErrorMessage(error) || 'Failed to load credentials',
    };
  }
}

export async function deleteWalletDemoCredential({
  credentialId,
  credentials = [],
  deleteCredential = defaultDeleteWalletCredential,
} = {}) {
  try {
    await deleteCredential(credentialId);
    return {
      credentials: resolveWalletDelete(credentials, credentialId),
      error: null,
    };
  } catch (error) {
    return {
      credentials: resolveWalletDelete(credentials, credentialId),
      error: getErrorMessage(error) || 'Failed to delete credential',
    };
  }
}

export async function createWalletDemoPresentation({
  selectedCredential,
  presentationRequest,
  createPresentation = defaultCreateWalletPresentation,
} = {}) {
  try {
    const result = await createPresentation(buildWalletPresentationPayload({
      selectedCredential,
      presentationRequest,
    }));
    return resolveWalletPresentationResult(result);
  } catch (error) {
    return {
      success: false,
      error: getErrorMessage(error) || error.message || 'Failed to create presentation',
      message: null,
    };
  }
}
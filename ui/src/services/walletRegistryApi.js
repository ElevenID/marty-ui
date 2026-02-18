/**
 * Wallet Registry API
 *
 * Provides access to the global wallet registry — descriptions of wallets
 * that support the OID4VCI protocol and can receive credentials via deep link.
 */
import { apiClient } from './api';

const BASE = '/v1/wallet-registry';

/**
 * List all active wallets in the registry.
 * @param {boolean} [activeOnly=true] - If true, only return active wallet entries.
 * @returns {Promise<Array>}
 */
export const listWallets = async (activeOnly = true) => {
  const response = await apiClient.get(BASE, { params: { active_only: activeOnly } });
  return response.data;
};

/**
 * Get a single wallet registry entry by ID.
 * @param {string} walletId
 * @returns {Promise<Object>}
 */
export const getWallet = async (walletId) => {
  const response = await apiClient.get(`${BASE}/${walletId}`);
  return response.data;
};

/**
 * Create a new wallet registry entry (admin only).
 * @param {Object} data
 * @returns {Promise<Object>}
 */
export const createWallet = async (data) => {
  const response = await apiClient.post(BASE, data);
  return response.data;
};

/**
 * Update an existing wallet registry entry (admin only).
 * @param {string} walletId
 * @param {Object} data
 * @returns {Promise<Object>}
 */
export const updateWallet = async (walletId, data) => {
  const response = await apiClient.patch(`${BASE}/${walletId}`, data);
  return response.data;
};

/**
 * Delete a wallet registry entry (admin only).
 * @param {string} walletId
 * @returns {Promise<Object>}
 */
export const deleteWallet = async (walletId) => {
  const response = await apiClient.delete(`${BASE}/${walletId}`);
  return response.data;
};

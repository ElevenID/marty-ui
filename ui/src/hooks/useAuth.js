/**
 * useAuth Hook
 *
 * Custom hook for accessing authentication context.
 * Provides convenient access to auth state and methods.
 */

import { useContext } from 'react';
import { AuthContext } from '../contexts/AuthContext';

/**
 * Hook to access authentication state and methods
 *
 * @returns {Object} Auth context value
 * @property {Object|null} user - Current authenticated user
 * @property {boolean} isAuthenticated - Whether user is authenticated
 * @property {boolean} isLoading - Whether auth state is loading
 * @property {boolean} isAdministrator - Whether user is an administrator
 * @property {boolean} isApplicant - Whether user is an applicant
 * @property {function} login - Initiate login flow
 * @property {function} logout - Initiate logout flow
 * @property {function} refreshUser - Refresh user info from server
 *
 * @example
 * const { user, isAuthenticated, isAdministrator, login, logout } = useAuth();
 *
 * if (!isAuthenticated) {
 *   return <button onClick={() => login()}>Login</button>;
 * }
 *
 * return <span>Welcome, {user.given_name}!</span>;
 */
export function useAuth() {
  const context = useContext(AuthContext);

  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider');
  }

  return context;
}

/**
 * Hook to require authentication
 *
 * Redirects to login if not authenticated.
 *
 * @param {string} [redirectUri] - Where to redirect after login
 * @returns {Object} Auth context value (guaranteed authenticated)
 */
export function useRequireAuth(redirectUri) {
  const auth = useAuth();

  if (!auth.isLoading && !auth.isAuthenticated) {
    auth.login(redirectUri || window.location.pathname);
  }

  return auth;
}

/**
 * Hook to require specific user type
 *
 * @param {'administrator' | 'applicant'} requiredType - Required user type
 * @param {string} [fallbackPath='/'] - Path to redirect if wrong type
 * @returns {Object} Auth context value
 */
export function useRequireUserType(requiredType, fallbackPath = '/') {
  const auth = useAuth();

  if (!auth.isLoading && auth.isAuthenticated) {
    if (auth.user?.user_type !== requiredType) {
      // Redirect to fallback if wrong user type
      window.location.href = fallbackPath;
    }
  }

  return auth;
}

export default useAuth;

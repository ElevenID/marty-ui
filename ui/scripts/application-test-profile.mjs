// A bounded application routing/authentication/startup suite. This is not the complete
// UI test suite or an OIDC/host qualification; combined/website tests keep their
// existing configuration and discovery rules.
export const APPLICATION_TEST_CONFIG = 'vitest.application.config.ts';

export const APPLICATION_TEST_FILES = Object.freeze([
  'src/__tests__/startupRecovery.test.ts',
  'src/application/routing/appHandoff.test.ts',
  'src/application/routing/applyEntry.test.ts',
  'src/application/routing/authCallback.test.ts',
  'src/application/routing/guardPolicy.test.ts',
  'src/application/routing/landingEntry.test.ts',
  'src/application/routing/loginEntry.test.ts',
  'src/application/routing/publicEntry.test.ts',
  'src/application/session/authSession.test.ts',
  'src/application/session/consoleSession.test.ts',
  'src/apps/public/PublicRoutes.test.tsx',
  'src/apps/console/ConsoleRoutes.test.tsx',
  'src/apps/shared/AppShell.publicEntry.test.tsx',
  'src/apps/shared/WebSurfaceBoundary.test.tsx',
  'src/contexts/__tests__/PublicEntryAuth.test.tsx',
  'src/components/__tests__/AuthCallback.integration.test.tsx',
  'src/components/__tests__/AuthAvailability.integration.test.tsx',
  'src/components/__tests__/ProtectedRoute.test.tsx',
  'src/components/__tests__/BrowserRedirect.test.tsx',
  'src/components/navigation/ConsoleHeaderBar.test.tsx',
  'src/components/navigation/SidebarNavigation.test.tsx',
  'src/components/navigation/SidebarNavigationApplicant.test.tsx',
  'src/components/console/agents/AgentTrustPages.test.tsx',
  'src/services/__tests__/agentTrustApi.test.ts',
  'src/services/__tests__/authApi.test.ts',
  'src/services/__tests__/authApiOrigin.test.ts',
  'src/services/__tests__/consoleApiOrigin.test.ts',
  'src/services/__tests__/identityProviderApi.test.ts',
  'src/services/__tests__/associationConsent.test.ts',
  'tests/application/surface-profile.test.tsx',
]);

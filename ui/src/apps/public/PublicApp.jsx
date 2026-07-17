import AppProviders from '../shared/AppProviders';
import AppShell from '../shared/AppShell';
import PublicRoutes from './PublicRoutes';

function PublicApp() {
  return (
    <AppProviders>
        <AppShell>
          <PublicRoutes />
        </AppShell>
    </AppProviders>
  );
}

export default PublicApp;

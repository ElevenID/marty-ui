import AppProviders from '../shared/AppProviders';
import AppShell from '../shared/AppShell';
import PrerenderReadySignal from '../shared/PrerenderReadySignal';
import PublicRoutes from './PublicRoutes';

function PublicApp() {
  return (
    <AppProviders>
      <AppShell>
        <PublicRoutes />
        <PrerenderReadySignal />
      </AppShell>
    </AppProviders>
  );
}

export default PublicApp;
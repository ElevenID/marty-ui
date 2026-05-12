import AppProviders from '../shared/AppProviders';
import AppShell from '../shared/AppShell';
import ConsoleRoutes from './ConsoleRoutes';

function ConsoleApp() {
  return (
    <AppProviders>
      <AppShell showAppBar={false}>
        <ConsoleRoutes />
      </AppShell>
    </AppProviders>
  );
}

export default ConsoleApp;
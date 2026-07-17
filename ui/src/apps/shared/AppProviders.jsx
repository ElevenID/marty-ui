import { Suspense } from 'react';
import { BrowserRouter as Router } from 'react-router-dom';
import { Box, Typography } from '@mui/material';

import { AuthProvider } from '../../contexts/AuthContext';
import { BrandingProvider } from '../../contexts/BrandingContext';
import { ConsoleProvider } from '../../contexts/ConsoleContext';
import { NotificationProvider } from '../../contexts/NotificationContext';
import ErrorBoundary from '../../components/ErrorBoundary';
import { TrustProvider } from '../../components/trust/TrustProvider';
import { CommerceProvider } from '../../extensions/commerce';
import PrerenderReadySignal from './PrerenderReadySignal';

function LoadingFallback() {
  return (
    <Box data-app-loading sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '100vh' }}>
      <Typography>Loading...</Typography>
    </Box>
  );
}

function AppProviders({ children }) {
  return (
    <ErrorBoundary>
      <Router>
        <PrerenderReadySignal />
        <Suspense fallback={<LoadingFallback />}>
          <BrandingProvider>
            <NotificationProvider>
              <TrustProvider>
                <CommerceProvider>
                  <AuthProvider>
                    <ConsoleProvider>
                      {children}
                    </ConsoleProvider>
                  </AuthProvider>
                </CommerceProvider>
              </TrustProvider>
            </NotificationProvider>
          </BrandingProvider>
        </Suspense>
      </Router>
    </ErrorBoundary>
  );
}

export default AppProviders;

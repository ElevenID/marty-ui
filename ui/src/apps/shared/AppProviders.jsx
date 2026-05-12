import { Suspense } from 'react';
import { BrowserRouter as Router } from 'react-router-dom';
import { Box, Typography } from '@mui/material';
import { PaymentProvider } from '@marty/subscriptions';

import { AuthProvider } from '../../contexts/AuthContext';
import { BrandingProvider } from '../../contexts/BrandingContext';
import { ConsoleProvider } from '../../contexts/ConsoleContext';
import { NotificationProvider } from '../../contexts/NotificationContext';
import ErrorBoundary from '../../components/ErrorBoundary';
import { TrustProvider } from '../../components/trust/TrustProvider';

function LoadingFallback() {
  return (
    <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '100vh' }}>
      <Typography>Loading...</Typography>
    </Box>
  );
}

function AppProviders({ children }) {
  return (
    <ErrorBoundary>
      <Suspense fallback={<LoadingFallback />}>
        <BrandingProvider>
          <NotificationProvider>
            <TrustProvider>
              <PaymentProvider>
                <Router>
                  <AuthProvider>
                    <ConsoleProvider>
                      {children}
                    </ConsoleProvider>
                  </AuthProvider>
                </Router>
              </PaymentProvider>
            </TrustProvider>
          </NotificationProvider>
        </BrandingProvider>
      </Suspense>
    </ErrorBoundary>
  );
}

export default AppProviders;
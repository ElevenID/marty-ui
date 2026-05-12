import { useEffect } from 'react';
import { useLocation } from 'react-router-dom';
import { Box, CircularProgress, Typography } from '@mui/material';
import { redirectBrowser } from '../application/routing/appHandoff';

function buildRedirectDestination(baseDestination, search, preserveSearch) {
  if (!preserveSearch || !search) {
    return baseDestination;
  }

  if (baseDestination.includes('?')) {
    return `${baseDestination}&${search.slice(1)}`;
  }

  return `${baseDestination}${search}`;
}

function BrowserRedirect({
  to,
  replace = true,
  preserveSearch = false,
  message = 'Redirecting...',
}) {
  const location = useLocation();
  const destination = buildRedirectDestination(to, location.search, preserveSearch);

  useEffect(() => {
    redirectBrowser(destination, { replace });
  }, [destination, replace]);

  return (
    <Box
      display="flex"
      flexDirection="column"
      alignItems="center"
      justifyContent="center"
      minHeight="50vh"
      data-testid="browser-redirect"
    >
      <CircularProgress size={48} />
      <Typography variant="body1" color="text.secondary" sx={{ mt: 2 }}>
        {message}
      </Typography>
    </Box>
  );
}

export default BrowserRedirect;
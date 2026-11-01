import { Box, Button, Stack, Typography } from '@mui/material';
import { publicEntryHref } from '../application/routing/publicEntry';
import { isWebSectionEnabled } from '../utils/runtimeConfig';

// Customer bundles deliberately do not import the production public-site
// module. Hiding its navigation would still ship the marketing page chunks.
function CustomerHomePage() {
  return (
    <Box component="main" sx={{ py: 6 }} data-testid="customer-home">
      <Typography variant="h3" component="h1" gutterBottom>
        Application portal
      </Typography>
      <Typography color="text.secondary" sx={{ mb: 3 }}>
        Access the applications and workspace available on this installation.
      </Typography>
      <Stack direction={{ xs: 'column', sm: 'row' }} spacing={2}>
        {isWebSectionEnabled('console') && (
          <>
            <Button component="a" href={publicEntryHref('/console')} variant="contained">
              Open console
            </Button>
            <Button component="a" href={publicEntryHref('/apply')} variant="outlined">
              View applications
            </Button>
          </>
        )}
        <Button component="a" href={publicEntryHref('/organizations')} variant="outlined">
          View organizations
        </Button>
      </Stack>
    </Box>
  );
}

export function getPublicLoginFallback() {
  return isWebSectionEnabled('console') ? '/console' : '/';
}

export function renderPublicRoot() {
  return <CustomerHomePage />;
}

export function renderMarketingRoutes() {
  return null;
}

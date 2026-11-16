import { Box, Typography } from '@mui/material';

export default function WebSectionUnavailable() {
  return (
    <Box component="main" sx={{ p: 4 }} data-testid="web-section-unavailable">
      <Typography component="h1" variant="h4" gutterBottom>Page unavailable</Typography>
      <Typography>This page is not available on this installation.</Typography>
    </Box>
  );
}

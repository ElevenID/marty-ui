/**
 * Preview Layout
 * 
 * Minimal background for preview pages without console navigation.
 */

import { Box } from '@mui/material';
import { Outlet } from 'react-router';

function PreviewLayout() {
  return (
    <Box sx={{ minHeight: '100vh', bgcolor: 'background.default' }}>
      <Outlet />
    </Box>
  );
}

export default PreviewLayout;

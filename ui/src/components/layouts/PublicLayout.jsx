/**
 * PublicLayout Component
 * 
 * Layout wrapper for public pages and traditional authenticated pages.
 * Uses Container with max-width and includes Navigation component.
 */

import { Outlet } from 'react-router-dom';
import { Container, Box } from '@mui/material';
import Navigation from '../Navigation';

function PublicLayout() {
  return (
    <Container maxWidth="lg">
      <Box sx={{ my: 4 }}>
        <Navigation />
        <Outlet />
      </Box>
    </Container>
  );
}

export default PublicLayout;

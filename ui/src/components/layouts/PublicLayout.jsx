/**
 * PublicLayout Component
 * 
 * Layout wrapper for public pages and traditional authenticated pages.
 * Uses Container with max-width and includes Navigation component.
 * Adds smooth scrolling and proper spacing for sticky nav.
 */

import { Outlet } from 'react-router-dom';
import { Container, Box } from '@mui/material';
import Navigation from '../Navigation';
import PublicFooter from './PublicFooter';

function PublicLayout() {
  return (
    <Box sx={{ scrollBehavior: 'smooth' }}>
      <Container maxWidth="lg">
        <Box sx={{ mt: 2 }}>
          <Navigation />
        </Box>
      </Container>
      <Container maxWidth="lg">
        <Box sx={{ mb: 4 }}>
          <Outlet />
          <PublicFooter />
        </Box>
      </Container>
    </Box>
  );
}

export default PublicLayout;

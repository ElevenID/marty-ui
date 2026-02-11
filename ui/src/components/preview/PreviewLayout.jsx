/**
 * Preview Layout
 * 
 * Minimal layout for preview pages - displays PreviewModeBanner and page content
 * without console navigation.
 */

import { Box } from '@mui/material';
import { Outlet } from 'react-router-dom';
import PreviewModeBanner from '../common/PreviewModeBanner';
import { usePreview } from '../../contexts/PreviewContext';

function PreviewLayout() {
  const { contextLabel } = usePreview();

  return (
    <Box sx={{ minHeight: '100vh', bgcolor: 'background.default' }}>
      <PreviewModeBanner contextLabel={contextLabel} />
      <Box sx={{ pt: 2 }}>
        <Outlet />
      </Box>
    </Box>
  );
}

export default PreviewLayout;

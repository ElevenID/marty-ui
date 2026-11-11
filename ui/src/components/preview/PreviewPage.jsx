import { Box } from '@mui/material';
import PropTypes from 'prop-types';
import { PreviewProvider } from '../../contexts/PreviewContext';
import PreviewModeBanner from '../common/PreviewModeBanner';

/** Keep each page's controls and content inside the same preview lifetime. */
function PreviewPage({ children, ...previewContext }) {
  return (
    <PreviewProvider {...previewContext}>
      <PreviewModeBanner />
      <Box sx={{ pt: 2 }}>{children}</Box>
    </PreviewProvider>
  );
}

PreviewPage.propTypes = {
  children: PropTypes.node.isRequired,
};

export default PreviewPage;

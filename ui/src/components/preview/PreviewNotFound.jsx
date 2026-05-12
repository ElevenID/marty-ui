/**
 * Preview Not Found Component
 * 
 * Error page displayed when a preview resource is not found or unavailable.
 */

import { Box, Container, Paper, Typography, Button, Alert } from '@mui/material';
import ErrorOutlineIcon from '@mui/icons-material/ErrorOutline';
import ArrowBackIcon from '@mui/icons-material/ArrowBack';
import { useNavigate, useLocation } from 'react-router-dom';
import PropTypes from 'prop-types';
import { redirectBrowser, shouldBrowserRedirect } from '../../application/routing/appHandoff';

function PreviewNotFound({ resourceType = 'resource', returnUrl = '/console' }) {
  const navigate = useNavigate();
  const location = useLocation();

  const handleReturnToConsole = () => {
    if (shouldBrowserRedirect({ currentPathname: location.pathname, destination: returnUrl })) {
      redirectBrowser(returnUrl, { replace: false });
      return;
    }

    navigate(returnUrl);
  };

  const getResourceLabel = () => {
    switch (resourceType) {
      case 'credential':
        return 'Credential Template';
      case 'application':
        return 'Application Template';
      case 'flow':
        return 'Issuance Flow';
      case 'catalog':
        return 'Credential Catalog';
      default:
        return 'Resource';
    }
  };

  return (
    <Container maxWidth="md" sx={{ py: 8 }}>
      <Paper elevation={3} sx={{ p: 6, textAlign: 'center' }}>
        <ErrorOutlineIcon 
          sx={{ fontSize: 80, color: 'error.main', mb: 3 }} 
        />
        
        <Typography variant="h4" gutterBottom>
          {getResourceLabel()} Not Found
        </Typography>
        
        <Typography variant="body1" color="text.secondary" paragraph>
          The {getResourceLabel().toLowerCase()} you're trying to preview could not be found or is no longer available.
        </Typography>

        <Alert severity="info" sx={{ mt: 3, mb: 3, textAlign: 'left' }}>
          <Typography variant="body2" gutterBottom>
            <strong>Common reasons:</strong>
          </Typography>
          <Typography variant="body2" component="ul" sx={{ pl: 2, mb: 0 }}>
            <li>The {getResourceLabel().toLowerCase()} was deleted</li>
            <li>You don't have permission to view this {getResourceLabel().toLowerCase()}</li>
            <li>The URL is incorrect or outdated</li>
            <li>The {getResourceLabel().toLowerCase()} is in a draft state and not yet available</li>
          </Typography>
        </Alert>

        <Box sx={{ display: 'flex', gap: 2, justifyContent: 'center', mt: 4 }}>
          <Button
            variant="outlined"
            startIcon={<ArrowBackIcon />}
            onClick={() => navigate(-1)}
          >
            Go Back
          </Button>
          <Button
            variant="contained"
            onClick={handleReturnToConsole}
          >
            Return to Console
          </Button>
        </Box>

        {location.pathname && (
          <Typography variant="caption" color="text.secondary" sx={{ mt: 3, display: 'block' }}>
            Attempted URL: {location.pathname}
          </Typography>
        )}
      </Paper>
    </Container>
  );
}

PreviewNotFound.propTypes = {
  resourceType: PropTypes.oneOf(['credential', 'application', 'flow', 'catalog', 'resource']),
  returnUrl: PropTypes.string,
};

export default PreviewNotFound;

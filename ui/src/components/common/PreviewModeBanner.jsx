/**
 * Preview Mode Banner
 * 
 * Persistent banner displayed at the top of preview pages to clearly indicate
 * that the user is viewing an applicant-facing experience in preview mode.
 */

import { Box, Alert, Button, Typography, Chip } from '@mui/material';
import { useTranslation } from 'react-i18next';
import ExitToAppIcon from '@mui/icons-material/ExitToApp';
import VisibilityIcon from '@mui/icons-material/Visibility';
import PropTypes from 'prop-types';
import { usePreview } from '../../contexts/PreviewContext';
import { useAuth } from '../../hooks/useAuth';

function PreviewModeBanner({ contextLabel, sx = {} }) {
  const { t } = useTranslation('common');
  const { exitPreview } = usePreview();
  const { organizationName } = useAuth();

  return (
    <Box
      sx={{
        position: 'sticky',
        top: 0,
        left: 0,
        right: 0,
        zIndex: 1300, // Above AppBar (typically 1100)
        ...sx,
      }}
    >
      <Alert
        severity="warning"
        icon={<VisibilityIcon />}
        sx={{
          borderRadius: 0,
          py: 1.5,
          '& .MuiAlert-message': {
            width: '100%',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
          },
        }}
      >
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, flexWrap: 'wrap' }}>
          <Typography variant="body1" component="span" sx={{ fontWeight: 600 }}>
            {t('previewMode.title')}
          </Typography>
          <Typography variant="body2" component="span">
            {t('previewMode.description')}
          </Typography>
          {contextLabel && (
            <Chip 
              label={contextLabel} 
              size="small" 
              sx={{ bgcolor: 'warning.dark', color: 'white' }}
            />
          )}
          {organizationName && (
            <Chip 
              label={t('previewMode.org', { organizationName })} 
              size="small" 
              variant="outlined"
            />
          )}
        </Box>
        <Button
          variant="contained"
          size="small"
          startIcon={<ExitToAppIcon />}
          onClick={exitPreview}
          sx={{
            ml: 2,
            bgcolor: 'warning.dark',
            color: 'white',
            '&:hover': {
              bgcolor: 'warning.main',
            },
            whiteSpace: 'nowrap',
          }}
        >
          {t('previewMode.exitPreview')}
        </Button>
      </Alert>
    </Box>
  );
}

PreviewModeBanner.propTypes = {
  contextLabel: PropTypes.string,
  sx: PropTypes.object,
};

export default PreviewModeBanner;

/**
 * Role Selection Step Component
 * 
 * Step 1: User chooses their role (Applicant or Vendor)
 */

import { Box, Typography, Grid, Fade } from '@mui/material';
import { useTranslation } from 'react-i18next';
import PersonIcon from '@mui/icons-material/Person';
import BusinessIcon from '@mui/icons-material/Business';
import RoleCard from '../RoleCard';

const RoleSelectionStep = ({ userType, onSelectRole }) => {
  const { t } = useTranslation('onboarding');
  
  return (
    <Fade in>
      <Box data-testid="role-selection-step" id="role-selection">
        <div data-testid="role-selection">
        <Typography variant="h5" gutterBottom textAlign="center" sx={{ mb: 4 }}>
          {t('roleSelection.promptTitle')}
        </Typography>

        <Grid container spacing={4} justifyContent="center">
          <Grid item xs={12} md={5}>
            <div data-testid="role-applicant">
              <RoleCard
                role="applicant"
                title={t('roleSelection.applicant')}
                description={t('roleSelection.applicantDesc')}
                icon={PersonIcon}
                selected={userType === 'applicant'}
                onSelect={onSelectRole}
                features={t('roleSelection.applicantFeatures', { returnObjects: true })}
                testId="role-card-applicant"
              />
            </div>
          </Grid>
          <Grid item xs={12} md={5}>
            <div data-testid="role-vendor" id="role-issuer">
              <RoleCard
                role="vendor"
                title={t('roleSelection.vendor')}
                description={t('roleSelection.vendorDesc')}
                icon={BusinessIcon}
                selected={userType === 'vendor'}
                onSelect={onSelectRole}
                features={t('roleSelection.vendorFeatures', { returnObjects: true })}
                testId="role-card-vendor"
              />
            </div>
          </Grid>
        </Grid>
        </div>
      </Box>
    </Fade>
  );
};

export default RoleSelectionStep;

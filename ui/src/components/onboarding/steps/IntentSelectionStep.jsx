/**
 * Intent Selection Step Component
 * 
 * Step shown for applicants to indicate their intent:
 * - Apply for credentials (standard applicant flow)
 * - Manage credentials for organization (future vendor/issuer)
 * 
 * This helps personalize the experience and analytics.
 */

import {
  Box,
  Typography,
  Card,
  CardContent,
  CardActionArea,
  Grid,
  Fade,
  Radio,
  Chip,
} from '@mui/material';
import PersonSearchIcon from '@mui/icons-material/PersonSearch';
import AdminPanelSettingsIcon from '@mui/icons-material/AdminPanelSettings';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';

const IntentCard = ({ intent, title, description, icon: Icon, features, selected, onSelect }) => {
  return (
    <Card
      variant="outlined"
      sx={{
        height: '100%',
        borderWidth: 2,
        borderColor: selected ? 'primary.main' : 'divider',
        transition: 'all 0.2s',
        '&:hover': {
          borderColor: 'primary.main',
          transform: 'translateY(-4px)',
          boxShadow: 3,
        },
      }}
    >
      <CardActionArea
        onClick={() => onSelect(intent)}
        sx={{ height: '100%', p: 3 }}
      >
        <CardContent sx={{ p: 0 }}>
          <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
            <Radio
              checked={selected}
              value={intent}
              sx={{ mr: 1 }}
            />
            <Icon sx={{ fontSize: 40, color: 'primary.main', mr: 2 }} />
            <Box sx={{ flex: 1 }}>
              <Typography variant="h6" gutterBottom>
                {title}
              </Typography>
              {selected && (
                <Chip
                  label="Selected"
                  size="small"
                  color="primary"
                  icon={<CheckCircleIcon />}
                  sx={{ mt: 0.5 }}
                />
              )}
            </Box>
          </Box>
          <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
            {description}
          </Typography>
          <Box component="ul" sx={{ pl: 2, mt: 2 }}>
            {features.map((feature, idx) => (
              <Typography
                key={idx}
                component="li"
                variant="body2"
                color="text.secondary"
                sx={{ mb: 0.5 }}
              >
                {feature}
              </Typography>
            ))}
          </Box>
        </CardContent>
      </CardActionArea>
    </Card>
  );
};

const IntentSelectionStep = ({ roleIntent, onSelectIntent }) => {
  return (
    <Fade in>
      <Box>
        <Typography variant="h5" gutterBottom textAlign="center">
          What brings you here?
        </Typography>
        <Typography
          variant="body1"
          color="text.secondary"
          textAlign="center"
          sx={{ mb: 4 }}
        >
          Help us understand your goals so we can provide the best experience
        </Typography>

        <Grid container spacing={3} justifyContent="center">
          <Grid item xs={12} md={6}>
            <IntentCard
              intent="apply_for_credentials"
              title="Apply for Documents"
              description="I want to apply for digital travel documents like ePassports, visas, or permits"
              icon={PersonSearchIcon}
              selected={roleIntent === 'apply_for_credentials'}
              onSelect={onSelectIntent}
              features={[
                'Submit applications',
                'Upload required documents',
                'Track application status',
                'Receive digital credentials',
                'Store in secure wallet',
              ]}
            />
          </Grid>
          <Grid item xs={12} md={6}>
            <IntentCard
              intent="manage_credentials"
              title="Manage Credentials"
              description="I represent an organization that issues or verifies credentials"
              icon={AdminPanelSettingsIcon}
              selected={roleIntent === 'manage_credentials'}
              onSelect={onSelectIntent}
              features={[
                'Issue digital credentials',
                'Verify document authenticity',
                'Manage applicant workflows',
                'Access admin dashboard',
                'Configure integrations',
              ]}
            />
          </Grid>
        </Grid>

        <Box sx={{ mt: 3, textAlign: 'center' }}>
          <Typography variant="caption" color="text.secondary">
            Don&apos;t worry, you can change this later in your account settings
          </Typography>
        </Box>
      </Box>
    </Fade>
  );
};

export default IntentSelectionStep;

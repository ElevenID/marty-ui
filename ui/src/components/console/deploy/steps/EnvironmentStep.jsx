/**
 * Environment Step - Deployment Profile Wizard
 * 
 * Define the deployment environment type and network mode.
 */

import {
  Box,
  Typography,
  TextField,
  FormControl,
  RadioGroup,
  FormControlLabel,
  Radio,
  Card,
  CardContent,
  CardActionArea,
  Grid,
  Chip,
} from '@mui/material';
import ApiIcon from '@mui/icons-material/Api';
import ComputerIcon from '@mui/icons-material/Computer';
import PhoneAndroidIcon from '@mui/icons-material/PhoneAndroid';
import PublicIcon from '@mui/icons-material/Public';
import OfflineBoltIcon from '@mui/icons-material/OfflineBolt';
import { useTranslation } from 'react-i18next';

const getEnvironmentTypes = (t) => [
  {
    value: 'api',
    label: t('wizards.deploymentProfile.environmentStep.environmentTypes.api.label'),
    icon: <ApiIcon sx={{ fontSize: 48 }} />,
    description: t('wizards.deploymentProfile.environmentStep.environmentTypes.api.description'),
  },
  {
    value: 'kiosk',
    label: t('wizards.deploymentProfile.environmentStep.environmentTypes.kiosk.label'),
    icon: <ComputerIcon sx={{ fontSize: 48 }} />,
    description: t('wizards.deploymentProfile.environmentStep.environmentTypes.kiosk.description'),
  },
  {
    value: 'mobile',
    label: t('wizards.deploymentProfile.environmentStep.environmentTypes.mobile.label'),
    icon: <PhoneAndroidIcon sx={{ fontSize: 48 }} />,
    description: t('wizards.deploymentProfile.environmentStep.environmentTypes.mobile.description'),
  },
];

const EnvironmentStep = ({ data, onChange }) => {
  const { t } = useTranslation('console');

  return (
    <Box>
      <Typography variant="h6" gutterBottom>
        {t('wizards.deploymentProfile.environmentStep.title')}
      </Typography>
      <Typography color="text.secondary" paragraph>
        {t('wizards.deploymentProfile.environmentStep.description')}
      </Typography>

      {/* Name */}
      <TextField
        fullWidth
        required
        label={t('wizards.deploymentProfile.environmentStep.fields.profileName')}
        value={data.name || ''}
        onChange={(e) => onChange({ name: e.target.value })}
        sx={{ mb: 3 }}
        helperText={t('wizards.deploymentProfile.environmentStep.helpers.profileName')}
      />

      {/* Description */}
      <TextField
        fullWidth
        multiline
        rows={2}
        label={t('wizards.deploymentProfile.environmentStep.fields.description')}
        value={data.description || ''}
        onChange={(e) => onChange({ description: e.target.value })}
        sx={{ mb: 4 }}
        helperText={t('wizards.deploymentProfile.environmentStep.helpers.description')}
      />

      {/* Environment Type Selection */}
      <Typography variant="subtitle2" gutterBottom>
        {t('wizards.deploymentProfile.environmentStep.fields.environmentType')}
      </Typography>
      <Typography variant="body2" color="text.secondary" paragraph>
        {t('wizards.deploymentProfile.environmentStep.helpers.environmentType')}
      </Typography>

      <Grid container spacing={2} sx={{ mb: 4 }}>
        {getEnvironmentTypes(t).map((type) => (
          <Grid item xs={12} md={4} key={type.value}>
            <Card
              variant={data.environment_type === type.value ? 'outlined' : 'elevation'}
              sx={{
                border: data.environment_type === type.value ? 2 : 0,
                borderColor: 'primary.main',
                height: '100%',
              }}
            >
              <CardActionArea
                onClick={() => onChange({ environment_type: type.value })}
                sx={{ height: '100%' }}
              >
                <CardContent sx={{ textAlign: 'center', py: 3 }}>
                  <Box sx={{ color: data.environment_type === type.value ? 'primary.main' : 'text.secondary', mb: 2 }}>
                    {type.icon}
                  </Box>
                  <Typography variant="h6" gutterBottom>
                    {type.label}
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    {type.description}
                  </Typography>
                  {data.environment_type === type.value && (
                      <Chip label={t('wizards.deploymentProfile.environmentStep.selectedChip')} color="primary" size="small" sx={{ mt: 2 }} />
                  )}
                </CardContent>
              </CardActionArea>
            </Card>
          </Grid>
        ))}
      </Grid>

      {/* Network Mode */}
      <Typography variant="subtitle2" gutterBottom>
        {t('wizards.deploymentProfile.environmentStep.fields.networkMode')}
      </Typography>
      <FormControl component="fieldset" fullWidth>
        <RadioGroup
          value={data.network_mode || 'ONLINE'}
          onChange={(e) => onChange({ network_mode: e.target.value })}
        >
          <FormControlLabel
            value="ONLINE"
            control={<Radio />}
            label={
              <Box sx={{ ml: 1 }}>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                  <PublicIcon fontSize="small" />
                  <Typography variant="body1">{t('wizards.deploymentProfile.environmentStep.networkModes.ONLINE.label')}</Typography>
                </Box>
                <Typography variant="body2" color="text.secondary">
                  {t('wizards.deploymentProfile.environmentStep.networkModes.ONLINE.description')}
                </Typography>
              </Box>
            }
          />
          <FormControlLabel
            value="OFFLINE"
            control={<Radio />}
            label={
              <Box sx={{ ml: 1 }}>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                  <OfflineBoltIcon fontSize="small" />
                  <Typography variant="body1">{t('wizards.deploymentProfile.environmentStep.networkModes.OFFLINE.label')}</Typography>
                </Box>
                <Typography variant="body2" color="text.secondary">
                  {t('wizards.deploymentProfile.environmentStep.networkModes.OFFLINE.description')}
                </Typography>
              </Box>
            }
          />
          <FormControlLabel
            value="HYBRID"
            control={<Radio />}
            label={
              <Box sx={{ ml: 1 }}>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                  <PublicIcon fontSize="small" />
                  <OfflineBoltIcon fontSize="small" />
                  <Typography variant="body1">{t('wizards.deploymentProfile.environmentStep.networkModes.HYBRID.label')}</Typography>
                </Box>
                <Typography variant="body2" color="text.secondary">
                  {t('wizards.deploymentProfile.environmentStep.networkModes.HYBRID.description')}
                </Typography>
              </Box>
            }
          />
        </RadioGroup>
      </FormControl>
    </Box>
  );
};

export default EnvironmentStep;

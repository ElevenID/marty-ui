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

const ENVIRONMENT_TYPES = [
  {
    value: 'api',
    label: 'API Service',
    icon: <ApiIcon sx={{ fontSize: 48 }} />,
    description: 'REST API for credential issuance and verification',
  },
  {
    value: 'kiosk',
    label: 'Kiosk',
    icon: <ComputerIcon sx={{ fontSize: 48 }} />,
    description: 'Self-service kiosk at physical locations',
  },
  {
    value: 'mobile',
    label: 'Mobile Verifier',
    icon: <PhoneAndroidIcon sx={{ fontSize: 48 }} />,
    description: 'Mobile app for credential verification',
  },
];

const EnvironmentStep = ({ data, onChange }) => {
  return (
    <Box>
      <Typography variant="h6" gutterBottom>
        Environment Configuration
      </Typography>
      <Typography color="text.secondary" paragraph>
        Define where and how this deployment profile will be used.
      </Typography>

      {/* Name */}
      <TextField
        fullWidth
        required
        label="Profile Name"
        value={data.name || ''}
        onChange={(e) => onChange({ name: e.target.value })}
        sx={{ mb: 3 }}
        helperText="A descriptive name for this deployment (e.g., 'Airport Gate 5', 'Mobile Verification App')"
      />

      {/* Description */}
      <TextField
        fullWidth
        multiline
        rows={2}
        label="Description"
        value={data.description || ''}
        onChange={(e) => onChange({ description: e.target.value })}
        sx={{ mb: 4 }}
        helperText="Optional: Additional context about this deployment"
      />

      {/* Environment Type Selection */}
      <Typography variant="subtitle2" gutterBottom>
        Environment Type *
      </Typography>
      <Typography variant="body2" color="text.secondary" paragraph>
        Select the type of environment where this profile will be deployed
      </Typography>

      <Grid container spacing={2} sx={{ mb: 4 }}>
        {ENVIRONMENT_TYPES.map((type) => (
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
                    <Chip label="Selected" color="primary" size="small" sx={{ mt: 2 }} />
                  )}
                </CardContent>
              </CardActionArea>
            </Card>
          </Grid>
        ))}
      </Grid>

      {/* Network Mode */}
      <Typography variant="subtitle2" gutterBottom>
        Network Mode
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
                  <Typography variant="body1">Online</Typography>
                </Box>
                <Typography variant="body2" color="text.secondary">
                  Full cloud connectivity required
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
                  <Typography variant="body1">Offline</Typography>
                </Box>
                <Typography variant="body2" color="text.secondary">
                  No network required - uses local validation
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
                  <Typography variant="body1">Hybrid</Typography>
                </Box>
                <Typography variant="body2" color="text.secondary">
                  Syncs when network is available
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

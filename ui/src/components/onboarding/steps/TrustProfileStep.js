/**
 * Trust Profile Step Component
 * 
 * Step 1 of trust setup: Choose trust profile/framework.
 * Options: EUDI (EU Digital Identity), ICAO PKD, AAMVA, Custom X.509
 */

import React from 'react';
import {
  Box,
  Typography,
  Grid,
  Paper,
  Fade,
} from '@mui/material';
import PublicIcon from '@mui/icons-material/Public';
import FlightIcon from '@mui/icons-material/Flight';
import DirectionsCarIcon from '@mui/icons-material/DirectionsCar';
import SettingsIcon from '@mui/icons-material/Settings';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import { TrustFramework } from '../../trust/ports/types';

/**
 * Trust profile option configuration.
 */
const PROFILE_OPTIONS = [
  {
    value: TrustFramework.EUDI,
    label: 'EU Digital Identity Wallet (EUDI)',
    description: 'Use EU trusted lists and wallet-compatible certificates. Recommended for Europe.',
    icon: <PublicIcon sx={{ fontSize: 40 }} />,
    recommended: true,
    badge: 'Recommended for Europe',
  },
  {
    value: TrustFramework.ICAO,
    label: 'ICAO PKD (Passports & Travel)',
    description: 'International Civil Aviation Organization Public Key Directory for travel documents.',
    icon: <FlightIcon sx={{ fontSize: 40 }} />,
    recommended: false,
    badge: 'Travel Documents',
  },
  {
    value: TrustFramework.AAMVA,
    label: 'AAMVA (Mobile Driver\'s License)',
    description: 'American Association of Motor Vehicle Administrators for mDL credentials.',
    icon: <DirectionsCarIcon sx={{ fontSize: 40 }} />,
    recommended: false,
    badge: 'North America',
  },
  {
    value: TrustFramework.CUSTOM,
    label: 'Custom X.509 (Advanced)',
    description: 'You provide the trusted roots and validation rules. Full control over trust anchors.',
    icon: <SettingsIcon sx={{ fontSize: 40 }} />,
    recommended: false,
    badge: 'Advanced',
  },
];

/**
 * Profile option card component.
 */
const ProfileCard = ({ option, selected, onSelect, disabled }) => {
  // Handle both single value (legacy) and array (multi-select)
  const selectedArray = Array.isArray(selected) ? selected : (selected ? [selected] : []);
  const isSelected = selectedArray.includes(option.value);

  return (
    <Paper
      variant="outlined"
      onClick={() => !disabled && onSelect(option.value)}
      sx={{
        p: 3,
        cursor: disabled ? 'not-allowed' : 'pointer',
        opacity: disabled ? 0.6 : 1,
        borderColor: isSelected ? 'primary.main' : 'divider',
        borderWidth: isSelected ? 2 : 1,
        bgcolor: isSelected ? 'action.selected' : 'background.paper',
        position: 'relative',
        transition: 'all 0.2s ease',
        '&:hover': disabled ? {} : {
          borderColor: 'primary.main',
          bgcolor: 'action.hover',
        },
      }}
    >
      {/* Selected checkmark */}
      {isSelected && (
        <CheckCircleIcon
          color="primary"
          sx={{
            position: 'absolute',
            top: 12,
            right: 12,
          }}
        />
      )}

      {/* Badge */}
      {option.badge && (
        <Typography
          variant="caption"
          sx={{
            position: 'absolute',
            top: 12,
            left: 12,
            color: option.recommended ? 'primary.main' : 'text.secondary',
            fontWeight: option.recommended ? 'bold' : 'normal',
          }}
        >
          {option.badge}
        </Typography>
      )}

      <Box sx={{ textAlign: 'center', pt: option.badge ? 2 : 0 }}>
        <Box sx={{ color: isSelected ? 'primary.main' : 'text.secondary', mb: 2 }}>
          {option.icon}
        </Box>
        <Typography variant="subtitle1" fontWeight="bold" gutterBottom>
          {option.label}
        </Typography>
        <Typography variant="body2" color="text.secondary">
          {option.description}
        </Typography>
      </Box>
    </Paper>
  );
};

/**
 * Trust Profile Step Component.
 * 
 * @param {Object} props
 * @param {string[]|string} [props.selectedProfile] - Currently selected profile(s) - array for multi-select
 * @param {function} props.onProfileChange - Callback when profile is selected
 * @param {boolean} [props.disabled] - Disable selection
 */
const TrustProfileStep = ({
  selectedProfile,
  onProfileChange,
  disabled = false,
}) => {
  const selectedArray = Array.isArray(selectedProfile) ? selectedProfile : (selectedProfile ? [selectedProfile] : []);
  
  return (
    <Fade in>
      <Box data-testid="trust-profile-step">
        <Typography variant="h5" gutterBottom textAlign="center">
          Choose your trust profile
        </Typography>
        <Typography
          variant="body1"
          color="text.secondary"
          textAlign="center"
          sx={{ mb: 2 }}
        >
          Select one or more frameworks for credential verification and issuance.
        </Typography>
        <Typography
          variant="body2"
          color="primary"
          textAlign="center"
          sx={{ mb: 4, fontWeight: 'medium' }}
        >
          {selectedArray.length > 0 
            ? `${selectedArray.length} framework${selectedArray.length > 1 ? 's' : ''} selected` 
            : 'Click to select frameworks'}
        </Typography>

        <Grid container spacing={3} sx={{ maxWidth: 900, mx: 'auto' }}>
          {PROFILE_OPTIONS.map((option) => (
            <Grid item xs={12} sm={6} key={option.value}>
              <ProfileCard
                option={option}
                selected={selectedProfile}
                onSelect={onProfileChange}
                disabled={disabled}
              />
            </Grid>
          ))}
        </Grid>

        <Typography
          variant="caption"
          color="text.secondary"
          sx={{ display: 'block', textAlign: 'center', mt: 3 }}
        >
          You can change this later in Trust Registry.
        </Typography>
      </Box>
    </Fade>
  );
};

export default TrustProfileStep;

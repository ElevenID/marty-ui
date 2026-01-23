/**
 * Acceptance Context Step Component
 * 
 * Asks "Who will accept these credentials?" and "Where do you operate?"
 * to determine trust registry configuration behind the scenes.
 */

import React from 'react';
import {
  Box,
  Typography,
  Grid,
  Paper,
  Checkbox,
  Fade,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Divider,
  Alert,
} from '@mui/material';
import {
  FlightTakeoff as AirportIcon,
  Security as BorderIcon,
  LocalBar as AgeRestrictedIcon,
  Business as EmployerIcon,
  School as SchoolIcon,
  LocalPolice as LawEnforcementIcon,
  Public as EuServicesIcon,
  VpnKey as AccessControlIcon,
  DirectionsCar as VehicleRentalIcon,
  AccountBalance as EmbassyIcon,
  LocationCity as FacilitiesIcon,
  CardMembership as StudentServicesIcon,
} from '@mui/icons-material';
import { USE_CASES } from './UseCaseStep';

// Acceptance type definitions with icons and descriptions
const ACCEPTANCE_TYPES = {
  airports: {
    id: 'airports',
    label: 'Airports & Airlines',
    description: 'Airport security, airline check-in, TSA PreCheck',
    icon: AirportIcon,
    color: '#1976d2',
  },
  border_control: {
    id: 'border_control',
    label: 'Border Control',
    description: 'Immigration, customs, passport control',
    icon: BorderIcon,
    color: '#d32f2f',
  },
  age_restricted: {
    id: 'age_restricted',
    label: 'Age-Restricted Venues',
    description: 'Bars, liquor stores, tobacco shops, casinos',
    icon: AgeRestrictedIcon,
    color: '#f57c00',
  },
  employers: {
    id: 'employers',
    label: 'Employers',
    description: 'HR systems, background checks, employee verification',
    icon: EmployerIcon,
    color: '#388e3c',
  },
  schools: {
    id: 'schools',
    label: 'Schools & Universities',
    description: 'Student registration, campus access, library services',
    icon: SchoolIcon,
    color: '#7b1fa2',
  },
  law_enforcement: {
    id: 'law_enforcement',
    label: 'Law Enforcement',
    description: 'Police traffic stops, identity verification',
    icon: LawEnforcementIcon,
    color: '#0d47a1',
  },
  eu_services: {
    id: 'eu_services',
    label: 'EU Government Services',
    description: 'European government portals and services',
    icon: EuServicesIcon,
    color: '#0d47a1',
  },
  access_control: {
    id: 'access_control',
    label: 'Access Control Systems',
    description: 'Building access, door readers, security gates',
    icon: AccessControlIcon,
    color: '#c62828',
  },
  vehicle_rental: {
    id: 'vehicle_rental',
    label: 'Vehicle Rental',
    description: 'Car rental agencies, vehicle sharing services',
    icon: VehicleRentalIcon,
    color: '#2e7d32',
  },
  embassies: {
    id: 'embassies',
    label: 'Embassies & Consulates',
    description: 'Diplomatic services, visa applications',
    icon: EmbassyIcon,
    color: '#5e35b1',
  },
  facilities: {
    id: 'facilities',
    label: 'Facilities Management',
    description: 'Office buildings, secure facilities',
    icon: FacilitiesIcon,
    color: '#616161',
  },
  student_services: {
    id: 'student_services',
    label: 'Student Services',
    description: 'Student discounts, campus dining, athletics',
    icon: StudentServicesIcon,
    color: '#8e24aa',
  },
};

// Jurisdiction options organized by region
const JURISDICTIONS = {
  'North America': [
    { value: 'US', label: 'United States (All States)' },
    { value: 'US-CA', label: 'California' },
    { value: 'US-NY', label: 'New York' },
    { value: 'US-TX', label: 'Texas' },
    { value: 'US-FL', label: 'Florida' },
    { value: 'CA', label: 'Canada (All Provinces)' },
    { value: 'CA-ON', label: 'Ontario' },
    { value: 'CA-QC', label: 'Quebec' },
    { value: 'CA-BC', label: 'British Columbia' },
  ],
  'Europe': [
    { value: 'EU', label: 'European Union (All Member States)' },
    { value: 'DE', label: 'Germany' },
    { value: 'FR', label: 'France' },
    { value: 'GB', label: 'United Kingdom' },
    { value: 'NL', label: 'Netherlands' },
    { value: 'ES', label: 'Spain' },
    { value: 'IT', label: 'Italy' },
  ],
  'Asia Pacific': [
    { value: 'AU', label: 'Australia' },
    { value: 'NZ', label: 'New Zealand' },
    { value: 'JP', label: 'Japan' },
    { value: 'SG', label: 'Singapore' },
  ],
  'Global': [
    { value: 'GLOBAL', label: 'Multiple Jurisdictions' },
  ],
};

/**
 * Acceptance Type Card Component
 */
const AcceptanceCard = ({ acceptanceType, selected, onToggle, disabled }) => {
  const Icon = acceptanceType.icon;

  return (
    <Paper
      onClick={() => !disabled && onToggle(acceptanceType.id)}
      sx={{
        p: 2.5,
        cursor: disabled ? 'default' : 'pointer',
        border: '2px solid',
        borderColor: selected ? 'primary.main' : 'transparent',
        bgcolor: selected ? 'action.selected' : 'background.paper',
        opacity: disabled ? 0.6 : 1,
        transition: 'all 0.2s',
        position: 'relative',
        minHeight: 140,
        '&:hover': disabled ? {} : {
          borderColor: selected ? 'primary.main' : 'action.hover',
          bgcolor: selected ? 'action.selected' : 'action.hover',
        },
      }}
      data-testid={`acceptance-card-${acceptanceType.id}`}
    >
      <Checkbox
        checked={selected}
        disabled={disabled}
        sx={{
          position: 'absolute',
          top: 8,
          right: 8,
        }}
      />

      <Box sx={{ pr: 4 }}>
        <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
          <Icon sx={{ fontSize: 32, color: acceptanceType.color, mr: 1.5 }} />
          <Typography variant="subtitle2" fontWeight="bold">
            {acceptanceType.label}
          </Typography>
        </Box>
        <Typography variant="body2" color="text.secondary">
          {acceptanceType.description}
        </Typography>
      </Box>
    </Paper>
  );
};

/**
 * Acceptance Context Step Component
 */
const AcceptanceStep = ({
  selectedUseCases = [],
  selectedAcceptance = [],
  onAcceptanceChange,
  jurisdiction,
  onJurisdictionChange,
  disabled = false,
}) => {
  // Determine which acceptance types are relevant based on selected use cases
  const relevantAcceptanceTypes = React.useMemo(() => {
    const relevantIds = new Set();
    selectedUseCases.forEach((useCaseId) => {
      const useCase = USE_CASES.find(uc => uc.id === useCaseId);
      if (useCase) {
        useCase.acceptanceTypes.forEach(type => relevantIds.add(type));
      }
    });
    return Array.from(relevantIds)
      .map(id => ACCEPTANCE_TYPES[id])
      .filter(Boolean);
  }, [selectedUseCases]);

  const handleToggle = (acceptanceId) => {
    if (selectedAcceptance.includes(acceptanceId)) {
      onAcceptanceChange(selectedAcceptance.filter(id => id !== acceptanceId));
    } else {
      onAcceptanceChange([...selectedAcceptance, acceptanceId]);
    }
  };

  return (
    <Fade in>
      <Box data-testid="acceptance-step">
        <Typography variant="h5" gutterBottom textAlign="center">
          Who will accept these credentials?
        </Typography>
        <Typography
          variant="body1"
          color="text.secondary"
          textAlign="center"
          sx={{ mb: 4 }}
        >
          Select the verifiers and systems that will check your credentials
        </Typography>

        {relevantAcceptanceTypes.length === 0 && (
          <Alert severity="info" sx={{ mb: 3 }}>
            Please select at least one credential type in the previous step.
          </Alert>
        )}

        {relevantAcceptanceTypes.length > 0 && (
          <>
            <Grid container spacing={2} sx={{ mb: 4 }}>
              {relevantAcceptanceTypes.map((acceptanceType) => (
                <Grid item xs={12} sm={6} md={4} key={acceptanceType.id}>
                  <AcceptanceCard
                    acceptanceType={acceptanceType}
                    selected={selectedAcceptance.includes(acceptanceType.id)}
                    onToggle={handleToggle}
                    disabled={disabled}
                  />
                </Grid>
              ))}
            </Grid>

            <Divider sx={{ my: 4 }} />

            {/* Jurisdiction Selection */}
            <Box sx={{ maxWidth: 600, mx: 'auto' }}>
              <Typography variant="h6" gutterBottom textAlign="center">
                Where do you operate?
              </Typography>
              <Typography
                variant="body2"
                color="text.secondary"
                textAlign="center"
                sx={{ mb: 3 }}
              >
                Select your primary jurisdiction to configure the right compliance standards
              </Typography>

              <FormControl fullWidth data-testid="jurisdiction-select">
                <InputLabel id="jurisdiction-label">Jurisdiction</InputLabel>
                <Select
                  labelId="jurisdiction-label"
                  value={jurisdiction || ''}
                  onChange={(e) => onJurisdictionChange(e.target.value)}
                  label="Jurisdiction"
                  disabled={disabled}
                >
                  {Object.entries(JURISDICTIONS).map(([region, options]) => [
                    <MenuItem key={region} disabled sx={{ fontWeight: 'bold', fontSize: '0.875rem' }}>
                      {region}
                    </MenuItem>,
                    ...options.map((option) => (
                      <MenuItem key={option.value} value={option.value} sx={{ pl: 4 }}>
                        {option.label}
                      </MenuItem>
                    )),
                  ])}
                </Select>
              </FormControl>
            </Box>

            {selectedAcceptance.length > 0 && jurisdiction && (
              <Box sx={{ mt: 3, textAlign: 'center' }}>
                <Typography variant="body2" color="text.secondary">
                  {selectedAcceptance.length} acceptance type{selectedAcceptance.length !== 1 ? 's' : ''} selected in {JURISDICTIONS['North America'].concat(JURISDICTIONS['Europe'], JURISDICTIONS['Asia Pacific'], JURISDICTIONS['Global']).find(j => j.value === jurisdiction)?.label || jurisdiction}
                </Typography>
              </Box>
            )}
          </>
        )}
      </Box>
    </Fade>
  );
};

export default AcceptanceStep;
export { ACCEPTANCE_TYPES, JURISDICTIONS };

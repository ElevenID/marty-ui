/**
 * Use Case Selection Step Component
 * 
 * Business-focused wizard asking "What will you issue?" to abstract technical complexity.
 * Maps user selections to trust profiles behind the scenes.
 */

import React from 'react';
import {
  Box,
  Typography,
  Grid,
  Paper,
  Checkbox,
  Fade,
  Chip,
} from '@mui/material';
import {
  Flight as TravelIcon,
  DirectionsCar as DriverLicenseIcon,
  AccountBalance as EuIcon,
  Badge as EmployeeIcon,
  School as StudentIcon,
  Security as AccessIcon,
} from '@mui/icons-material';

// Use case definitions with business-friendly language
const USE_CASES = [
  {
    id: 'travel_documents',
    label: 'Travel Documents',
    description: 'Passports and travel credentials for international border crossing',
    icon: TravelIcon,
    color: '#1976d2',
    acceptanceTypes: ['airports', 'border_control', 'embassies'],
    recommended: true,
  },
  {
    id: 'driver_licenses',
    label: "Driver's Licenses",
    description: 'Mobile driver licenses and vehicle operator credentials',
    icon: DriverLicenseIcon,
    color: '#2e7d32',
    acceptanceTypes: ['law_enforcement', 'age_restricted', 'vehicle_rental'],
  },
  {
    id: 'eu_credentials',
    label: 'EU Digital Credentials',
    description: 'European digital identity wallet credentials',
    icon: EuIcon,
    color: '#0d47a1',
    acceptanceTypes: ['eu_services', 'border_control'],
    badge: 'EU Only',
  },
  {
    id: 'employee_ids',
    label: 'Employee IDs',
    description: 'Corporate employee identification and access credentials',
    icon: EmployeeIcon,
    color: '#f57c00',
    acceptanceTypes: ['employers', 'access_control'],
  },
  {
    id: 'student_ids',
    label: 'Student IDs',
    description: 'Educational institution student identification',
    icon: StudentIcon,
    color: '#7b1fa2',
    acceptanceTypes: ['schools', 'student_services'],
  },
  {
    id: 'access_badges',
    label: 'Access Badges',
    description: 'Physical and digital access control credentials',
    icon: AccessIcon,
    color: '#c62828',
    acceptanceTypes: ['access_control', 'facilities'],
  },
];

/**
 * Use Case Card Component
 */
const UseCaseCard = ({ useCase, selected, onToggle, disabled }) => {
  const Icon = useCase.icon;

  return (
    <Paper
      onClick={() => !disabled && onToggle(useCase.id)}
      sx={{
        p: 3,
        cursor: disabled ? 'default' : 'pointer',
        border: '2px solid',
        borderColor: selected ? 'primary.main' : 'transparent',
        bgcolor: selected ? 'action.selected' : 'background.paper',
        opacity: disabled ? 0.6 : 1,
        transition: 'all 0.2s',
        position: 'relative',
        '&:hover': disabled ? {} : {
          borderColor: selected ? 'primary.main' : 'action.hover',
          bgcolor: selected ? 'action.selected' : 'action.hover',
        },
      }}
      data-testid={`use-case-card-${useCase.id}`}
    >
      {/* Selection checkbox */}
      <Checkbox
        checked={selected}
        disabled={disabled}
        sx={{
          position: 'absolute',
          top: 12,
          right: 12,
        }}
        data-testid={`use-case-checkbox-${useCase.id}`}
      />

      {/* Badge */}
      {useCase.badge && (
        <Chip
          label={useCase.badge}
          size="small"
          color={useCase.recommended ? 'primary' : 'default'}
          sx={{
            position: 'absolute',
            top: 12,
            left: 12,
            fontWeight: useCase.recommended ? 'bold' : 'normal',
          }}
        />
      )}

      {/* Recommended badge */}
      {useCase.recommended && !useCase.badge && (
        <Chip
          label="Recommended"
          size="small"
          color="primary"
          sx={{
            position: 'absolute',
            top: 12,
            left: 12,
            fontWeight: 'bold',
          }}
        />
      )}

      <Box sx={{ textAlign: 'center', pt: useCase.badge || useCase.recommended ? 2 : 0 }}>
        <Box sx={{ color: useCase.color, mb: 2 }}>
          <Icon sx={{ fontSize: 48 }} />
        </Box>
        <Typography variant="subtitle1" fontWeight="bold" gutterBottom>
          {useCase.label}
        </Typography>
        <Typography variant="body2" color="text.secondary">
          {useCase.description}
        </Typography>
      </Box>
    </Paper>
  );
};

/**
 * Use Case Selection Step Component
 */
const UseCaseStep = ({
  selectedUseCases = [],
  onUseCasesChange,
  disabled = false,
}) => {
  const handleToggle = (useCaseId) => {
    if (selectedUseCases.includes(useCaseId)) {
      onUseCasesChange(selectedUseCases.filter(id => id !== useCaseId));
    } else {
      onUseCasesChange([...selectedUseCases, useCaseId]);
    }
  };

  return (
    <Fade in>
      <Box data-testid="use-case-step">
        <Typography variant="h5" gutterBottom textAlign="center">
          Who will you operate with?
        </Typography>
        <Typography
          variant="body1"
          color="text.secondary"
          textAlign="center"
          sx={{ mb: 4 }}
        >
          Select the trust profile to enable interoperability in your operating networks
        </Typography>

        <Grid container spacing={3}>
          {USE_CASES.map((useCase) => (
            <Grid item xs={12} sm={6} md={4} key={useCase.id}>
              <UseCaseCard
                useCase={useCase}
                selected={selectedUseCases.includes(useCase.id)}
                onToggle={handleToggle}
                disabled={disabled}
              />
            </Grid>
          ))}
        </Grid>

        {selectedUseCases.length > 0 && (
          <Box sx={{ mt: 3, textAlign: 'center' }}>
            <Typography variant="body2" color="text.secondary">
              {selectedUseCases.length} credential type{selectedUseCases.length !== 1 ? 's' : ''} selected
            </Typography>
          </Box>
        )}
      </Box>
    </Fade>
  );
};

export default UseCaseStep;
export { USE_CASES };

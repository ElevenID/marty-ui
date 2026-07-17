/**
 * Business Context Step Component
 * 
 * Consolidated step combining Use Cases, Acceptance Types, and Jurisdiction.
 * Asks business-focused questions to configure trust profile behind the scenes.
 */

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
  Chip,
} from '@mui/material';
import TravelIcon from '@mui/icons-material/Flight';
import DriverLicenseIcon from '@mui/icons-material/DirectionsCar';
import EuIcon from '@mui/icons-material/AccountBalance';
import EmployeeIcon from '@mui/icons-material/Badge';
import StudentIcon from '@mui/icons-material/School';
import AccessIcon from '@mui/icons-material/Security';
import AirportIcon from '@mui/icons-material/FlightTakeoff';
import BorderIcon from '@mui/icons-material/Security';
import AgeRestrictedIcon from '@mui/icons-material/LocalBar';
import EmployerIcon from '@mui/icons-material/Business';
import SchoolIcon2 from '@mui/icons-material/School';
import LawEnforcementIcon from '@mui/icons-material/LocalPolice';
import EuServicesIcon from '@mui/icons-material/Public';
import AccessControlIcon from '@mui/icons-material/VpnKey';
import VehicleRentalIcon from '@mui/icons-material/DirectionsCar';
import EmbassyIcon from '@mui/icons-material/AccountBalance';
import FacilitiesIcon from '@mui/icons-material/LocationCity';
import StudentServicesIcon from '@mui/icons-material/CardMembership';
import SchoolIcon from '@mui/icons-material/School';

// Use case definitions
const USE_CASES = [
  {
    id: 'travel_documents',
    label: 'Travel Documents',
    description: 'Passports and travel credentials',
    icon: TravelIcon,
    color: '#1976d2',
    acceptanceTypes: ['airports', 'border_control', 'embassies'],
  },
  {
    id: 'driver_licenses',
    label: "Driver's Licenses",
    description: 'Mobile driver licenses',
    icon: DriverLicenseIcon,
    color: '#2e7d32',
    acceptanceTypes: ['law_enforcement', 'age_restricted', 'vehicle_rental'],
  },
  {
    id: 'eu_credentials',
    label: 'EU Digital Credentials',
    description: 'European digital identity',
    icon: EuIcon,
    color: '#0d47a1',
    acceptanceTypes: ['eu_services', 'border_control'],
  },
  {
    id: 'employee_ids',
    label: 'Employee IDs',
    description: 'Corporate credentials',
    icon: EmployeeIcon,
    color: '#f57c00',
    acceptanceTypes: ['employers', 'access_control'],
  },
  {
    id: 'student_ids',
    label: 'Student IDs',
    description: 'Educational credentials',
    icon: StudentIcon,
    color: '#7b1fa2',
    acceptanceTypes: ['schools', 'student_services'],
  },
  {
    id: 'access_badges',
    label: 'Access Badges',
    description: 'Access control credentials',
    icon: AccessIcon,
    color: '#c62828',
    acceptanceTypes: ['access_control', 'facilities'],
  },
  {
    id: 'open_badges',
    label: 'Open Badges',
    description: 'Educational achievements, certifications, and skill badges',
    icon: SchoolIcon,
    color: '#FF6B35',
    framework: 'open_badges',
    acceptanceTypes: ['schools', 'employers', 'professional_development'],
  },
];

// Acceptance types
const ACCEPTANCE_TYPES = {
  airports: { id: 'airports', label: 'Airports & Airlines', icon: AirportIcon },
  border_control: { id: 'border_control', label: 'Border Control', icon: BorderIcon },
  age_restricted: { id: 'age_restricted', label: 'Age-Restricted Venues', icon: AgeRestrictedIcon },
  employers: { id: 'employers', label: 'Employers', icon: EmployerIcon },
  schools: { id: 'schools', label: 'Schools & Universities', icon: SchoolIcon2 },
  law_enforcement: { id: 'law_enforcement', label: 'Law Enforcement', icon: LawEnforcementIcon },
  eu_services: { id: 'eu_services', label: 'EU Government Services', icon: EuServicesIcon },
  access_control: { id: 'access_control', label: 'Access Control Systems', icon: AccessControlIcon },
  vehicle_rental: { id: 'vehicle_rental', label: 'Vehicle Rental', icon: VehicleRentalIcon },
  embassies: { id: 'embassies', label: 'Embassies & Consulates', icon: EmbassyIcon },
  facilities: { id: 'facilities', label: 'Facilities Management', icon: FacilitiesIcon },
  student_services: { id: 'student_services', label: 'Student Services', icon: StudentServicesIcon },
  professional_development: { id: 'professional_development', label: 'Professional Development', icon: SchoolIcon },
};

// Jurisdictions
const JURISDICTIONS = [
  { value: 'US', label: 'United States' },
  { value: 'US-CA', label: 'California, USA' },
  { value: 'US-NY', label: 'New York, USA' },
  { value: 'CA', label: 'Canada' },
  { value: 'UK', label: 'United Kingdom' },
  { value: 'EU', label: 'European Union' },
  { value: 'DE', label: 'Germany' },
  { value: 'FR', label: 'France' },
  { value: 'NL', label: 'Netherlands' },
  { value: 'AU', label: 'Australia' },
  { value: 'NZ', label: 'New Zealand' },
  { value: 'SG', label: 'Singapore' },
  { value: 'GLOBAL', label: 'Global / Multiple' },
];

/**
 * Use Case Card Component
 */
const UseCaseCard = ({ useCase, selected, onToggle }) => {
  const Icon = useCase.icon;

  return (
    <Paper
      onClick={() => onToggle(useCase.id)}
      sx={{
        p: 2.5,
        cursor: 'pointer',
        border: '2px solid',
        borderColor: selected ? 'primary.main' : 'transparent',
        bgcolor: selected ? 'action.selected' : 'background.paper',
        transition: 'all 0.2s',
        '&:hover': {
          borderColor: selected ? 'primary.main' : 'action.hover',
          boxShadow: 2,
        },
      }}
    >
      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5, mb: 1 }}>
        <Checkbox checked={selected} sx={{ p: 0 }} />
        <Icon sx={{ fontSize: 32, color: useCase.color }} />
        <Box sx={{ flexGrow: 1 }}>
          <Typography variant="subtitle2" fontWeight="bold">
            {useCase.label}
          </Typography>
          <Typography variant="caption" color="text.secondary">
            {useCase.description}
          </Typography>
        </Box>
      </Box>
    </Paper>
  );
};

/**
 * Acceptance Type Card Component
 */
const AcceptanceCard = ({ type, selected, onToggle }) => {
  const Icon = type.icon;

  return (
    <Paper
      onClick={() => onToggle(type.id)}
      sx={{
        p: 2,
        cursor: 'pointer',
        border: '1px solid',
        borderColor: selected ? 'primary.main' : 'divider',
        bgcolor: selected ? 'action.selected' : 'background.paper',
        transition: 'all 0.2s',
        '&:hover': {
          borderColor: 'primary.main',
          boxShadow: 1,
        },
      }}
    >
      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
        <Checkbox checked={selected} size="small" sx={{ p: 0 }} />
        <Icon sx={{ fontSize: 24, color: 'text.secondary' }} />
        <Typography variant="body2" fontWeight={selected ? 'bold' : 'normal'}>
          {type.label}
        </Typography>
      </Box>
    </Paper>
  );
};

/**
 * Business Context Step Component
 */
const BusinessContextStep = ({
  selectedUseCases = [],
  onUseCasesChange,
  selectedAcceptance = [],
  onAcceptanceChange,
  jurisdiction = '',
  onJurisdictionChange,
}) => {
  const handleUseCaseToggle = (id) => {
    if (selectedUseCases.includes(id)) {
      onUseCasesChange(selectedUseCases.filter((u) => u !== id));
    } else {
      onUseCasesChange([...selectedUseCases, id]);
    }
  };

  const handleAcceptanceToggle = (id) => {
    if (selectedAcceptance.includes(id)) {
      onAcceptanceChange(selectedAcceptance.filter((a) => a !== id));
    } else {
      onAcceptanceChange([...selectedAcceptance, id]);
    }
  };

  // Get recommended acceptance types based on selected use cases
  const recommendedAcceptance = new Set(
    USE_CASES.filter((uc) => selectedUseCases.includes(uc.id))
      .flatMap((uc) => uc.acceptanceTypes)
  );

  const acceptanceTypes = Object.values(ACCEPTANCE_TYPES);

  return (
    <Fade in>
      <Box data-testid="business-context-step">
        <Typography variant="h5" gutterBottom textAlign="center">
          Tell us about your business
        </Typography>
        <Typography variant="body1" color="text.secondary" textAlign="center" sx={{ mb: 4 }}>
          Help us configure the right trust settings for your needs
        </Typography>

        <Box sx={{ maxWidth: 900, mx: 'auto' }}>
          {/* Section 1: Use Cases */}
          <Typography variant="h6" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            1. Who will you operate with?
          </Typography>
          <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
            Select all credential types you&apos;ll issue or verify
          </Typography>

          <Grid container spacing={2} sx={{ mb: 4 }}>
            {USE_CASES.map((useCase) => (
              <Grid item xs={12} sm={6} key={useCase.id}>
                <UseCaseCard
                  useCase={useCase}
                  selected={selectedUseCases.includes(useCase.id)}
                  onToggle={handleUseCaseToggle}
                />
              </Grid>
            ))}
          </Grid>

          <Divider sx={{ my: 4 }} />

          {/* Section 2: Acceptance Types */}
          <Typography variant="h6" gutterBottom>
            2. Who will accept these credentials?
          </Typography>
          <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
            Select the types of organizations that will verify your credentials
          </Typography>

          {recommendedAcceptance.size > 0 && (
            <Alert severity="info" sx={{ mb: 2 }}>
              <Typography variant="body2">
                Based on your selections, we recommend:{' '}
                {Array.from(recommendedAcceptance).map((id) => (
                  <Chip
                    key={id}
                    label={ACCEPTANCE_TYPES[id]?.label}
                    size="small"
                    sx={{ ml: 0.5 }}
                  />
                ))}
              </Typography>
            </Alert>
          )}

          <Grid container spacing={1.5} sx={{ mb: 4 }}>
            {acceptanceTypes.map((type) => (
              <Grid item xs={12} sm={6} md={4} key={type.id}>
                <AcceptanceCard
                  type={type}
                  selected={selectedAcceptance.includes(type.id)}
                  onToggle={handleAcceptanceToggle}
                />
              </Grid>
            ))}
          </Grid>

          <Divider sx={{ my: 4 }} />

          {/* Section 3: Jurisdiction */}
          <Typography variant="h6" gutterBottom>
            3. Where do you operate?
          </Typography>
          <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
            Select your primary jurisdiction for compliance and trust framework selection
          </Typography>

          <FormControl fullWidth>
            <InputLabel>Jurisdiction</InputLabel>
            <Select
              value={jurisdiction}
              onChange={(e) => onJurisdictionChange(e.target.value)}
              label="Jurisdiction"
            >
              {JURISDICTIONS.map((j) => (
                <MenuItem key={j.value} value={j.value}>
                  {j.label}
                </MenuItem>
              ))}
            </Select>
          </FormControl>
        </Box>
      </Box>
    </Fade>
  );
};

export default BusinessContextStep;

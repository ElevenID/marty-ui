/**
 * Preconditions Step
 * 
 * Configure preconditions that must be met before the flow automatically advances.
 * Specifically for OID4VCI issuance flows - controls when credential offers are automatically generated.
 */

import { useState, useEffect } from 'react';
import {
  Box,
  Typography,
  Card,
  CardContent,
  FormGroup,
  FormControlLabel,
  Checkbox,
  Alert,
  Chip,
  Stack,
  Divider,
  Paper,
} from '@mui/material';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import GppGoodIcon from '@mui/icons-material/GppGood';
import AdminPanelSettingsIcon from '@mui/icons-material/AdminPanelSettings';
import VerifiedIcon from '@mui/icons-material/Verified';
import HelpOutlineIcon from '@mui/icons-material/HelpOutline';

// Available preconditions
const PRECONDITION_TYPES = [
  {
    id: 'application_approved',
    label: 'Application Approved',
    description: 'Automatically trigger when an applicant\'s credential application is approved',
    icon: <CheckCircleIcon />,
    color: 'success',
    recommended: true,
  },
  {
    id: 'identity_verified',
    label: 'Identity Verified',
    description: 'Require successful identity verification (biometric, document scan, etc.)',
    icon: <GppGoodIcon />,
    color: 'primary',
    recommended: true,
  },
  {
    id: 'manual_admin_approval',
    label: 'Manual Admin Approval',
    description: 'Require explicit admin action to proceed with issuance',
    icon: <AdminPanelSettingsIcon />,
    color: 'warning',
    recommended: false,
  },
  {
    id: 'external_verification',
    label: 'External Verification Result',
    description: 'Wait for external system verification callback (webhook/API)',
    icon: <VerifiedIcon />,
    color: 'info',
    recommended: false,
  },
];

const PreconditionsStep = ({ flowType, preconditions = [], onUpdate }) => {
  const [selectedPreconditions, setSelectedPreconditions] = useState(preconditions);

  // Initialize with defaults for OID4VCI flows
  useEffect(() => {
    if (flowType === 'issuance_oid4vci' && preconditions.length === 0) {
      // Default to application_approved for OID4VCI flows
      setSelectedPreconditions(['application_approved']);
      onUpdate({ preconditions: ['application_approved'] });
    }
  }, [flowType, preconditions.length, onUpdate]);

  const handleTogglePrecondition = (preconditionId) => {
    const newPreconditions = selectedPreconditions.includes(preconditionId)
      ? selectedPreconditions.filter(id => id !== preconditionId)
      : [...selectedPreconditions, preconditionId];
    
    setSelectedPreconditions(newPreconditions);
    onUpdate({ preconditions: newPreconditions });
  };

  const isOID4VCIFlow = flowType === 'issuance_oid4vci';
  const isPreconditionSelected = (id) => selectedPreconditions.includes(id);

  return (
    <Box>
      <Typography variant="h6" gutterBottom>
        Configure Preconditions
      </Typography>
      
      <Typography color="text.secondary" paragraph>
        {isOID4VCIFlow 
          ? 'Define when credential offers should be automatically generated. Select one or more conditions that must be met before proceeding.'
          : 'Configure preconditions for this flow type.'
        }
      </Typography>

      {!isOID4VCIFlow && (
        <Alert severity="info" sx={{ mb: 3 }}>
          Precondition configuration is currently optimized for OID4VCI issuance flows. 
          Other flow types may have limited precondition support.
        </Alert>
      )}

      {/* Precondition Selection */}
      <Card sx={{ mb: 3 }}>
        <CardContent>
          <Typography variant="subtitle1" gutterBottom sx={{ fontWeight: 600, mb: 2 }}>
            Select Preconditions
          </Typography>

          <FormGroup>
            {PRECONDITION_TYPES.map((precondition) => (
              <Paper
                key={precondition.id}
                elevation={isPreconditionSelected(precondition.id) ? 3 : 0}
                sx={{
                  mb: 2,
                  p: 2,
                  border: 2,
                  borderColor: isPreconditionSelected(precondition.id) 
                    ? `${precondition.color}.main` 
                    : 'divider',
                  cursor: 'pointer',
                  transition: 'all 0.2s',
                  '&:hover': {
                    borderColor: `${precondition.color}.light`,
                    bgcolor: 'action.hover',
                  },
                }}
                onClick={() => handleTogglePrecondition(precondition.id)}
              >
                <Box sx={{ display: 'flex', alignItems: 'flex-start' }}>
                  <FormControlLabel
                    control={
                      <Checkbox
                        checked={isPreconditionSelected(precondition.id)}
                        onChange={() => handleTogglePrecondition(precondition.id)}
                        onClick={(e) => e.stopPropagation()}
                        color={precondition.color}
                      />
                    }
                    label=""
                    sx={{ mr: 2 }}
                  />
                  
                  <Box sx={{ flex: 1 }}>
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 0.5 }}>
                      <Box sx={{ color: `${precondition.color}.main` }}>
                        {precondition.icon}
                      </Box>
                      <Typography variant="body1" sx={{ fontWeight: 600 }}>
                        {precondition.label}
                      </Typography>
                      {precondition.recommended && (
                        <Chip 
                          label="Recommended" 
                          size="small" 
                          color="success" 
                          variant="outlined"
                        />
                      )}
                    </Box>
                    
                    <Typography variant="body2" color="text.secondary">
                      {precondition.description}
                    </Typography>
                  </Box>
                </Box>
              </Paper>
            ))}
          </FormGroup>
        </CardContent>
      </Card>

      {/* Configuration Summary */}
      {selectedPreconditions.length > 0 && (
        <Alert severity="info" icon={<HelpOutlineIcon />}>
          <Typography variant="body2" gutterBottom sx={{ fontWeight: 600 }}>
            Selected Configuration ({selectedPreconditions.length} condition{selectedPreconditions.length > 1 ? 's' : ''})
          </Typography>
          <Typography variant="body2" paragraph>
            {selectedPreconditions.length === 1 
              ? 'The flow will automatically advance when the selected condition is met.'
              : 'The flow will automatically advance when ALL selected conditions are met (AND logic).'}
          </Typography>
          
          <Divider sx={{ my: 1 }} />
          
          <Stack direction="row" spacing={1} sx={{ mt: 1, flexWrap: 'wrap', gap: 1 }}>
            {selectedPreconditions.map(id => {
              const precondition = PRECONDITION_TYPES.find(p => p.id === id);
              return precondition ? (
                <Chip
                  key={id}
                  label={precondition.label}
                  color={precondition.color}
                  size="small"
                  icon={precondition.icon}
                />
              ) : null;
            })}
          </Stack>
        </Alert>
      )}

      {selectedPreconditions.length === 0 && (
        <Alert severity="warning">
          <Typography variant="body2">
            No preconditions selected. The flow will require manual triggering or external orchestration.
          </Typography>
        </Alert>
      )}
    </Box>
  );
};

export default PreconditionsStep;

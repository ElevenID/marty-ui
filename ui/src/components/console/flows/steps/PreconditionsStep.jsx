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
import { useTranslation } from 'react-i18next';

// Available preconditions
const getPreconditionTypes = (t) => [
  {
    id: 'application_approved',
    label: t('wizards.flowDefinition.preconditionsStep.types.application_approved.label'),
    description: t('wizards.flowDefinition.preconditionsStep.types.application_approved.description'),
    icon: <CheckCircleIcon />,
    color: 'success',
    recommended: true,
  },
  {
    id: 'identity_verified',
    label: t('wizards.flowDefinition.preconditionsStep.types.identity_verified.label'),
    description: t('wizards.flowDefinition.preconditionsStep.types.identity_verified.description'),
    icon: <GppGoodIcon />,
    color: 'primary',
    recommended: true,
  },
  {
    id: 'manual_admin_approval',
    label: t('wizards.flowDefinition.preconditionsStep.types.manual_admin_approval.label'),
    description: t('wizards.flowDefinition.preconditionsStep.types.manual_admin_approval.description'),
    icon: <AdminPanelSettingsIcon />,
    color: 'warning',
    recommended: false,
  },
  {
    id: 'external_verification',
    label: t('wizards.flowDefinition.preconditionsStep.types.external_verification.label'),
    description: t('wizards.flowDefinition.preconditionsStep.types.external_verification.description'),
    icon: <VerifiedIcon />,
    color: 'info',
    recommended: false,
  },
];

const PreconditionsStep = ({ flowType, preconditions = [], onUpdate }) => {
  const { t } = useTranslation('console');
  const [selectedPreconditions, setSelectedPreconditions] = useState(preconditions);
  const PRECONDITION_TYPES = getPreconditionTypes(t);

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
        {t('wizards.flowDefinition.preconditionsStep.title')}
      </Typography>
      
      <Typography color="text.secondary" paragraph>
        {isOID4VCIFlow 
          ? t('wizards.flowDefinition.preconditionsStep.descriptionOid4vci')
          : t('wizards.flowDefinition.preconditionsStep.descriptionDefault')
        }
      </Typography>

      {!isOID4VCIFlow && (
        <Alert severity="info" sx={{ mb: 3 }}>
          {t('wizards.flowDefinition.preconditionsStep.limitedSupport')}
        </Alert>
      )}

      {/* Precondition Selection */}
      <Card sx={{ mb: 3 }}>
        <CardContent>
          <Typography variant="subtitle1" gutterBottom sx={{ fontWeight: 600, mb: 2 }}>
            {t('wizards.flowDefinition.preconditionsStep.selectTitle')}
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
                          label={t('wizards.flowDefinition.preconditionsStep.recommendedChip')} 
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
            {t('wizards.flowDefinition.preconditionsStep.summaryTitle', { count: selectedPreconditions.length })}
          </Typography>
          <Typography variant="body2" paragraph>
            {selectedPreconditions.length === 1 
              ? t('wizards.flowDefinition.preconditionsStep.summarySingle')
              : t('wizards.flowDefinition.preconditionsStep.summaryMultiple')}
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
            {t('wizards.flowDefinition.preconditionsStep.noneSelected')}
          </Typography>
        </Alert>
      )}
    </Box>
  );
};

export default PreconditionsStep;

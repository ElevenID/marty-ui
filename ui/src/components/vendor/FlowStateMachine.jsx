/**
 * Flow State Machine Visualization
 * 
 * Visual representation of the application flow states from submission to credential issuance.
 */

import { useTranslation } from 'react-i18next';
import {
  Box,
  Paper,
  Typography,
  Stepper,
  Step,
  StepLabel,
  StepContent,
  Chip,
} from '@mui/material';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import HourglassEmptyIcon from '@mui/icons-material/HourglassEmpty';
import CancelIcon from '@mui/icons-material/Cancel';
import PropTypes from 'prop-types';

const getFlowSteps = (t) => [
  {
    label: t('flowStateMachine.steps.submitted.label'),
    description: t('flowStateMachine.steps.submitted.description'),
    status: 'submitted',
  },
  {
    label: t('flowStateMachine.steps.underReview.label'),
    description: t('flowStateMachine.steps.underReview.description'),
    status: 'under_review',
  },
  {
    label: t('flowStateMachine.steps.approved.label'),
    description: t('flowStateMachine.steps.approved.description'),
    status: 'approved',
  },
  {
    label: t('flowStateMachine.steps.qrIssued.label'),
    description: t('flowStateMachine.steps.qrIssued.description'),
    status: 'qr_issued',
  },
  {
    label: t('flowStateMachine.steps.credentialIssued.label'),
    description: t('flowStateMachine.steps.credentialIssued.description'),
    status: 'credential_issued',
  },
];

function FlowStateMachine({ currentStatus = 'submitted', isRejected = false, sx = {} }) {
  const { t } = useTranslation('vendor');
  const FLOW_STEPS = getFlowSteps(t);
  const getCurrentStep = () => {
    if (isRejected) return -1;
    const index = FLOW_STEPS.findIndex(step => step.status === currentStatus);
    return index >= 0 ? index : 0;
  };

  const activeStep = getCurrentStep();

  const getStepIcon = (index) => {
    if (isRejected) {
      return <CancelIcon color="error" />;
    }
    if (index < activeStep) {
      return <CheckCircleIcon color="success" />;
    }
    if (index === activeStep) {
      return <HourglassEmptyIcon color="primary" />;
    }
    return null;
  };

  return (
    <Paper elevation={1} sx={{ p: 3, ...sx }}>
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
        <Typography variant="h6">{t('flowStateMachine.title')}</Typography>
        {isRejected ? (
          <Chip label={t('flowStateMachine.rejected')} color="error" size="small" />
        ) : (
          <Chip 
            label={FLOW_STEPS[activeStep]?.label || t('flowStateMachine.unknown')} 
            color="primary" 
            size="small" 
          />
        )}
      </Box>

      {isRejected ? (
        <Box sx={{ textAlign: 'center', py: 3 }}>
          <CancelIcon sx={{ fontSize: 60, color: 'error.main', mb: 2 }} />
          <Typography variant="h6" color="error">
            {t('flowStateMachine.applicationRejected')}
          </Typography>
          <Typography variant="body2" color="text.secondary">
            {t('flowStateMachine.rejectionMessage')}
          </Typography>
        </Box>
      ) : (
        <Stepper activeStep={activeStep} orientation="vertical">
          {FLOW_STEPS.map((step, index) => (
            <Step key={step.status}>
              <StepLabel
                StepIconComponent={() => getStepIcon(index)}
                optional={
                  index === FLOW_STEPS.length - 1 && (
                    <Typography variant="caption">{t('flowStateMachine.finalStep')}</Typography>
                  )
                }
              >
                {step.label}
              </StepLabel>
              <StepContent>
                <Typography variant="body2" color="text.secondary">
                  {step.description}
                </Typography>
              </StepContent>
            </Step>
          ))}
        </Stepper>
      )}
    </Paper>
  );
}

FlowStateMachine.propTypes = {
  currentStatus: PropTypes.oneOf([
    'submitted',
    'under_review',
    'approved',
    'qr_issued',
    'credential_issued',
  ]),
  isRejected: PropTypes.bool,
  sx: PropTypes.object,
};

export default FlowStateMachine;

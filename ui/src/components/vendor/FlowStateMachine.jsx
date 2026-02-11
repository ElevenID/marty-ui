/**
 * Flow State Machine Visualization
 * 
 * Visual representation of the application flow states from submission to credential issuance.
 */

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

const FLOW_STEPS = [
  {
    label: 'Submitted',
    description: 'Application received and validated',
    status: 'submitted',
  },
  {
    label: 'Under Review',
    description: 'Application is being reviewed by approver',
    status: 'under_review',
  },
  {
    label: 'Approved',
    description: 'Application approved, ready for credential issuance',
    status: 'approved',
  },
  {
    label: 'QR Issued',
    description: 'QR code generated for credential claim',
    status: 'qr_issued',
  },
  {
    label: 'Credential Issued',
    description: 'Credential successfully issued to applicant',
    status: 'credential_issued',
  },
];

function FlowStateMachine({ currentStatus = 'submitted', isRejected = false, sx = {} }) {
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
        <Typography variant="h6">Application Flow</Typography>
        {isRejected ? (
          <Chip label="Rejected" color="error" size="small" />
        ) : (
          <Chip 
            label={FLOW_STEPS[activeStep]?.label || 'Unknown'} 
            color="primary" 
            size="small" 
          />
        )}
      </Box>

      {isRejected ? (
        <Box sx={{ textAlign: 'center', py: 3 }}>
          <CancelIcon sx={{ fontSize: 60, color: 'error.main', mb: 2 }} />
          <Typography variant="h6" color="error">
            Application Rejected
          </Typography>
          <Typography variant="body2" color="text.secondary">
            This application did not meet approval criteria
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
                    <Typography variant="caption">Final Step</Typography>
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

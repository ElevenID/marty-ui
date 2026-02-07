/**
 * Credential Flow Diagram
 * 
 * Interactive visualization of the credential lifecycle:
 * Issue → Hold → Present → Verify
 */

import { Box, Paper, Typography, useTheme } from '@mui/material';

function CredentialFlowDiagram({ interactive = true }) {
  const theme = useTheme();

  const steps = [
    {
      label: 'Issue',
      description: 'Issuer creates and signs credential',
      color: theme.palette.primary.main,
    },
    {
      label: 'Hold',
      description: 'Holder stores credential in wallet',
      color: theme.palette.secondary.main,
    },
    {
      label: 'Present',
      description: 'Holder presents credential to verifier',
      color: theme.palette.success.main,
    },
    {
      label: 'Verify',
      description: 'Verifier validates credential and trust',
      color: theme.palette.warning.main,
    },
  ];

  return (
    <Box
      sx={{
        display: 'flex',
        flexDirection: { xs: 'column', md: 'row' },
        alignItems: 'center',
        justifyContent: 'space-around',
        gap: 3,
        p: 4,
      }}
    >
      {steps.map((step, index) => (
        <Box
          key={step.label}
          sx={{
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'center',
            flex: 1,
            position: 'relative',
          }}
        >
          {/* Arrow connector */}
          {index < steps.length - 1 && (
            <Box
              sx={{
                display: { xs: 'none', md: 'block' },
                position: 'absolute',
                right: '-24px',
                top: '50%',
                transform: 'translateY(-50%)',
                width: '48px',
                height: '2px',
                bgcolor: 'divider',
                '&::after': {
                  content: '""',
                  position: 'absolute',
                  right: 0,
                  top: '50%',
                  transform: 'translateY(-50%)',
                  width: 0,
                  height: 0,
                  borderTop: '6px solid transparent',
                  borderBottom: '6px solid transparent',
                  borderLeft: `6px solid ${theme.palette.divider}`,
                },
              }}
            />
          )}

          {/* Step circle */}
          <Paper
            elevation={interactive ? 4 : 2}
            sx={{
              width: 120,
              height: 120,
              borderRadius: '50%',
              display: 'flex',
              flexDirection: 'column',
              alignItems: 'center',
              justifyContent: 'center',
              bgcolor: step.color,
              color: 'white',
              transition: 'all 0.3s ease',
              cursor: interactive ? 'pointer' : 'default',
              '&:hover': interactive ? {
                transform: 'scale(1.1)',
                elevation: 8,
              } : {},
            }}
          >
            <Typography variant="h5" fontWeight="bold">
              {step.label}
            </Typography>
          </Paper>

          {/* Step description */}
          <Typography
            variant="body2"
            color="text.secondary"
            sx={{ mt: 2, textAlign: 'center', maxWidth: 180 }}
          >
            {step.description}
          </Typography>
        </Box>
      ))}
    </Box>
  );
}

export default CredentialFlowDiagram;

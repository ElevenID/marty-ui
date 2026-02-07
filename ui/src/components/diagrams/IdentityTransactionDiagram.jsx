/**
 * Identity Transaction Diagram
 * 
 * Visualizes identity as a transaction answering three questions:
 * Authenticity, Binding, Appropriateness
 */

import { Box, Paper, Typography, useTheme } from '@mui/material';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';

function IdentityTransactionDiagram({ interactive = true }) {
  const theme = useTheme();

  const questions = [
    {
      question: 'Authenticity',
      description: 'Who issued this claim, and do I trust them?',
      color: theme.palette.primary.main,
    },
    {
      question: 'Binding',
      description: 'Is the presenter the legitimate holder?',
      color: theme.palette.secondary.main,
    },
    {
      question: 'Appropriateness',
      description: 'Is the information disclosed sufficient—and no more?',
      color: theme.palette.success.main,
    },
  ];

  const flow = [
    'Verifier requests proof',
    'Holder presents proof',
    'Verifier validates trust',
    'Relying party decides',
  ];

  return (
    <Box sx={{ p: 4 }}>
      {/* Three Questions */}
      <Typography variant="h5" fontWeight="bold" textAlign="center" gutterBottom>
        Identity Answers Three Questions
      </Typography>

      <Box
        sx={{
          display: 'grid',
          gridTemplateColumns: { xs: '1fr', md: '1fr 1fr 1fr' },
          gap: 3,
          mb: 6,
          mt: 3,
        }}
      >
        {questions.map((item, index) => (
          <Paper
            key={item.question}
            elevation={interactive ? 3 : 1}
            sx={{
              p: 3,
              textAlign: 'center',
              transition: 'all 0.3s ease',
              cursor: interactive ? 'pointer' : 'default',
              borderLeft: `6px solid ${item.color}`,
              '&:hover': interactive ? {
                transform: 'scale(1.05)',
                elevation: 6,
              } : {},
            }}
          >
            <Box
              sx={{
                display: 'inline-flex',
                alignItems: 'center',
                justifyContent: 'center',
                width: 48,
                height: 48,
                borderRadius: '50%',
                bgcolor: item.color,
                color: 'white',
                mb: 2,
                fontWeight: 'bold',
                fontSize: '1.5rem',
              }}
            >
              {index + 1}
            </Box>
            <Typography variant="h6" fontWeight="bold" gutterBottom color={item.color}>
              {item.question}
            </Typography>
            <Typography variant="body2" color="text.secondary">
              {item.description}
            </Typography>
          </Paper>
        ))}
      </Box>

      {/* Transaction Flow */}
      <Typography variant="h5" fontWeight="bold" textAlign="center" gutterBottom sx={{ mt: 6 }}>
        Identity as Transaction
      </Typography>

      <Box
        sx={{
          display: 'flex',
          flexDirection: { xs: 'column', md: 'row' },
          alignItems: 'center',
          justifyContent: 'center',
          gap: 2,
          mt: 3,
        }}
      >
        {flow.map((step, index) => (
          <Box
            key={step}
            sx={{
              display: 'flex',
              alignItems: 'center',
              gap: 2,
            }}
          >
            <Paper
              elevation={2}
              sx={{
                p: 2,
                minWidth: 200,
                textAlign: 'center',
                bgcolor: theme.palette.grey[50],
              }}
            >
              <Typography variant="body1" fontWeight="medium">
                {step}
              </Typography>
            </Paper>

            {index < flow.length - 1 && (
              <Box
                sx={{
                  display: { xs: 'none', md: 'block' },
                  color: theme.palette.primary.main,
                }}
              >
                <CheckCircleIcon />
              </Box>
            )}
          </Box>
        ))}
      </Box>
    </Box>
  );
}

export default IdentityTransactionDiagram;

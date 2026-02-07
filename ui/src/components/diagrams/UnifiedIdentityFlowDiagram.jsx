/**
 * Unified Identity Flow Diagram
 * 
 * Canonical end-to-end visualization showing:
 * - Four primitives (Issuer, Holder, Verifier, Trust Registry)
 * - Complete flow (Issue → Hold → Present → Verify)
 * - Three questions (Who says? Says what? Who checks?)
 * 
 * This is the master reference diagram used across all pages
 */

import { Box, Paper, Typography, useTheme, Divider } from '@mui/material';
import ArrowForwardIcon from '@mui/icons-material/ArrowForward';
import VerifiedUserIcon from '@mui/icons-material/VerifiedUser';
import AccountBalanceIcon from '@mui/icons-material/AccountBalance';
import PersonIcon from '@mui/icons-material/Person';
import PolicyIcon from '@mui/icons-material/Policy';

function UnifiedIdentityFlowDiagram({ interactive = true }) {
  const theme = useTheme();

  const actors = [
    {
      id: 'issuer',
      label: 'Issuer',
      icon: <AccountBalanceIcon sx={{ fontSize: 48 }} />,
      question: 'Who says?',
      description: 'Creates and signs credentials',
      example: 'DMV issues driver\u2019s license',
      color: theme.palette.primary.main,
    },
    {
      id: 'holder',
      label: 'Holder',
      icon: <PersonIcon sx={{ fontSize: 48 }} />,
      question: 'Says what?',
      description: 'Stores and presents credentials',
      example: 'You store license in wallet',
      color: theme.palette.secondary.main,
    },
    {
      id: 'verifier',
      label: 'Verifier',
      icon: <VerifiedUserIcon sx={{ fontSize: 48 }} />,
      question: 'Who checks?',
      description: 'Validates credentials and trust',
      example: 'Bar checks your age',
      color: theme.palette.success.main,
    },
    {
      id: 'trustRegistry',
      label: 'Trust Registry',
      icon: <PolicyIcon sx={{ fontSize: 48 }} />,
      question: 'Who to trust?',
      description: 'Defines which issuers are trusted',
      example: 'State maintains list of valid DMVs',
      color: theme.palette.warning.main,
    },
  ];

  const flowSteps = [
    { label: '1. Issue', from: 'Issuer', to: 'Holder', description: 'Issuer creates signed credential' },
    { label: '2. Hold', actor: 'Holder', description: 'Holder stores credential in wallet' },
    { label: '3. Present', from: 'Holder', to: 'Verifier', description: 'Holder shares credential' },
    { label: '4. Verify', actor: 'Verifier', description: 'Verifier checks signature + trust' },
    { label: '5. Trust Check', from: 'Verifier', to: 'Trust Registry', description: 'Is issuer authorized?' },
  ];

  return (
    <Box sx={{ width: '100%' }}>
      {/* Title */}
      <Typography variant="h5" fontWeight="bold" gutterBottom textAlign="center" sx={{ mb: 4 }}>
        Complete Identity Flow: The Four Actors
      </Typography>

      {/* Four Actors */}
      <Box
        sx={{
          display: 'grid',
          gridTemplateColumns: { xs: '1fr', sm: '1fr 1fr', lg: '1fr 1fr 1fr 1fr' },
          gap: 3,
          mb: 4,
        }}
      >
        {actors.map((actor) => (
          <Paper
            key={actor.id}
            elevation={interactive ? 2 : 1}
            sx={{
              p: 3,
              textAlign: 'center',
              borderTop: 4,
              borderColor: actor.color,
              transition: 'all 0.3s ease',
              ...(interactive && {
                '&:hover': {
                  transform: 'translateY(-4px)',
                  boxShadow: theme.shadows[6],
                },
              }),
            }}
          >
            <Box sx={{ color: actor.color, mb: 1 }}>
              {actor.icon}
            </Box>
            <Typography variant="h6" fontWeight="bold" gutterBottom>
              {actor.label}
            </Typography>
            <Typography variant="body2" color="primary" fontWeight="bold" sx={{ mb: 1, fontStyle: 'italic' }}>
              {actor.question}
            </Typography>
            <Typography variant="body2" paragraph>
              {actor.description}
            </Typography>
            <Typography variant="caption" color="text.secondary" sx={{ fontStyle: 'italic' }}>
              Example: {actor.example}
            </Typography>
          </Paper>
        ))}
      </Box>

      <Divider sx={{ my: 4 }} />

      {/* Flow Sequence */}
      <Typography variant="h6" fontWeight="bold" gutterBottom textAlign="center" sx={{ mb: 3 }}>
        Transaction Flow
      </Typography>

      <Box
        sx={{
          display: 'flex',
          flexDirection: 'column',
          gap: 2,
          maxWidth: 800,
          mx: 'auto',
        }}
      >
        {flowSteps.map((step, index) => (
          <Paper
            key={index}
            elevation={1}
            sx={{
              p: 2,
              display: 'flex',
              alignItems: 'center',
              gap: 2,
              bgcolor: index % 2 === 0 ? 'grey.50' : 'white',
            }}
          >
            <Box
              sx={{
                minWidth: 40,
                height: 40,
                borderRadius: '50%',
                bgcolor: 'primary.main',
                color: 'white',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                fontWeight: 'bold',
              }}
            >
              {index + 1}
            </Box>
            <Box sx={{ flex: 1 }}>
              <Typography variant="subtitle1" fontWeight="bold">
                {step.label}
              </Typography>
              <Typography variant="body2" color="text.secondary">
                {step.description}
              </Typography>
            </Box>
            {step.from && step.to && (
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, minWidth: 150 }}>
                <Typography variant="caption" fontWeight="bold">
                  {step.from}
                </Typography>
                <ArrowForwardIcon fontSize="small" color="primary" />
                <Typography variant="caption" fontWeight="bold">
                  {step.to}
                </Typography>
              </Box>
            )}
          </Paper>
        ))}
      </Box>

      {/* Key Insight */}
      <Paper elevation={0} sx={{ p: 3, mt: 4, bgcolor: 'info.light', borderLeft: 4, borderColor: 'info.main' }}>
        <Typography variant="body1" fontWeight="bold" gutterBottom>
          Key Insight:
        </Typography>
        <Typography variant="body2">
          The <strong>Trust Registry</strong> is what makes this system work at scale. Without it, every verifier 
          would need to manually configure which issuers they trust. With it, trust decisions are centralized, 
          auditable, and can be updated without changing verifier code.
        </Typography>
      </Paper>
    </Box>
  );
}

export default UnifiedIdentityFlowDiagram;

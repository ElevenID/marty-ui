/**
 * Trust Model Diagram
 * 
 * Visualizes the four primitives + Flow orchestration model:
 * Trust Profile, Credential Template, Presentation Policy, Deployment Profile
 */

import { Box, Paper, Typography, useTheme } from '@mui/material';
import VerifiedUserIcon from '@mui/icons-material/VerifiedUser';
import DescriptionIcon from '@mui/icons-material/Description';
import PolicyIcon from '@mui/icons-material/Policy';
import DevicesIcon from '@mui/icons-material/Devices';
import AccountTreeIcon from '@mui/icons-material/AccountTree';

function TrustModelDiagram({ interactive = true }) {
  const theme = useTheme();

  const primitives = [
    {
      icon: <VerifiedUserIcon sx={{ fontSize: 40 }} />,
      label: 'Trust Profile',
      description: 'Who is trusted & how crypto is validated',
      color: theme.palette.primary.main,
    },
    {
      icon: <DescriptionIcon sx={{ fontSize: 40 }} />,
      label: 'Credential Template',
      description: 'What is issued & schema + semantics',
      color: theme.palette.secondary.main,
    },
    {
      icon: <PolicyIcon sx={{ fontSize: 40 }} />,
      label: 'Presentation Policy',
      description: 'What must be shown & minimum disclosure',
      color: theme.palette.success.main,
    },
    {
      icon: <DevicesIcon sx={{ fontSize: 40 }} />,
      label: 'Deployment Profile',
      description: 'Where it runs & device/site behavior',
      color: theme.palette.warning.main,
    },
  ];

  return (
    <Box sx={{ p: 4 }}>
      {/* Primitives Grid */}
      <Box
        sx={{
          display: 'grid',
          gridTemplateColumns: { xs: '1fr', sm: '1fr 1fr', md: '1fr 1fr 1fr 1fr' },
          gap: 3,
          mb: 4,
        }}
      >
        {primitives.map((primitive) => (
          <Paper
            key={primitive.label}
            elevation={interactive ? 3 : 1}
            sx={{
              p: 3,
              textAlign: 'center',
              transition: 'all 0.3s ease',
              cursor: interactive ? 'pointer' : 'default',
              borderTop: `4px solid ${primitive.color}`,
              '&:hover': interactive ? {
                transform: 'translateY(-4px)',
                elevation: 6,
              } : {},
            }}
          >
            <Box sx={{ color: primitive.color, mb: 1 }}>
              {primitive.icon}
            </Box>
            <Typography variant="subtitle1" fontWeight="bold" gutterBottom>
              {primitive.label}
            </Typography>
            <Typography variant="body2" color="text.secondary">
              {primitive.description}
            </Typography>
          </Paper>
        ))}
      </Box>

      {/* Flow Orchestration */}
      <Box sx={{ textAlign: 'center', mt: 4 }}>
        <Box
          sx={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: 2,
            mb: 2,
          }}
        >
          <Box
            sx={{
              width: 80,
              height: 2,
              bgcolor: 'divider',
            }}
          />
          <Typography variant="h6" color="text.secondary">
            orchestrated by
          </Typography>
          <Box
            sx={{
              width: 80,
              height: 2,
              bgcolor: 'divider',
            }}
          />
        </Box>

        <Paper
          elevation={4}
          sx={{
            display: 'inline-block',
            p: 3,
            bgcolor: theme.palette.info.main,
            color: 'white',
          }}
        >
          <AccountTreeIcon sx={{ fontSize: 48, mb: 1 }} />
          <Typography variant="h5" fontWeight="bold">
            Flow
          </Typography>
          <Typography variant="body2" sx={{ mt: 1 }}>
            Apply → Issue → Present → Verify
          </Typography>
        </Paper>
      </Box>
    </Box>
  );
}

export default TrustModelDiagram;

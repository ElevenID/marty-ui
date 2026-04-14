import { Box, Paper, Typography } from '@mui/material';
import ArrowDownwardIcon from '@mui/icons-material/ArrowDownward';
import AccountBalanceIcon from '@mui/icons-material/AccountBalance';
import PhoneIphoneIcon from '@mui/icons-material/PhoneIphone';
import VerifiedUserIcon from '@mui/icons-material/VerifiedUser';
import PolicyIcon from '@mui/icons-material/Policy';

const NODES = [
  {
    id: 'issuer-service',
    title: 'Issuer Service',
    subtitle: 'Credential Issue',
    accent: '#8ec5ff',
    icon: <AccountBalanceIcon sx={{ fontSize: 30 }} />,
  },
  {
    id: 'wallet',
    title: 'Wallet',
    subtitle: 'Holder',
    accent: '#6ee7b7',
    icon: <PhoneIphoneIcon sx={{ fontSize: 30 }} />,
  },
  {
    id: 'verification-api',
    title: 'Verification API',
    subtitle: 'ElevenID Core',
    accent: '#fbbf24',
    icon: <VerifiedUserIcon sx={{ fontSize: 30 }} />,
  },
  {
    id: 'trust-registry',
    title: 'Trust Registry',
    subtitle: 'PKI / Trust Lists',
    accent: '#fda4af',
    icon: <PolicyIcon sx={{ fontSize: 30 }} />,
  },
];

const CONNECTORS = ['Signed Credential', 'Proof', 'Trust Check'];

function DeploymentModelDiagram() {
  return (
    <Box sx={{ width: '100%' }}>
      <Typography variant="overline" sx={{ display: 'block', textAlign: 'center', letterSpacing: 1.4, color: 'rgba(255,255,255,0.66)' }}>
        Deployment model diagram
      </Typography>
      <Box sx={{ maxWidth: 360, mx: 'auto', mt: 2.5 }}>
        {NODES.map((node, index) => (
          <Box key={node.id}>
            <Paper
              elevation={0}
              sx={{
                p: 2.25,
                mx: 'auto',
                borderRadius: 3,
                bgcolor: 'rgba(255,255,255,0.96)',
                border: '1px solid rgba(255,255,255,0.18)',
                boxShadow: '0 16px 40px rgba(0, 0, 0, 0.18)',
                maxWidth: 300,
              }}
            >
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5 }}>
                <Box
                  sx={{
                    width: 46,
                    height: 46,
                    borderRadius: 2,
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    bgcolor: node.accent,
                    color: '#071427',
                    flexShrink: 0,
                  }}
                >
                  {node.icon}
                </Box>
                <Box>
                  <Typography variant="subtitle1" fontWeight={800} color="text.primary">
                    {node.title}
                  </Typography>
                  <Typography variant="body2" sx={{ color: 'text.secondary' }}>
                    {node.subtitle}
                  </Typography>
                </Box>
              </Box>
            </Paper>

            {index < CONNECTORS.length && (
              <Box sx={{ display: 'flex', flexDirection: 'column', alignItems: 'center', py: 1.4 }}>
                <Typography
                  variant="caption"
                  sx={{
                    px: 1.25,
                    py: 0.45,
                    borderRadius: 999,
                    bgcolor: 'rgba(255,255,255,0.12)',
                    color: 'rgba(255,255,255,0.82)',
                    letterSpacing: 0.3,
                  }}
                >
                  {CONNECTORS[index]}
                </Typography>
                <ArrowDownwardIcon sx={{ mt: 0.6, color: 'rgba(255,255,255,0.84)' }} />
              </Box>
            )}
          </Box>
        ))}
      </Box>
    </Box>
  );
}

export default DeploymentModelDiagram;
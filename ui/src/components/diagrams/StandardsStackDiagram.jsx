/**
 * Standards Stack Diagram
 * 
 * Visualizes standards grouped by layer:
 * Identity, Credentials, Transport, Governance
 */

import { Box, Paper, Typography, Chip, useTheme } from '@mui/material';

function StandardsStackDiagram({ interactive = true }) {
  const theme = useTheme();

  const layers = [
    {
      layer: 'Identity Standards',
      description: 'Foundation for identity frameworks',
      standards: ['ICAO 9303', 'eIDAS', 'EUDI Wallet'],
      color: theme.palette.primary.main,
    },
    {
      layer: 'Credential Formats',
      description: 'How credentials are structured',
      standards: ['mDoc (ISO 18013-5)', 'SD-JWT', 'W3C VC', 'JSON-LD'],
      color: theme.palette.secondary.main,
    },
    {
      layer: 'Transport Protocols',
      description: 'How credentials are exchanged',
      standards: ['OpenID4VP', 'OpenID4VCI', 'QR/NFC/BLE'],
      color: theme.palette.success.main,
    },
    {
      layer: 'Trust & Governance',
      description: 'How trust is established',
      standards: ['PKI', 'ICAO PKD', 'Trust Lists', 'AAMVA', 'X.509'],
      color: theme.palette.warning.main,
    },
  ];

  return (
    <Box sx={{ p: 4 }}>
      <Box
        sx={{
          display: 'flex',
          flexDirection: 'column',
          gap: 2,
          maxWidth: 900,
          mx: 'auto',
        }}
      >
        {layers.map((layer, index) => (
          <Paper
            key={layer.layer}
            elevation={interactive ? 3 : 1}
            sx={{
              p: 3,
              transition: 'all 0.3s ease',
              cursor: interactive ? 'pointer' : 'default',
              borderLeft: `6px solid ${layer.color}`,
              '&:hover': interactive ? {
                transform: 'translateX(8px)',
                elevation: 6,
              } : {},
            }}
          >
            <Box
              sx={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                mb: 2,
                flexWrap: 'wrap',
                gap: 2,
              }}
            >
              <Box>
                <Typography variant="h6" fontWeight="bold" color={layer.color}>
                  {layer.layer}
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  {layer.description}
                </Typography>
              </Box>

              <Chip
                label={`Layer ${index + 1}`}
                size="small"
                sx={{
                  bgcolor: layer.color,
                  color: 'white',
                  fontWeight: 'bold',
                }}
              />
            </Box>

            <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1 }}>
              {layer.standards.map((standard) => (
                <Chip
                  key={standard}
                  label={standard}
                  variant="outlined"
                  size="small"
                  sx={{
                    borderColor: layer.color,
                    color: layer.color,
                    '&:hover': interactive ? {
                      bgcolor: layer.color,
                      color: 'white',
                    } : {},
                  }}
                />
              ))}
            </Box>
          </Paper>
        ))}
      </Box>

      {/* Bottom note */}
      <Typography
        variant="body2"
        color="text.secondary"
        textAlign="center"
        sx={{ mt: 4, fontStyle: 'italic' }}
      >
        Standards ensure portability, trust, and long-term viability
      </Typography>
    </Box>
  );
}

export default StandardsStackDiagram;

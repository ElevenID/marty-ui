/**
 * API Documentation Component
 * 
 * Embeds ReDoc to display professional OpenAPI documentation
 * from the gateway API. Publicly accessible without authentication.
 */

import { useEffect, useRef, useState } from 'react';
import { Box, Typography, Paper, Grid, Card, CardContent, Divider, Chip, Button, Collapse } from '@mui/material';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import ExpandLessIcon from '@mui/icons-material/ExpandLess';
import VerifiedUserIcon from '@mui/icons-material/VerifiedUser';
import FlightTakeoffIcon from '@mui/icons-material/FlightTakeoff';
import AccountTreeIcon from '@mui/icons-material/AccountTree';

function ApiDocumentation() {
  const containerRef = useRef(null);
  const redocInstanceRef = useRef(null);
  const [showGuide, setShowGuide] = useState(true);

  useEffect(() => {
    let mounted = true;

    const initRedoc = () => {
      if (!mounted || !containerRef.current) return;
      
      // Only initialize if not already done
      if (redocInstanceRef.current) return;

      if (window.Redoc) {
        try {
          // Create a new div that React won't touch
          const redocDiv = document.createElement('div');
          containerRef.current.appendChild(redocDiv);
          
          window.Redoc.init(
            '/openapi.json',
            {
              scrollYOffset: 80,
              hideDownloadButton: false,
              disableSearch: false,
              theme: {
                colors: {
                  primary: {
                    main: '#1976d2',
                  },
                },
                typography: {
                  fontSize: '14px',
                  fontFamily: '"Roboto", "Helvetica", "Arial", sans-serif',
                },
              },
            },
            redocDiv
          );
          
          redocInstanceRef.current = true;
        } catch (error) {
          console.error('Failed to initialize ReDoc:', error);
        }
      }
    };

    // Check if ReDoc is already available
    if (window.Redoc) {
      initRedoc();
    } else {
      // Load the ReDoc script
      const script = document.createElement('script');
      script.src = 'https://cdn.redoc.ly/redoc/latest/bundles/redoc.standalone.js';
      script.async = true;
      script.onload = () => {
        if (mounted) {
          initRedoc();
        }
      };
      script.onerror = () => {
        console.error('Failed to load ReDoc script');
      };
      document.head.appendChild(script);
    }

    return () => {
      mounted = false;
    };
  }, []);

  return (
    <Box sx={{ 
      width: '100vw', 
      backgroundColor: '#fff',
      position: 'relative',
      left: '50%',
      right: '50%',
      marginLeft: '-50vw',
      marginRight: '-50vw',
    }}>
      {/* Orientation Header */}
      <Paper elevation={0} sx={{ p: 4, bgcolor: 'grey.50', borderBottom: 1, borderColor: 'divider' }}>
        <Typography variant="h4" fontWeight="bold" gutterBottom>
          API Reference
        </Typography>
        <Typography variant="body1" color="text.secondary" paragraph sx={{ maxWidth: 900 }}>
          <strong>ElevenID implements digital identity as governed configuration.</strong>{' '}
          Instead of hard-coding trust, disclosure, and verification logic into applications, 
          ElevenID models identity using five composable primitives—then executes them consistently 
          across wallets, APIs, kiosks, and offline environments.
        </Typography>

        <Button 
          size="small" 
          onClick={() => setShowGuide(!showGuide)}
          endIcon={showGuide ? <ExpandLessIcon /> : <ExpandMoreIcon />}
          sx={{ mb: 2 }}
        >
          {showGuide ? 'Hide' : 'Show'} Quick Start Guide
        </Button>

        <Collapse in={showGuide}>
          {/* Model Map */}
          <Paper elevation={1} sx={{ p: 2, mb: 3, bgcolor: 'white', fontFamily: 'monospace' }}>
            <Typography variant="subtitle2" fontWeight="bold" gutterBottom color="primary">
              The Model
            </Typography>
            <Box sx={{ display: 'grid', gridTemplateColumns: 'auto 1fr', gap: 0.5, fontSize: '0.875rem' }}>
              <Typography variant="body2" fontWeight="bold">Trust Profile</Typography>
              <Typography variant="body2" color="text.secondary">→ Who is trusted</Typography>
              <Typography variant="body2" fontWeight="bold">Credential Template</Typography>
              <Typography variant="body2" color="text.secondary">→ What is issued</Typography>
              <Typography variant="body2" fontWeight="bold">Presentation Policy</Typography>
              <Typography variant="body2" color="text.secondary">→ What must be shown</Typography>
              <Typography variant="body2" fontWeight="bold">Deployment Profile</Typography>
              <Typography variant="body2" color="text.secondary">→ Where it runs</Typography>
              <Typography variant="body2" fontWeight="bold">Flow</Typography>
              <Typography variant="body2" color="text.secondary">→ How it all executes</Typography>
            </Box>
          </Paper>

          {/* Choose Your Path */}
          <Typography variant="subtitle1" fontWeight="bold" gutterBottom>
            Choose Your Path
          </Typography>
          <Grid container spacing={2} sx={{ mb: 3 }}>
            <Grid item xs={12} md={4}>
              <Card elevation={1} sx={{ height: '100%' }}>
                <CardContent>
                  <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1 }}>
                    <VerifiedUserIcon color="primary" />
                    <Typography variant="subtitle2" fontWeight="bold">
                      Start with Verification
                    </Typography>
                    <Chip label="Most common" size="small" color="primary" variant="outlined" />
                  </Box>
                  <Typography variant="body2" color="text.secondary" component="ol" sx={{ pl: 2, mb: 0 }}>
                    <li>Create Organization</li>
                    <li>Create Trust Profile</li>
                    <li>Create Presentation Policy</li>
                    <li>Call <code>/presentation-policies/&#123;id&#125;/evaluate</code></li>
                  </Typography>
                </CardContent>
              </Card>
            </Grid>
            <Grid item xs={12} md={4}>
              <Card elevation={1} sx={{ height: '100%' }}>
                <CardContent>
                  <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1 }}>
                    <FlightTakeoffIcon color="secondary" />
                    <Typography variant="subtitle2" fontWeight="bold">
                      Start with Issuance
                    </Typography>
                  </Box>
                  <Typography variant="body2" color="text.secondary" component="ol" sx={{ pl: 2, mb: 0 }}>
                    <li>Create Organization</li>
                    <li>Create Trust Profile</li>
                    <li>Create Credential Template</li>
                    <li>Issue via <code>/issuance</code></li>
                  </Typography>
                </CardContent>
              </Card>
            </Grid>
            <Grid item xs={12} md={4}>
              <Card elevation={1} sx={{ height: '100%' }}>
                <CardContent>
                  <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1 }}>
                    <AccountTreeIcon color="warning" />
                    <Typography variant="subtitle2" fontWeight="bold">
                      Full Flow (wallet + QR)
                    </Typography>
                  </Box>
                  <Typography variant="body2" color="text.secondary" component="ol" sx={{ pl: 2, mb: 0 }}>
                    <li>Create Trust Profile</li>
                    <li>Create Credential Template</li>
                    <li>Create Presentation Policy</li>
                    <li>Create Flow, call <code>/flows/verify</code></li>
                  </Typography>
                </CardContent>
              </Card>
            </Grid>
          </Grid>

          {/* Verification Modes */}
          <Divider sx={{ my: 2 }} />
          <Typography variant="subtitle2" fontWeight="bold" gutterBottom>
            Verification Modes
          </Typography>
          <Box sx={{ display: 'flex', gap: 2, flexWrap: 'wrap', mb: 2 }}>
            <Paper elevation={0} sx={{ p: 1.5, bgcolor: 'grey.100', borderRadius: 1 }}>
              <Typography variant="body2">
                <strong>Stateless API:</strong> <code>/presentation-policies/&#123;id&#125;/evaluate</code>
              </Typography>
              <Typography variant="caption" color="text.secondary">
                Backend verification without user interaction
              </Typography>
            </Paper>
            <Paper elevation={0} sx={{ p: 1.5, bgcolor: 'grey.100', borderRadius: 1 }}>
              <Typography variant="body2">
                <strong>Wallet / QR flows:</strong> <code>/flows/verify</code>
              </Typography>
              <Typography variant="caption" color="text.secondary">
                User-presented wallet credentials via QR/NFC
              </Typography>
            </Paper>
          </Box>

          {/* Clarifications */}
          <Divider sx={{ my: 2 }} />
          <Typography variant="caption" color="text.secondary" component="div" sx={{ lineHeight: 1.6 }}>
            <strong>Note on Application Templates:</strong> Application Templates define how users apply for credentials. 
            They are only required for application-based issuance—not for direct or batch issuance.
          </Typography>
          <Typography variant="caption" color="text.secondary" component="div" sx={{ mt: 1, lineHeight: 1.6 }}>
            <strong>Full lifecycle:</strong> See the &quot;Getting Started&quot; section in the API reference below for 
            end-to-end issuance and verification workflows.
          </Typography>
        </Collapse>
      </Paper>

      {/* ReDoc Container */}
      <Box
        sx={{
          width: '100%',
          minHeight: 'calc(100vh - 64px)',
          pb: 16,
          '& > div': {
            paddingBottom: '4rem',
          },
          // Sticky search bar
          '& .redoc-wrap .search-box, & [role="search"]': {
            position: 'sticky',
            top: 0,
            zIndex: 10,
            backgroundColor: '#fff',
          },
        }}
      >
        <div ref={containerRef} />
      </Box>
    </Box>
  );
}

export default ApiDocumentation;

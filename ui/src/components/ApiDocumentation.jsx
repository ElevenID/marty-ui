/**
 * API Documentation Component
 * 
 * Embeds ReDoc to display professional OpenAPI documentation
 * from the gateway API. Publicly accessible without authentication.
 */

import { useEffect, useRef, useState } from 'react';
import { Box, Typography, Paper, Grid, Card, CardContent, Divider, Chip, Button, Collapse, Alert, AlertTitle, Stack, Link as MuiLink } from '@mui/material';
import { SEOHead } from './seo';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import ExpandLessIcon from '@mui/icons-material/ExpandLess';
import VerifiedUserIcon from '@mui/icons-material/VerifiedUser';
import FlightTakeoffIcon from '@mui/icons-material/FlightTakeoff';
import AccountTreeIcon from '@mui/icons-material/AccountTree';

function ApiDocumentation() {
  const containerRef = useRef(null);
  const redocInstanceRef = useRef(null);
  const [showGuide, setShowGuide] = useState(true);
  const [redocError, setRedocError] = useState(null);
  const [specUrlInUse, setSpecUrlInUse] = useState(null);

  useEffect(() => {
    let mounted = true;
    const redocScriptCandidates = [
      'https://cdn.redoc.ly/redoc/latest/bundles/redoc.standalone.js',
      'https://cdn.jsdelivr.net/npm/redoc@next/bundles/redoc.standalone.js',
    ];
    const openApiCandidates = [
      import.meta.env.VITE_OPENAPI_URL,
      '/openapi.json',
    ].filter(Boolean);

    const isOpenApiReachable = async (url) => {
      try {
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 7000);
        const response = await fetch(url, {
          method: 'GET',
          headers: {
            Accept: 'application/json, application/yaml, text/yaml, */*',
          },
          signal: controller.signal,
        });
        clearTimeout(timeout);
        return response.ok;
      } catch {
        return false;
      }
    };

    const initRedoc = (openApiUrl) => {
      if (!mounted || !containerRef.current) return;
      
      // Only initialize if not already done
      if (redocInstanceRef.current) return;

      if (window.Redoc) {
        try {
          // Create a new div that React won't touch
          const redocDiv = document.createElement('div');
          containerRef.current.appendChild(redocDiv);
          
          window.Redoc.init(
            openApiUrl,
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
          setRedocError('ReDoc loaded, but API schema rendering failed.');
          console.error('Failed to initialize ReDoc:', error);
        }
      }
    };

    const loadRedocScript = async () => {
      if (window.Redoc) return true;

      for (const src of redocScriptCandidates) {
        const existing = document.querySelector(`script[src="${src}"]`);
        if (existing && window.Redoc) return true;

        const loaded = await new Promise((resolve) => {
          const script = document.createElement('script');
          script.src = src;
          script.async = true;
          script.onload = () => resolve(true);
          script.onerror = () => resolve(false);
          document.head.appendChild(script);
        });

        if (loaded && window.Redoc) return true;
      }

      return false;
    };

    const boot = async () => {
      const reachableSpec = (await Promise.all(
        openApiCandidates.map(async (candidate) => ({
          candidate,
          ok: await isOpenApiReachable(candidate),
        }))
      )).find((result) => result.ok)?.candidate;

      if (!mounted) return;

      if (!reachableSpec) {
        setRedocError('OpenAPI schema is not publicly reachable in this environment (expected endpoint returned 403/404).');
        return;
      }

      setSpecUrlInUse(reachableSpec);

      const scriptLoaded = await loadRedocScript();
      if (!mounted) return;

      if (!scriptLoaded) {
        setRedocError('Unable to load ReDoc JavaScript bundle (CDN blocked or unavailable).');
        return;
      }

      initRedoc(reachableSpec);
    };

    boot();

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
      <SEOHead
        title="Verifiable Credential API Documentation"
        description="API reference for credential issuance, verification, trust profiles, presentation policies, and identity flow orchestration."
        canonicalPath="/docs"
        keywords={['API documentation', 'verifiable credential API', 'identity API reference', 'presentation policy API']}
      />

      {/* Orientation Header */}
      <Paper elevation={0} sx={{ p: 4, bgcolor: 'grey.50', borderBottom: 1, borderColor: 'divider' }}>
        <Typography variant="h3" component="h1" fontWeight="bold" gutterBottom>
          Verifiable Credential API Documentation
        </Typography>
        <Typography variant="body1" color="text.secondary" paragraph sx={{ maxWidth: 900 }}>
          <strong>ElevenID LLC implements digital identity as governed configuration.</strong>{' '}
          Instead of hard-coding trust, disclosure, and verification logic into applications, 
          ElevenID LLC models identity using five composable primitives—then executes them consistently 
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
        {redocError && (
          <Paper elevation={0} sx={{ maxWidth: 980, mx: 'auto', mt: 3, p: 2 }}>
            <Alert severity="warning" sx={{ mb: 2 }}>
              <AlertTitle>Interactive API docs are temporarily unavailable</AlertTitle>
              {redocError}
            </Alert>
            <Typography variant="body2" color="text.secondary" sx={{ mb: 1.5 }}>
              This beta environment is currently running in tunnel/dev mode. If the gateway blocks
              the schema endpoint or external script CDNs, the embedded viewer cannot render.
            </Typography>
            <Stack direction={{ xs: 'column', sm: 'row' }} spacing={1.5}>
              <Button variant="outlined" size="small" component="a" href="/openapi.json" target="_blank" rel="noopener noreferrer">
                Try /openapi.json
              </Button>
              <Button variant="outlined" size="small" component="a" href="http://localhost:8000/docs" target="_blank" rel="noopener noreferrer">
                Local gateway docs
              </Button>
            </Stack>
            {specUrlInUse && (
              <Typography variant="caption" color="text.secondary" sx={{ mt: 1.5, display: 'block' }}>
                Last reachable schema URL: <MuiLink href={specUrlInUse}>{specUrlInUse}</MuiLink>
              </Typography>
            )}
          </Paper>
        )}
        <div ref={containerRef} />
      </Box>
    </Box>
  );
}

export default ApiDocumentation;

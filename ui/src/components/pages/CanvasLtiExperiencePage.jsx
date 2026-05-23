import { useEffect, useMemo, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import {
  Alert,
  Box,
  Button,
  Chip,
  CircularProgress,
  Container,
  Paper,
  Stack,
  Typography,
} from '@mui/material';
import ArrowForwardIcon from '@mui/icons-material/ArrowForward';
import SchoolIcon from '@mui/icons-material/School';

import { get } from '../../services/api';
import { useAuth } from '../../hooks/useAuth';

function compactRoles(roles = []) {
  return roles
    .map((role) => String(role).split('/').pop())
    .filter(Boolean)
    .slice(0, 3);
}

function sessionValue(session, key) {
  return (
    session?.[key]
    || session?.mip_primitives?.context?.[key]
    || session?.verified_launch?.[key]
    || null
  );
}

function buildCanvasContinuePath(session, state) {
  const query = new URLSearchParams({ canvas_lti_state: state });
  const canvasProgramBindingId = sessionValue(session, 'canvas_program_binding_id');
  const canvasPlatformId = sessionValue(session, 'canvas_platform_id');
  const applicationTemplateId = sessionValue(session, 'application_template_id');
  const credentialTemplateId = sessionValue(session, 'credential_template_id');

  if (canvasProgramBindingId) query.set('canvas_program_binding_id', canvasProgramBindingId);
  if (canvasPlatformId) query.set('canvas_platform_id', canvasPlatformId);
  if (applicationTemplateId) query.set('application_template_id', applicationTemplateId);

  if (credentialTemplateId) {
    return `/console/applicant/apply/${encodeURIComponent(credentialTemplateId)}?${query.toString()}`;
  }

  return `/console/applicant/catalog?${query.toString()}`;
}

function buildCanvasLtiSessionPath(state, nextPath) {
  const query = new URLSearchParams({
    state,
    redirect_uri: nextPath,
  });
  return `/v1/auth/canvas-lti/finalize?${query.toString()}`;
}

function CanvasLtiExperiencePage() {
  const [searchParams] = useSearchParams();
  const { isLoading: authLoading = false } = useAuth() || {};
  const state = searchParams.get('state') || '';
  const [session, setSession] = useState(null);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(Boolean(state));

  useEffect(() => {
    let alive = true;
    async function loadSession() {
      if (!state) {
        setError('Canvas launch state is missing.');
        setLoading(false);
        return;
      }
      try {
        const data = await get(`/v1/integrations/canvas/lti/experience-sessions/${encodeURIComponent(state)}`);
        if (alive) {
          setSession(data);
          setError('');
        }
      } catch (err) {
        if (alive) {
          setError(err?.message || 'Canvas launch could not be opened.');
        }
      } finally {
        if (alive) {
          setLoading(false);
        }
      }
    }
    loadSession();
    return () => {
      alive = false;
    };
  }, [state]);

  const verifiedLaunch = session?.verified_launch || {};
  const context = verifiedLaunch.context || {};
  const learner = verifiedLaunch.learner_identity || {};
  const roles = useMemo(() => compactRoles(verifiedLaunch.roles), [verifiedLaunch.roles]);
  const nextPath = buildCanvasContinuePath(session, state);
  const canvasSessionPath = buildCanvasLtiSessionPath(state, nextPath);
  const canvasProgramBindingId = sessionValue(session, 'canvas_program_binding_id');
  const credentialTemplateId = sessionValue(session, 'credential_template_id');
  const continueButtonProps = {
    component: 'a',
    href: canvasSessionPath,
    target: '_top',
    rel: 'noreferrer',
  };

  return (
    <Box
      component="main"
      data-testid="canvas-lti-login-page"
      sx={{
        bgcolor: 'background.default',
        minHeight: '100vh',
        display: 'flex',
        alignItems: 'center',
        py: { xs: 3, md: 6 },
      }}
    >
      <Container maxWidth="sm">
        <Paper
          elevation={0}
          sx={{
            border: '1px solid',
            borderColor: 'divider',
            borderRadius: 2,
            p: { xs: 3, md: 4 },
            boxShadow: '0 18px 48px rgba(15, 23, 42, 0.08)',
          }}
        >
          {loading ? (
            <Stack alignItems="center" spacing={2} sx={{ py: 6 }}>
              <CircularProgress size={42} />
              <Typography color="text.secondary">Opening Canvas sign-in...</Typography>
            </Stack>
          ) : error ? (
            <Stack spacing={3} alignItems="stretch">
              <Stack spacing={0.75}>
                <Typography variant="overline" color="primary" sx={{ fontWeight: 700 }}>
                  ElevenID LLC
                </Typography>
                <Typography variant="h5">Canvas sign-in unavailable</Typography>
              </Stack>
              <Alert severity="error">{error}</Alert>
              <Button component="a" href="/" target="_top" variant="outlined">
                Return to ElevenID
              </Button>
            </Stack>
          ) : (
            <Stack spacing={3} alignItems="stretch">
              <Stack spacing={2} alignItems="center" textAlign="center">
                <Typography variant="overline" color="primary" sx={{ fontWeight: 700 }}>
                  ElevenID LLC
                </Typography>
                <Box
                  sx={{
                    width: 52,
                    height: 52,
                    borderRadius: '50%',
                    bgcolor: 'primary.main',
                    color: 'primary.contrastText',
                    display: 'grid',
                    placeItems: 'center',
                  }}
                >
                  <SchoolIcon />
                </Box>
                <Stack spacing={0.75}>
                  <Typography variant="h4" sx={{ fontSize: { xs: '1.65rem', md: '2rem' } }}>
                    Continue with Canvas
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    Canvas launch verified
                  </Typography>
                </Stack>
              </Stack>

              <Stack
                spacing={1}
                sx={{
                  py: 2,
                  borderTop: '1px solid',
                  borderBottom: '1px solid',
                  borderColor: 'divider',
                }}
              >
                <Typography variant="caption" color="text.secondary" sx={{ textTransform: 'uppercase', fontWeight: 700 }}>
                  Course
                </Typography>
                <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>
                  {context.title || context.label || context.id || 'Canvas Course'}
                </Typography>
              </Stack>

              <Stack direction="row" spacing={1} useFlexGap flexWrap="wrap">
                {learner.subject || verifiedLaunch.subject ? (
                  <Chip label={`Canvas user ${learner.subject || verifiedLaunch.subject}`} />
                ) : null}
                {session?.organization_id ? <Chip label={`Org ${session.organization_id}`} /> : null}
                {canvasProgramBindingId ? <Chip label="Bound Canvas program" color="primary" variant="outlined" /> : null}
                {credentialTemplateId ? <Chip label="Application selected" color="success" variant="outlined" /> : null}
                {roles.map((role) => (
                  <Chip key={role} label={role} />
                ))}
              </Stack>

              <Button
                {...continueButtonProps}
                variant="contained"
                size="large"
                endIcon={<ArrowForwardIcon />}
                disabled={authLoading}
                fullWidth
              >
                Continue in ElevenID
              </Button>
            </Stack>
          )}
        </Paper>
      </Container>
    </Box>
  );
}

export default CanvasLtiExperiencePage;

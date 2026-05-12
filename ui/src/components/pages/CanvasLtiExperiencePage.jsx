import { useEffect, useMemo, useState } from 'react';
import { Link as RouterLink, useSearchParams } from 'react-router-dom';
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

function CanvasLtiExperiencePage() {
  const [searchParams] = useSearchParams();
  const { isAuthenticated = false } = useAuth() || {};
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
  const nextPath = `/console/applicant/catalog?canvas_lti_state=${encodeURIComponent(state)}`;
  const continuePath = isAuthenticated ? nextPath : `/login?next=${encodeURIComponent(nextPath)}`;

  return (
    <Box sx={{ bgcolor: 'background.default', minHeight: 'calc(100vh - 72px)', py: { xs: 4, md: 8 } }}>
      <Container maxWidth="md">
        <Paper
          elevation={0}
          sx={{
            border: '1px solid',
            borderColor: 'divider',
            borderRadius: 2,
            p: { xs: 3, md: 4 },
          }}
        >
          {loading ? (
            <Stack alignItems="center" spacing={2} sx={{ py: 6 }}>
              <CircularProgress size={42} />
              <Typography color="text.secondary">Opening Canvas launch...</Typography>
            </Stack>
          ) : error ? (
            <Stack spacing={3}>
              <Alert severity="error">{error}</Alert>
              <Button component={RouterLink} to="/" variant="outlined">
                Return Home
              </Button>
            </Stack>
          ) : (
            <Stack spacing={3}>
              <Stack direction="row" spacing={1.5} alignItems="center">
                <SchoolIcon color="primary" />
                <Typography variant="h4" sx={{ fontSize: { xs: '1.6rem', md: '2rem' } }}>
                  Canvas Launch Verified
                </Typography>
              </Stack>

              <Stack spacing={1}>
                <Typography variant="subtitle2" color="text.secondary">
                  Course
                </Typography>
                <Typography variant="h6">{context.title || context.label || context.id || 'Canvas Course'}</Typography>
              </Stack>

              <Stack direction="row" spacing={1} useFlexGap flexWrap="wrap">
                {learner.subject || verifiedLaunch.subject ? (
                  <Chip label={`Canvas user ${learner.subject || verifiedLaunch.subject}`} />
                ) : null}
                {session?.organization_id ? <Chip label={`Org ${session.organization_id}`} /> : null}
                {roles.map((role) => (
                  <Chip key={role} label={role} />
                ))}
              </Stack>

              <Button
                component={RouterLink}
                to={continuePath}
                variant="contained"
                endIcon={<ArrowForwardIcon />}
                sx={{ alignSelf: { xs: 'stretch', sm: 'flex-start' } }}
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

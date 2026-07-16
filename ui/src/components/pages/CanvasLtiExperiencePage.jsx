import { useEffect, useMemo, useRef, useState } from 'react';
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
import AddLinkIcon from '@mui/icons-material/AddLink';
import SchoolIcon from '@mui/icons-material/School';

import { useAuth } from '../../hooks/useAuth';
import {
  CANVAS_LTI_NAVIGATION_MARKER,
  createCurrentCanvasLtiDeepLinkingResponse,
  exchangeCanvasLtiExperienceCode,
  finalizeCanvasLtiAuthentication,
  getCurrentCanvasLtiExperience,
} from '../../services/canvasLtiExperience';

const DEEP_LINKING_STAFF_ROLES = new Set(['instructor', 'administrator']);

function compactRoles(roles = []) {
  return roles
    .map((role) => String(role).replace(/#/g, '/').split('/').pop())
    .filter(Boolean)
    .slice(0, 3);
}

function canvasRoleName(role) {
  return String(role || '')
    .trim()
    .toLowerCase()
    .replace(/#/g, '/')
    .replace(/\/+$/, '')
    .split('/')
    .pop();
}

function hasDeepLinkingStaffRole(roles = []) {
  return roles.some((role) => DEEP_LINKING_STAFF_ROLES.has(canvasRoleName(role)));
}

function validateDeepLinkingForm(response) {
  const formPost = response?.form_post;
  const method = String(formPost?.method || '').trim().toUpperCase();
  const action = String(formPost?.action || '').trim();
  const returnUrl = String(response?.deep_link_return_url || '').trim();
  const jwt = String(response?.jwt || '').trim();
  const formJwt = String(formPost?.fields?.JWT || '').trim();

  let destination;
  try {
    destination = new URL(action);
  } catch {
    destination = null;
  }

  if (
    method !== 'POST'
    || !destination
    || destination.protocol !== 'https:'
    || action !== returnUrl
    || !jwt
    || jwt !== formJwt
  ) {
    throw new Error(
      'Canvas did not return a valid Deep Linking destination. Reopen the activity from Canvas.',
    );
  }

  return { action, jwt };
}

function buildCanvasContinuePath(session) {
  const query = new URLSearchParams({ canvas_lti_state: CANVAS_LTI_NAVIGATION_MARKER });
  const canvasProgramBindingId = session?.canvas_program_binding_id;
  const canvasPlatformId = session?.canvas_platform_id;
  const applicationTemplateId = session?.application_template_id;
  const credentialTemplateId = session?.credential_template_id;

  if (canvasProgramBindingId) query.set('canvas_program_binding_id', canvasProgramBindingId);
  if (canvasPlatformId) query.set('canvas_platform_id', canvasPlatformId);
  if (applicationTemplateId) query.set('application_template_id', applicationTemplateId);

  if (credentialTemplateId) {
    return `/console/applicant/apply/${encodeURIComponent(credentialTemplateId)}?${query.toString()}`;
  }

  return `/console/applicant/catalog?${query.toString()}`;
}

function CanvasLtiExperiencePage() {
  const [searchParams] = useSearchParams();
  const { isLoading: authLoading = false } = useAuth() || {};
  const code = searchParams.get('code') || '';
  const [session, setSession] = useState(null);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(true);
  const [deepLinkingError, setDeepLinkingError] = useState('');
  const [deepLinkingSubmission, setDeepLinkingSubmission] = useState(null);
  const [deepLinkingSubmitting, setDeepLinkingSubmitting] = useState(false);
  const sessionLoadRef = useRef(null);
  const deepLinkingFormRef = useRef(null);
  const submittedDeepLinkingJwtRef = useRef(null);

  useEffect(() => {
    let alive = true;
    async function loadSession() {
      try {
        if (!sessionLoadRef.current) {
          sessionLoadRef.current = (async () => {
            if (code) {
              await exchangeCanvasLtiExperienceCode(code);
              window.history.replaceState({}, '', window.location.pathname);
            }
            const currentSession = await getCurrentCanvasLtiExperience();
            if (!currentSession?.lti_capabilities?.deep_linking) {
              await finalizeCanvasLtiAuthentication();
            }
            return currentSession;
          })();
        }
        const data = await sessionLoadRef.current;
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
  }, [code]);

  useEffect(() => {
    if (!deepLinkingSubmission || !deepLinkingFormRef.current) return;
    if (submittedDeepLinkingJwtRef.current === deepLinkingSubmission.jwt) return;

    try {
      submittedDeepLinkingJwtRef.current = deepLinkingSubmission.jwt;
      deepLinkingFormRef.current.submit();
    } catch {
      submittedDeepLinkingJwtRef.current = null;
      setDeepLinkingSubmitting(false);
      setDeepLinkingError(
        'Canvas could not accept the activity. Reopen the activity picker and try again.',
      );
    }
  }, [deepLinkingSubmission]);

  const context = session?.canvas_context || {};
  const roles = useMemo(() => compactRoles(session?.roles), [session?.roles]);
  const isDeepLinkingLaunch = Boolean(session?.lti_capabilities?.deep_linking);
  const canCreateDeepLink = useMemo(
    () => hasDeepLinkingStaffRole(session?.roles),
    [session?.roles],
  );
  const nextPath = buildCanvasContinuePath(session);
  const canvasProgramBindingId = session?.canvas_program_binding_id;
  const credentialTemplateId = session?.credential_template_id;
  const mappingStatus = session?.identity_mapping_status;
  const continueButtonProps = {
    component: 'a',
    href: nextPath,
    target: '_top',
    rel: 'noreferrer',
  };

  async function addActivityToCanvas() {
    setDeepLinkingError('');
    setDeepLinkingSubmitting(true);
    try {
      const response = await createCurrentCanvasLtiDeepLinkingResponse();
      setDeepLinkingSubmission(validateDeepLinkingForm(response));
    } catch (err) {
      setDeepLinkingSubmitting(false);
      setDeepLinkingError(
        err?.message || 'Canvas could not add the Marty activity. Reopen the activity picker and try again.',
      );
    }
  }

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
                    {isDeepLinkingLaunch ? 'Add Marty activity to Canvas' : 'Continue with Canvas'}
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    {isDeepLinkingLaunch ? 'Canvas Deep Linking launch verified' : 'Canvas launch verified'}
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
                  {context.title || context.label || context.course_id || 'Canvas Course'}
                </Typography>
              </Stack>

              <Stack direction="row" spacing={1} useFlexGap flexWrap="wrap">
                {session?.learner_display_name ? <Chip label={session.learner_display_name} /> : null}
                {canvasProgramBindingId ? <Chip label="Bound Canvas program" color="primary" variant="outlined" /> : null}
                {credentialTemplateId ? <Chip label="Application selected" color="success" variant="outlined" /> : null}
                {mappingStatus ? (
                  <Chip
                    label={mappingStatus === 'linked' ? 'Canvas identity linked' : 'Canvas identity needs review'}
                    color={mappingStatus === 'linked' ? 'success' : 'warning'}
                    variant="outlined"
                  />
                ) : null}
                {roles.map((role) => (
                  <Chip key={role} label={role} />
                ))}
              </Stack>

              {isDeepLinkingLaunch ? (
                canCreateDeepLink ? (
                  <Stack spacing={1.5}>
                    {deepLinkingError ? <Alert severity="error">{deepLinkingError}</Alert> : null}
                    <Typography variant="body2" color="text.secondary" textAlign="center">
                      Marty will create the activity from this program binding and return you to Canvas.
                    </Typography>
                    <Button
                      type="button"
                      variant="contained"
                      size="large"
                      startIcon={deepLinkingSubmitting ? <CircularProgress color="inherit" size={18} /> : <AddLinkIcon />}
                      disabled={authLoading || deepLinkingSubmitting}
                      onClick={addActivityToCanvas}
                      fullWidth
                    >
                      {deepLinkingSubmitting ? 'Returning to Canvas...' : 'Add Marty activity to Canvas'}
                    </Button>
                  </Stack>
                ) : (
                  <Alert severity="warning">
                    Canvas requires an Instructor or Administrator role to add this activity.
                  </Alert>
                )
              ) : (
                <Button
                  {...continueButtonProps}
                  variant="contained"
                  size="large"
                  endIcon={<ArrowForwardIcon />}
                  disabled={authLoading}
                  fullWidth
                  data-testid="canvas-lti-continue"
                >
                  Continue in ElevenID
                </Button>
              )}

              {deepLinkingSubmission ? (
                <form
                  ref={deepLinkingFormRef}
                  method="post"
                  action={deepLinkingSubmission.action}
                  target="_top"
                  aria-hidden="true"
                  style={{ display: 'none' }}
                >
                  <input type="hidden" name="JWT" value={deepLinkingSubmission.jwt} readOnly />
                </form>
              ) : null}
            </Stack>
          )}
        </Paper>
      </Container>
    </Box>
  );
}

export default CanvasLtiExperiencePage;

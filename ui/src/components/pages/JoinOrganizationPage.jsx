/**
 * Join Organization Page
 *
 * Canonical join flow shell for organization membership.
 * Entry points:
 * - /organizations/join
 * - /organizations/join?orgId=<id>
 * - /organizations/join?mode=code
 */

import { useEffect, useMemo, useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import {
  Box,
  Container,
  Typography,
  Card,
  CardContent,
  CardActionArea,
  Grid,
  Button,
  Stack,
  Chip,
  Divider,
  Alert,
  CircularProgress,
  TextField,
  InputAdornment,
  Paper,
} from '@mui/material';
import BusinessIcon from '@mui/icons-material/Business';
import SearchIcon from '@mui/icons-material/Search';
import VpnKeyIcon from '@mui/icons-material/VpnKey';
import LockOpenIcon from '@mui/icons-material/LockOpen';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import HourglassTopIcon from '@mui/icons-material/HourglassTop';
import ErrorIcon from '@mui/icons-material/Error';

import {
  acceptOrganizationInvitation,
  discoverOrganizations,
  getErrorMessage,
  getOrganization,
  joinByCode,
  joinOrganization,
  validateOrganizationInvitation,
} from '../../services/organizationsApi';
import { useConsole } from '../../contexts/ConsoleContext';
import { useAuth } from '../../hooks/useAuth';

const CAPABILITY_HINTS = [
  'Access organization workspace',
  'View and manage your organization applications',
  'Use organization-specific settings and defaults',
];

const INVITE_STATES = {
  LOADING: 'loading',
  VALID: 'valid',
  ACCEPTING: 'accepting',
  ACCEPTED: 'accepted',
  ERROR: 'error',
};

const getJoinMethodLabel = (method) => {
  const labels = {
    open: 'Open',
    code: 'Join code',
    invite: 'Invite only',
    domain: 'Domain',
  };
  return labels[method] || method || 'Invite only';
};

const toErrorText = (error, fallback) => {
  const parsed = getErrorMessage(error);
  if (typeof parsed === 'string' && parsed.trim() && parsed !== '[object Object]') {
    return parsed;
  }

  const nestedUserMessage = error?.response?.error?.user_message || error?.response?.errors?.[0]?.user_message;
  if (typeof nestedUserMessage === 'string' && nestedUserMessage.trim()) {
    return nestedUserMessage;
  }

  const nestedMessage = error?.response?.error?.message;
  if (typeof nestedMessage === 'string' && nestedMessage.trim() && nestedMessage !== '[object Object]') {
    return nestedMessage;
  }

  return fallback;
};

export default function JoinOrganizationPage() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const { setActiveOrgId, refreshMemberships } = useConsole();
  const { isAuthenticated, isLoading: authLoading, login } = useAuth();

  const orgIdFromQuery = searchParams.get('orgId');
  const modeFromQuery = searchParams.get('mode');
  const inviteToken = searchParams.get('inviteToken');

  const [organizations, setOrganizations] = useState([]);
  const [loading, setLoading] = useState(true);
  const [loadingSelection, setLoadingSelection] = useState(false);
  const [selectedOrg, setSelectedOrg] = useState(null);
  const [error, setError] = useState(null);
  const [searchQuery, setSearchQuery] = useState('');

  const [joinCode, setJoinCode] = useState(searchParams.get('code') || '');
  const [joining, setJoining] = useState(false);

  const [successState, setSuccessState] = useState(null); // 'joined' | 'pending' | null
  const [successOrgName, setSuccessOrgName] = useState('');

  const [inviteState, setInviteState] = useState(inviteToken ? INVITE_STATES.LOADING : null);
  const [invitation, setInvitation] = useState(null);

  const showCodeMode = modeFromQuery === 'code';

  const ensureAuthenticated = () => {
    // Don't show error during auth loading - just prevent action
    if (authLoading) {
      return false;
    }

    if (!isAuthenticated) {
      const returnTo = window.location.pathname + window.location.search;
      login(returnTo);
      return false;
    }

    return true;
  };

  useEffect(() => {
    if (!inviteToken) return;

    async function validateInvitation() {
      try {
        setInviteState(INVITE_STATES.LOADING);
        setError(null);

        const data = await validateOrganizationInvitation(inviteToken);
        if (!data?.valid) {
          const inviteMessage =
            (typeof data?.message === 'string' && data.message) ||
            data?.error?.user_message ||
            data?.error?.message ||
            'Invitation is invalid or expired';
          throw new Error(inviteMessage);
        }
        setInvitation(data);
        setSelectedOrg((prev) => prev || {
          id: data.organization_id,
          name: data.organization_name,
          display_name: data.organization_name,
          join_mechanism: 'invite',
          requires_approval: false,
          description: data.organization_description || '',
        });
        setInviteState(INVITE_STATES.VALID);
      } catch (err) {
        console.error('Failed to validate invitation:', err);
        setInviteState(INVITE_STATES.ERROR);
        setError(toErrorText(err, 'Failed to validate invitation'));
      }
    }

    validateInvitation();
  }, [inviteToken]);

  useEffect(() => {
    async function loadDiscoverableOrgs() {
      try {
        setLoading(true);
        const orgs = await discoverOrganizations({ limit: 100 });
        setOrganizations(orgs || []);

        // If we arrived via /organizations/join?orgId=..., prefer org data from discover list.
        if (orgIdFromQuery) {
          const fromDiscoverList = (orgs || []).find((org) => org.id === orgIdFromQuery);
          if (fromDiscoverList) {
            setSelectedOrg(fromDiscoverList);
            setError(null);
          }
        }
      } catch (err) {
        console.error('Failed to load organizations:', err);
        setError(toErrorText(err, 'Failed to load organizations'));
      } finally {
        setLoading(false);
      }
    }

    loadDiscoverableOrgs();
  }, [orgIdFromQuery]);

  useEffect(() => {
    async function loadSelectedFromQuery() {
      if (!orgIdFromQuery) return;
      try {
        setLoadingSelection(true);

        // If org is already in discoverable list, we can render immediately without detail lookup.
        const fromList = organizations.find((org) => org.id === orgIdFromQuery);
        if (fromList) {
          setSelectedOrg(fromList);
          setError(null);
          return;
        }

        // Avoid protected details call for unauthenticated users.
        // Discover data is enough for preview in anonymous mode.
        if (isAuthenticated) {
          const org = await getOrganization(orgIdFromQuery);
          setSelectedOrg(org);
          setError(null);
        }
      } catch (err) {
        console.error('Failed to load organization:', err);
        // Some environments restrict direct organization details for non-members.
        // Keep join preview working using discoverable list data if present.
        const fromList = organizations.find((org) => org.id === orgIdFromQuery);
        if (fromList) {
          setSelectedOrg(fromList);
          setError(null);
        } else {
          setError(toErrorText(err, 'Failed to load organization details'));
        }
      } finally {
        setLoadingSelection(false);
      }
    }

    loadSelectedFromQuery();
  }, [orgIdFromQuery, organizations, isAuthenticated]);

  const filteredOrganizations = useMemo(() => {
    const query = searchQuery.trim().toLowerCase();
    if (!query) return organizations;
    return organizations.filter((org) => {
      const name = (org.name || org.display_name || '').toLowerCase();
      const description = (org.description || '').toLowerCase();
      return name.includes(query) || description.includes(query);
    });
  }, [organizations, searchQuery]);

  const handleJoinByCode = async () => {
    if (!joinCode.trim()) {
      setError('Please enter a join code');
      return;
    }

    if (!ensureAuthenticated()) {
      return;
    }

    try {
      setJoining(true);
      setError(null);
      const result = await joinByCode(joinCode.trim().toUpperCase());
      const organization = result?.organization;
      const membership = result?.membership;

      if (!organization) {
        throw new Error('Join succeeded but organization details were missing');
      }

      setSuccessOrgName(organization.name || organization.display_name || 'Organization');

      if (membership?.status === 'pending') {
        setSuccessState('pending');
        return;
      }

      await refreshMemberships();
      await setActiveOrgId(organization.id);
      setSuccessState('joined');
      setTimeout(() => navigate('/console'), 1200);
    } catch (err) {
      console.error('Failed to join by code:', err);
      setError(toErrorText(err, 'Failed to join organization using join code'));
    } finally {
      setJoining(false);
    }
  };

  const handleJoinSelectedOrg = async () => {
    if (!selectedOrg) return;

    if (!ensureAuthenticated()) {
      return;
    }

    if (selectedOrg.join_mechanism !== 'open') {
      setError('This organization is not open for direct join. Use a join code or invitation link.');
      return;
    }

    try {
      setJoining(true);
      setError(null);

      const result = await joinOrganization(selectedOrg.id);
      const membershipStatus = result?.membership?.status;
      const orgName = selectedOrg.name || selectedOrg.display_name || 'Organization';

      setSuccessOrgName(orgName);

      if (membershipStatus === 'pending') {
        setSuccessState('pending');
        return;
      }

      await refreshMemberships();
      await setActiveOrgId(selectedOrg.id);
      setSuccessState('joined');
      setTimeout(() => navigate('/console'), 1200);
    } catch (err) {
      console.error('Failed to join organization:', err);
      setError(toErrorText(err, 'Failed to join organization'));
    } finally {
      setJoining(false);
    }
  };

  const handleAcceptInvitation = async () => {
    if (!inviteToken) return;

    if (!ensureAuthenticated()) {
      return;
    }

    try {
      setInviteState(INVITE_STATES.ACCEPTING);
      setError(null);

      const data = await acceptOrganizationInvitation(inviteToken);
      const orgId = data.organization_id || invitation?.organization_id || selectedOrg?.id;
      const orgName = data.organization_name || invitation?.organization_name || selectedOrg?.name || 'Organization';

      setSuccessOrgName(orgName);
      setInviteState(INVITE_STATES.ACCEPTED);
      setSuccessState('joined');

      if (orgId) {
        await refreshMemberships();
        await setActiveOrgId(orgId);
      }
      setTimeout(() => navigate('/console'), 1200);
    } catch (err) {
      console.error('Failed to accept invitation:', err);
      setInviteState(INVITE_STATES.ERROR);
      setError(toErrorText(err, 'Failed to accept invitation'));
    }
  };

  if (inviteToken) {
    return (
      <Container maxWidth="md" sx={{ py: 6 }}>
        <Paper sx={{ p: 4 }}>
          {inviteState === INVITE_STATES.LOADING && (
            <Box sx={{ textAlign: 'center', py: 4 }}>
              <CircularProgress sx={{ mb: 2 }} />
              <Typography variant="h6">Validating invitation…</Typography>
            </Box>
          )}

          {inviteState === INVITE_STATES.VALID && (
            <>
              <Typography variant="h4" fontWeight={700} gutterBottom>
                Join {invitation?.organization_name || selectedOrg?.name}
              </Typography>
              <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
                You were invited to join this organization. Accept the invitation to activate your organization context.
              </Typography>

              <Card variant="outlined" sx={{ mb: 3 }}>
                <CardContent>
                  <Typography variant="subtitle1" fontWeight={600} gutterBottom>
                    Invitation details
                  </Typography>
                  <Stack spacing={1}>
                    <Typography variant="body2" color="text.secondary">
                      Organization: {invitation?.organization_name || 'N/A'}
                    </Typography>
                    {invitation?.email && (
                      <Typography variant="body2" color="text.secondary">
                        Invited email: {invitation.email}
                      </Typography>
                    )}
                    {invitation?.expires_at && (
                      <Typography variant="body2" color="text.secondary">
                        Expires: {new Date(invitation.expires_at).toLocaleString()}
                      </Typography>
                    )}
                  </Stack>
                </CardContent>
              </Card>

              <Button variant="contained" onClick={handleAcceptInvitation}>
                Accept invitation
              </Button>
            </>
          )}

          {inviteState === INVITE_STATES.ACCEPTING && (
            <Box sx={{ textAlign: 'center', py: 4 }}>
              <CircularProgress sx={{ mb: 2 }} />
              <Typography variant="h6">Accepting invitation…</Typography>
            </Box>
          )}

          {inviteState === INVITE_STATES.ERROR && (
            <Box sx={{ textAlign: 'center', py: 4 }}>
              <ErrorIcon color="error" sx={{ fontSize: 56, mb: 2 }} />
              <Typography variant="h6" gutterBottom>
                Unable to process invitation
              </Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                {error || 'Please contact your organization administrator for a new invitation.'}
              </Typography>
              <Button variant="outlined" onClick={() => navigate('/organizations/discover')}>
                Discover Organizations
              </Button>
            </Box>
          )}
        </Paper>
      </Container>
    );
  }

  if (successState === 'joined') {
    return (
      <Container maxWidth="md" sx={{ py: 6 }}>
        <Card>
          <CardContent sx={{ textAlign: 'center', py: 6 }}>
            <CheckCircleIcon color="success" sx={{ fontSize: 64, mb: 2 }} />
            <Typography variant="h4" fontWeight={700} gutterBottom>
              You joined {successOrgName}
            </Typography>
            <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
              Your organization context is now active. Redirecting to your workspace…
            </Typography>
            <Button variant="contained" onClick={() => navigate('/console')}>
              Go to Organization Console
            </Button>
          </CardContent>
        </Card>
      </Container>
    );
  }

  if (successState === 'pending') {
    return (
      <Container maxWidth="md" sx={{ py: 6 }}>
        <Card>
          <CardContent sx={{ textAlign: 'center', py: 6 }}>
            <HourglassTopIcon color="warning" sx={{ fontSize: 64, mb: 2 }} />
            <Typography variant="h4" fontWeight={700} gutterBottom>
              Request submitted to {successOrgName}
            </Typography>
            <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
              An administrator must approve your membership before access is granted.
            </Typography>
            <Stack direction="row" spacing={2} justifyContent="center">
              <Button variant="outlined" onClick={() => navigate('/organizations/mine')}>
                View My Organizations
              </Button>
              <Button variant="contained" onClick={() => navigate('/organizations/discover')}>
                Discover More Organizations
              </Button>
            </Stack>
          </CardContent>
        </Card>
      </Container>
    );
  }

  return (
    <Container maxWidth="lg" sx={{ py: 4 }}>
      <Box sx={{ mb: 4 }}>
        <Typography variant="h4" gutterBottom fontWeight={700}>
          Join an Organization
        </Typography>
        <Typography variant="body1" color="text.secondary">
          Preview organizations, understand what you’ll unlock, and join with confidence.
        </Typography>
      </Box>

      {error && (
        <Alert severity="error" sx={{ mb: 3 }}>
          {error}
        </Alert>
      )}

      <Grid container spacing={3}>
        {/* Left side: discovery list + join code */}
        <Grid item xs={12} md={6}>
          <Card sx={{ mb: 3 }}>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Use a Join Code
              </Typography>
              <TextField
                fullWidth
                placeholder="Enter 8-character join code"
                value={joinCode}
                onChange={(e) => setJoinCode(e.target.value.toUpperCase())}
                InputProps={{
                  startAdornment: (
                    <InputAdornment position="start">
                      <VpnKeyIcon />
                    </InputAdornment>
                  ),
                }}
                sx={{ mb: 2 }}
              />
              <Button
                variant="contained"
                onClick={handleJoinByCode}
                disabled={authLoading || joining || !joinCode.trim()}
              >
                {joining ? <CircularProgress size={20} color="inherit" /> : authLoading ? 'Loading...' : 'Join via Code'}
              </Button>
            </CardContent>
          </Card>

          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Discover Organizations
              </Typography>
              <TextField
                fullWidth
                size="small"
                placeholder="Search organizations..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                InputProps={{
                  startAdornment: (
                    <InputAdornment position="start">
                      <SearchIcon />
                    </InputAdornment>
                  ),
                }}
                sx={{ mb: 2 }}
              />

              {loading ? (
                <Box sx={{ py: 4, textAlign: 'center' }}>
                  <CircularProgress size={24} />
                </Box>
              ) : filteredOrganizations.length === 0 ? (
                <Alert severity="info">No discoverable organizations found.</Alert>
              ) : (
                <Stack spacing={1.5}>
                  {filteredOrganizations.map((org) => (
                    <Card
                      key={org.id}
                      variant="outlined"
                      sx={{
                        borderColor: selectedOrg?.id === org.id ? 'primary.main' : 'divider',
                        boxShadow: selectedOrg?.id === org.id ? (theme) => `0 0 0 1px ${theme.palette.primary.main}` : 'none',
                      }}
                    >
                      <CardActionArea onClick={() => setSelectedOrg(org)}>
                        <CardContent sx={{ pb: 1.5 }}>
                          <Typography fontWeight={600}>{org.name || org.display_name}</Typography>
                          {org.description && (
                            <Typography variant="body2" color="text.secondary" sx={{ mt: 0.5 }}>
                              {org.description}
                            </Typography>
                          )}
                          <Stack direction="row" spacing={1} sx={{ mt: 1.5, flexWrap: 'wrap' }}>
                            <Chip size="small" label={getJoinMethodLabel(org.join_mechanism)} icon={<LockOpenIcon fontSize="small" />} />
                            {org.requires_approval && (
                              <Chip size="small" label="Approval Required" color="warning" variant="outlined" />
                            )}
                          </Stack>
                        </CardContent>
                      </CardActionArea>
                    </Card>
                  ))}
                </Stack>
              )}
            </CardContent>
          </Card>
        </Grid>

        {/* Right side: org preview and action */}
        <Grid item xs={12} md={6}>
          <Card sx={{ minHeight: 480 }}>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Organization Preview
              </Typography>

              {loadingSelection ? (
                <Box sx={{ py: 6, textAlign: 'center' }}>
                  <CircularProgress size={24} />
                </Box>
              ) : !selectedOrg ? (
                <Box sx={{ py: 8, textAlign: 'center' }}>
                  <BusinessIcon color="action" sx={{ fontSize: 56, mb: 2 }} />
                  <Typography color="text.secondary">
                    Select an organization from the list to preview details and join options.
                  </Typography>
                </Box>
              ) : (
                <>
                  <Typography variant="h5" fontWeight={700} gutterBottom>
                    {selectedOrg.name || selectedOrg.display_name}
                  </Typography>

                  {selectedOrg.description && (
                    <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                      {selectedOrg.description}
                    </Typography>
                  )}

                  <Stack direction="row" spacing={1} sx={{ mb: 2, flexWrap: 'wrap' }}>
                    {selectedOrg.org_type && (
                      <Chip size="small" label={selectedOrg.org_type} variant="outlined" sx={{ textTransform: 'capitalize' }} />
                    )}
                    <Chip
                      size="small"
                      label={getJoinMethodLabel(selectedOrg.join_mechanism)}
                      color={selectedOrg.join_mechanism === 'open' ? 'success' : 'default'}
                    />
                    {selectedOrg.requires_approval && (
                      <Chip size="small" label="Approval Required" color="warning" variant="outlined" />
                    )}
                  </Stack>

                  <Divider sx={{ my: 2 }} />

                  <Typography variant="subtitle2" gutterBottom>
                    You will be able to:
                  </Typography>
                  <Stack spacing={1} sx={{ mb: 3 }}>
                    {CAPABILITY_HINTS.map((item) => (
                      <Typography key={item} variant="body2" color="text.secondary">
                        • {item}
                      </Typography>
                    ))}
                  </Stack>

                  <Alert severity="info" sx={{ mb: 2 }}>
                    You will join as a member. Additional permissions depend on organization role assignments.
                  </Alert>

                  <Button
                    variant="contained"
                    fullWidth
                    onClick={handleJoinSelectedOrg}
                    disabled={authLoading || joining || selectedOrg.join_mechanism !== 'open'}
                  >
                    {authLoading
                      ? 'Loading...'
                      : joining
                        ? <CircularProgress size={20} color="inherit" />
                        : selectedOrg.requires_approval
                          ? 'Request to Join'
                          : 'Join Organization'}
                  </Button>

                  {selectedOrg.join_mechanism !== 'open' && (
                    <Typography variant="caption" color="text.secondary" sx={{ display: 'block', mt: 1.5 }}>
                      This organization is not open for direct join. Use a join code or invitation link.
                    </Typography>
                  )}
                </>
              )}
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {showCodeMode && (
        <Alert severity="info" sx={{ mt: 3 }}>
          You opened the join flow in code mode. Enter your join code above to continue.
        </Alert>
      )}
    </Container>
  );
}

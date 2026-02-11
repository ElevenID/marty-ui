/**
 * Applicant Join Organization Step Component
 * 
 * Step 2 for Applicants: Join an organization via code, browse, or skip
 */

import { useState, useMemo } from 'react';
import {
  Box,
  Typography,
  TextField,
  Button,
  FormControl,
  FormControlLabel,
  RadioGroup,
  Radio,
  Divider,
  Alert,
  Grid,
  Card,
  CardContent,
  CircularProgress,
  InputAdornment,
  Fade,
  MenuItem,
  Select,
  Chip,
  Stack,
} from '@mui/material';
import VpnKeyIcon from '@mui/icons-material/VpnKey';
import VisibilityIcon from '@mui/icons-material/Visibility';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import ArrowForwardIcon from '@mui/icons-material/ArrowForward';
import WarningAmberIcon from '@mui/icons-material/WarningAmber';
import InfoIcon from '@mui/icons-material/Info';
import SearchIcon from '@mui/icons-material/Search';
import MembershipModeChip from '../MembershipModeChip';

const ApplicantJoinStep = ({
  joinMethod,
  onJoinMethodChange,
  inviteCode,
  onInviteCodeChange,
  organizations,
  submitting,
  onJoinWithCode,
  onSelectOrg,
  onSkip,
}) => {
  const [searchQuery, setSearchQuery] = useState('');
  const [membershipFilter, setMembershipFilter] = useState('all');

  // Filter and search organizations
  const filteredOrganizations = useMemo(() => {
    let filtered = [...organizations];

    // Apply search query
    if (searchQuery.trim()) {
      const query = searchQuery.toLowerCase();
      filtered = filtered.filter(
        (org) =>
          org.name.toLowerCase().includes(query) ||
          (org.description && org.description.toLowerCase().includes(query))
      );
    }

    // Apply membership mode filter
    if (membershipFilter !== 'all') {
      filtered = filtered.filter((org) => org.membership_mode === membershipFilter);
    }

    return filtered;
  }, [organizations, searchQuery, membershipFilter]);
  return (
    <Fade in>
      <Box>
        <Typography variant="h5" gutterBottom textAlign="center">
          Join an Organization
        </Typography>
        <Typography
          variant="body1"
          color="text.secondary"
          textAlign="center"
          sx={{ mb: 4 }}
        >
          Connect with a vendor organization to apply for travel documents
        </Typography>

        {/* Join Method Selection */}
        <Box sx={{ mb: 4 }}>
          <FormControl component="fieldset">
            <RadioGroup
              row
              value={joinMethod}
              onChange={(e) => onJoinMethodChange(e.target.value)}
              sx={{ justifyContent: 'center', gap: 2 }}
            >
              <FormControlLabel
                value="code"
                control={<Radio />}
                label={
                  <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                    <VpnKeyIcon fontSize="small" />
                    I have an invite code
                  </Box>
                }
              />
              <FormControlLabel
                value="browse"
                control={<Radio />}
                label={
                  <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                    <VisibilityIcon fontSize="small" />
                    Browse organizations
                  </Box>
                }
              />
              <FormControlLabel
                value="skip"
                control={<Radio />}
                label="Skip for now"
              />
            </RadioGroup>
          </FormControl>
        </Box>

        <Divider sx={{ my: 3 }} />

        {/* Join with Invite Code */}
        {joinMethod === 'code' && (
          <Box sx={{ maxWidth: 500, mx: 'auto', textAlign: 'center' }}>
            <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
              Enter the invite code provided by your organization
            </Typography>
            <TextField
              fullWidth
              label="Invite Code"
              value={inviteCode}
              onChange={(e) => onInviteCodeChange(e.target.value.toUpperCase())}
              placeholder="e.g., ABC123XY"
              InputProps={{
                startAdornment: (
                  <InputAdornment position="start">
                    <VpnKeyIcon color="action" />
                  </InputAdornment>
                ),
              }}
              sx={{ mb: 3 }}
            />
            <Button
              variant="contained"
              size="large"
              onClick={onJoinWithCode}
              disabled={submitting || !inviteCode.trim()}
              endIcon={submitting ? <CircularProgress size={16} /> : <CheckCircleIcon />}
            >
              {submitting ? 'Joining...' : 'Join Organization'}
            </Button>
          </Box>
        )}

        {/* Browse Organizations */}
        {joinMethod === 'browse' && (
          <Box>
            {organizations.length === 0 ? (
              <Alert severity="info" icon={<InfoIcon />}>
                <Typography variant="body2">
                  No discoverable organizations are currently available.
                  Please use an invite code or contact your organization administrator.
                </Typography>
              </Alert>
            ) : (
              <>
                <Alert severity="warning" icon={<WarningAmberIcon />} sx={{ mb: 3 }}>
                  <Typography variant="body2">
                    <strong>Important:</strong> Make sure you select the correct organization.
                    You will be asked to confirm your selection.
                  </Typography>
                </Alert>

                {/* Search and Filter Controls */}
                <Stack direction={{ xs: 'column', sm: 'row' }} spacing={2} sx={{ mb: 3 }}>
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
                  />
                  <FormControl size="small" sx={{ minWidth: 200 }}>
                    <Select
                      value={membershipFilter}
                      onChange={(e) => setMembershipFilter(e.target.value)}
                      displayEmpty
                    >
                      <MenuItem value="all">All Types</MenuItem>
                      <MenuItem value="open">Open (Join Immediately)</MenuItem>
                      <MenuItem value="approval">Request Approval</MenuItem>
                      <MenuItem value="invite_only">Invite Only</MenuItem>
                    </Select>
                  </FormControl>
                </Stack>

                {/* Results count */}
                {(searchQuery || membershipFilter !== 'all') && (
                  <Box sx={{ mb: 2 }}>
                    <Chip
                      size="small"
                      label={`${filteredOrganizations.length} organization${filteredOrganizations.length !== 1 ? 's' : ''} found`}
                      color="primary"
                      variant="outlined"
                    />
                  </Box>
                )}

                {filteredOrganizations.length === 0 ? (
                  <Alert severity="info" icon={<InfoIcon />}>
                    <Typography variant="body2">
                      No organizations match your search criteria. Try adjusting your filters.
                    </Typography>
                  </Alert>
                ) : (
                  <Grid container spacing={2}>
                    {filteredOrganizations.map((org) => (
                      <Grid item xs={12} md={6} key={org.id}>
                        <Card
                        variant="outlined"
                        sx={{
                          cursor: org.membership_mode !== 'invite_only' ? 'pointer' : 'not-allowed',
                          opacity: org.membership_mode === 'invite_only' ? 0.6 : 1,
                          '&:hover': org.membership_mode !== 'invite_only' ? {
                            borderColor: 'primary.main',
                            boxShadow: 2,
                          } : {},
                        }}
                        onClick={() => onSelectOrg(org)}
                      >
                        <CardContent>
                          <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', mb: 1 }}>
                            <Typography variant="h6">{org.name}</Typography>
                            <MembershipModeChip mode={org.membership_mode} />
                          </Box>
                          {org.description && (
                            <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                              {org.description}
                            </Typography>
                          )}
                          <Typography variant="caption" color="text.secondary">
                            {org.member_count} member{org.member_count !== 1 ? 's' : ''}
                          </Typography>
                        </CardContent>
                      </Card>
                    </Grid>
                  ))}
                </Grid>
                )}
              </>
            )}
          </Box>
        )}

        {/* Skip */}
        {joinMethod === 'skip' && (
          <Box sx={{ textAlign: 'center' }}>
            <Alert severity="info" sx={{ mb: 3, maxWidth: 500, mx: 'auto' }}>
              <Typography variant="body2">
                You can join an organization later from your dashboard or when you receive
                an invite code from a vendor.
              </Typography>
            </Alert>
            <Button
              variant="contained"
              size="large"
              onClick={onSkip}
              disabled={submitting}
              endIcon={submitting ? <CircularProgress size={16} /> : <ArrowForwardIcon />}
            >
              {submitting ? 'Setting up...' : 'Continue to Dashboard'}
            </Button>
          </Box>
        )}
      </Box>
    </Fade>
  );
};

export default ApplicantJoinStep;

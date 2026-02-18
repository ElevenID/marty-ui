/**
 * Discover Organizations Page
 * 
 * Allows users to discover and join publicly available organizations.
 * Includes search and filtering by organization type and join mechanism.
 */

import { useState, useEffect, useCallback } from 'react';
import {
  Box,
  Container,
  Typography,
  Card,
  CardContent,
  CardActions,
  Button,
  Chip,
  Grid,
  Alert,
  CircularProgress,
  TextField,
  InputAdornment,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Stack,
  Divider,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
} from '@mui/material';
import SearchIcon from '@mui/icons-material/Search';
import BusinessIcon from '@mui/icons-material/Business';
import LockOpenIcon from '@mui/icons-material/LockOpen';
import VpnKeyIcon from '@mui/icons-material/VpnKey';
import EmailIcon from '@mui/icons-material/Email';
import PublicIcon from '@mui/icons-material/Public';
import InfoOutlinedIcon from '@mui/icons-material/InfoOutlined';
import { useNavigate } from 'react-router-dom';

import { discoverOrganizations } from '../../services/organizationsApi';

/**
 * Discover Organizations Page Component
 */
export function DiscoverOrganizationsPage() {
  const navigate = useNavigate();
  
  const [organizations, setOrganizations] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [orgTypeFilter, setOrgTypeFilter] = useState('');
  const [joinMechanismFilter, setJoinMechanismFilter] = useState('');
  
  // Join code dialog state
  const [joinCodeDialog, setJoinCodeDialog] = useState(false);
  const [joinCode, setJoinCode] = useState('');
  const [joinCodeError, setJoinCodeError] = useState(null);
  const [joiningCode, setJoiningCode] = useState(false);

  /**
   * Load discoverable organizations
   */
  const loadOrganizations = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);
      const orgs = await discoverOrganizations({
        search: searchQuery || undefined,
        orgType: orgTypeFilter || undefined,
        joinMechanism: joinMechanismFilter || undefined,
        limit: 100,
      });
      setOrganizations(orgs || []);
    } catch (err) {
      console.error('Failed to load organizations:', err);
      setError(err.message || 'Failed to load organizations');
    } finally {
      setLoading(false);
    }
  }, [searchQuery, orgTypeFilter, joinMechanismFilter]);

  /**
   * Load organizations on mount and when filters change
   */
  useEffect(() => {
    loadOrganizations();
  }, [loadOrganizations]);

  /**
   * Handle join by code
   */
  const handleJoinByCode = async () => {
    if (!joinCode.trim()) {
      setJoinCodeError('Please enter a join code');
      return;
    }

    setJoiningCode(true);
    setJoinCodeError(null);
    setJoinCodeDialog(false);
    const code = joinCode.trim().toUpperCase();
    setJoinCode('');
    navigate(`/organizations/join?mode=code&code=${encodeURIComponent(code)}`);
    setJoiningCode(false);
  };

  /**
   * Get join mechanism icon
   */
  const getJoinMechanismIcon = (mechanism) => {
    const icons = {
      open: <LockOpenIcon fontSize="small" />,
      code: <VpnKeyIcon fontSize="small" />,
      invite: <EmailIcon fontSize="small" />,
      domain: <PublicIcon fontSize="small" />,
    };
    return icons[mechanism] || <BusinessIcon fontSize="small" />;
  };

  /**
   * Get join mechanism label
   */
  const getJoinMechanismLabel = (mechanism) => {
    const labels = {
      open: 'Open',
      code: 'Join code',
      invite: 'Invite only',
      domain: 'Domain',
    };
    return labels[mechanism] || mechanism;
  };

  /**
   * Get join mechanism color
   */
  const getJoinMechanismColor = (mechanism) => {
    const colors = {
      open: 'success',
      code: 'info',
      invite: 'warning',
      domain: 'default',
    };
    return colors[mechanism] || 'default';
  };

  /**
   * Open the canonical join/details flow for the selected organization.
   */
  const handleViewOrganization = (org) => {
    navigate(`/organizations/join?orgId=${encodeURIComponent(org.id)}`);
  };

  return (
    <Container maxWidth="lg" sx={{ py: 4 }}>
      {/* Header */}
      <Box sx={{ mb: 4 }}>
        <Typography variant="h4" gutterBottom fontWeight={600}>
          Discover Organizations
        </Typography>
        <Typography variant="body1" color="text.secondary">
          Find and join publicly available organizations.
        </Typography>
      </Box>

      {/* Filters */}
      <Card sx={{ mb: 3 }}>
        <CardContent>
          <Grid container spacing={2}>
            {/* Search */}
            <Grid item xs={12} md={4}>
              <TextField
                fullWidth
                placeholder="Search by name..."
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
            </Grid>

            {/* Organization Type Filter */}
            <Grid item xs={12} sm={6} md={3}>
              <FormControl fullWidth>
                <InputLabel>Organization Type</InputLabel>
                <Select
                  value={orgTypeFilter}
                  label="Organization Type"
                  onChange={(e) => setOrgTypeFilter(e.target.value)}
                >
                  <MenuItem value="">All Types</MenuItem>
                  <MenuItem value="enterprise">Enterprise</MenuItem>
                  <MenuItem value="startup">Startup</MenuItem>
                  <MenuItem value="individual">Individual</MenuItem>
                  <MenuItem value="government">Government</MenuItem>
                  <MenuItem value="education">Education</MenuItem>
                </Select>
              </FormControl>
            </Grid>

            {/* Join Mechanism Filter */}
            <Grid item xs={12} sm={6} md={3}>
              <FormControl fullWidth>
                <InputLabel>Join Method</InputLabel>
                <Select
                  value={joinMechanismFilter}
                  label="Join Method"
                  onChange={(e) => setJoinMechanismFilter(e.target.value)}
                >
                  <MenuItem value="">All Methods</MenuItem>
                  <MenuItem value="open">Open</MenuItem>
                  <MenuItem value="code">Join code</MenuItem>
                  <MenuItem value="invite">Invite only</MenuItem>
                  <MenuItem value="domain">Domain</MenuItem>
                </Select>
              </FormControl>
            </Grid>

            {/* Join by Code Button */}
            <Grid item xs={12} md={2}>
              <Button
                fullWidth
                variant="contained"
                startIcon={<VpnKeyIcon />}
                onClick={() => setJoinCodeDialog(true)}
                sx={{ height: '100%' }}
              >
                Use Join Code
              </Button>
            </Grid>
          </Grid>
        </CardContent>
      </Card>

      {/* Error Alert */}
      {error && (
        <Alert severity="error" sx={{ mb: 3 }}>
          {error}
        </Alert>
      )}

      {/* Loading State */}
      {loading && (
        <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', minHeight: 400 }}>
          <CircularProgress />
        </Box>
      )}

      {/* Empty State */}
      {!loading && organizations.length === 0 && (
        <Card sx={{ textAlign: 'center', py: 6 }}>
          <CardContent>
            <SearchIcon sx={{ fontSize: 64, color: 'text.secondary', mb: 2 }} />
            <Typography variant="h6" gutterBottom>
              No Organizations Found
            </Typography>
            <Typography variant="body2" color="text.secondary">
              Try adjusting your search criteria or using a join code.
            </Typography>
          </CardContent>
        </Card>
      )}

      {/* Organizations Grid */}
      {!loading && organizations.length > 0 && (
        <Grid container spacing={3}>
          {organizations.map((org) => (
            <Grid item xs={12} sm={6} md={4} key={org.id}>
              <Card
                sx={{
                  height: '100%',
                  display: 'flex',
                  flexDirection: 'column',
                  transition: 'all 0.2s',
                  '&:hover': {
                    boxShadow: 4,
                    transform: 'translateY(-2px)',
                  },
                }}
              >
                <CardContent sx={{ flexGrow: 1 }}>
                  {/* Organization Name */}
                  <Box sx={{ display: 'flex', alignItems: 'flex-start', gap: 1, mb: 2 }}>
                    <BusinessIcon color="action" sx={{ mt: 0.5 }} />
                    <Box sx={{ flexGrow: 1 }}>
                      <Typography variant="h6" gutterBottom>
                        {org.name || org.display_name}
                      </Typography>
                      {org.description && (
                        <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                          {org.description}
                        </Typography>
                      )}
                    </Box>
                  </Box>

                  <Divider sx={{ my: 2 }} />

                  {/* Organization Details */}
                  <Stack spacing={1.5}>
                    {/* Type */}
                    {org.org_type && (
                      <Box>
                        <Chip
                          label={org.org_type}
                          size="small"
                          variant="outlined"
                          sx={{ textTransform: 'capitalize' }}
                        />
                      </Box>
                    )}

                    {/* Join Mechanism */}
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                      <Chip
                        icon={getJoinMechanismIcon(org.join_mechanism)}
                        label={getJoinMechanismLabel(org.join_mechanism)}
                        color={getJoinMechanismColor(org.join_mechanism)}
                        size="small"
                      />
                      {org.requires_approval && (
                        <Chip
                          label="Requires Approval"
                          size="small"
                          color="warning"
                          variant="outlined"
                        />
                      )}
                    </Box>

                    {/* Contact */}
                    {org.contact_email && (
                      <Typography variant="caption" color="text.secondary">
                        Contact: {org.contact_email}
                      </Typography>
                    )}

                    {/* Website */}
                    {org.website && (
                      <Typography variant="caption" color="text.secondary">
                        <a
                          href={org.website}
                          target="_blank"
                          rel="noopener noreferrer"
                          style={{ color: 'inherit' }}
                        >
                          {org.website}
                        </a>
                      </Typography>
                    )}
                  </Stack>
                </CardContent>

                <CardActions sx={{ p: 2, pt: 0, gap: 1 }}>
                  <Button
                    fullWidth
                    variant="outlined"
                    onClick={() => handleViewOrganization(org)}
                    startIcon={<InfoOutlinedIcon />}
                  >
                    Details
                  </Button>
                </CardActions>
              </Card>
            </Grid>
          ))}
        </Grid>
      )}

      {/* Join by Code Dialog */}
      <Dialog
        open={joinCodeDialog}
        onClose={() => {
          setJoinCodeDialog(false);
          setJoinCode('');
          setJoinCodeError(null);
        }}
        maxWidth="sm"
        fullWidth
      >
        <DialogTitle>Join Organization by Code</DialogTitle>
        <DialogContent>
          <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
            Enter the 8-character join code provided by the organization.
          </Typography>
          <TextField
            fullWidth
            label="Join code"
            placeholder="ABC12345"
            value={joinCode}
            onChange={(e) => setJoinCode(e.target.value.toUpperCase())}
            error={Boolean(joinCodeError)}
            helperText={joinCodeError}
            inputProps={{ maxLength: 8 }}
            autoFocus
          />
        </DialogContent>
        <DialogActions>
          <Button
            onClick={() => {
              setJoinCodeDialog(false);
              setJoinCode('');
              setJoinCodeError(null);
            }}
            disabled={joiningCode}
          >
            Cancel
          </Button>
          <Button
            variant="contained"
            onClick={handleJoinByCode}
            disabled={joiningCode || !joinCode.trim()}
          >
            {joiningCode ? <CircularProgress size={24} /> : 'Continue'}
          </Button>
        </DialogActions>
      </Dialog>
    </Container>
  );
}

export default DiscoverOrganizationsPage;

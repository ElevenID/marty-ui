/**
 * Profile Page Component
 *
 * Shows user profile information from OIDC claims.
 * Supports viewing and uploading a profile picture.
 * Available to all authenticated users.
 */

import { useRef, useState } from 'react';
import {
  Box,
  Card,
  CardContent,
  Typography,
  Grid,
  Avatar,
  Chip,
  Divider,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  IconButton,
  Tooltip,
  CircularProgress,
  Alert,
  Button,
} from '@mui/material';
import PersonIcon from '@mui/icons-material/Person';
import EmailIcon from '@mui/icons-material/Email';
import BadgeIcon from '@mui/icons-material/Badge';
import PublicIcon from '@mui/icons-material/Public';
import CakeIcon from '@mui/icons-material/Cake';
import SecurityIcon from '@mui/icons-material/Security';
import AdminPanelSettingsIcon from '@mui/icons-material/AdminPanelSettings';
import BusinessIcon from '@mui/icons-material/Business';
import PhotoCameraIcon from '@mui/icons-material/PhotoCamera';
import { useAuth } from '../hooks/useAuth';
import { updateProfilePicture } from '../services/authApi';

function ProfilePage() {
  const {
    user,
    isAdministrator,
    isApplicant,
    organizationId,
    organizations,
    setActiveOrganizationId,
    refreshUser,
  } = useAuth();

  const fileInputRef = useRef(null);
  const [previewUrl, setPreviewUrl] = useState(null);
  const [uploading, setUploading] = useState(false);
  const [uploadError, setUploadError] = useState(null);
  const [uploadSuccess, setUploadSuccess] = useState(false);

  if (!user) {
    return (
      <Box display="flex" alignItems="center" justifyContent="center" minHeight="40vh">
        <CircularProgress />
      </Box>
    );
  }

  const formatDate = (dateString) => {
    if (!dateString) return 'Not provided';
    return new Date(dateString).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'long',
      day: 'numeric',
    });
  };

  const displayPicture = previewUrl || user.picture || undefined;
  const userInitial = (user.given_name || user.name || user.email || 'U')[0].toUpperCase();

  const handleFileChange = (e) => {
    const file = e.target.files?.[0];
    if (!file) return;

    if (!file.type.startsWith('image/')) {
      setUploadError('Please select an image file (JPEG, PNG, GIF, WebP).');
      return;
    }
    if (file.size > 2 * 1024 * 1024) {
      setUploadError('Image must be smaller than 2 MB.');
      return;
    }

    setUploadError(null);
    setUploadSuccess(false);

    const reader = new FileReader();
    reader.onload = (ev) => setPreviewUrl(ev.target.result);
    reader.readAsDataURL(file);
  };

  const handleSavePicture = async () => {
    if (!previewUrl) return;

    setUploading(true);
    setUploadError(null);
    setUploadSuccess(false);

    const result = await updateProfilePicture(previewUrl);

    setUploading(false);
    if (result.success) {
      setUploadSuccess(true);
      setPreviewUrl(null);
      await refreshUser();
    } else {
      setUploadError(result.error || 'Failed to update profile picture.');
    }
  };

  const handleCancelPicture = () => {
    setPreviewUrl(null);
    setUploadError(null);
    setUploadSuccess(false);
    if (fileInputRef.current) fileInputRef.current.value = '';
  };

  return (
    <Box>
      <Typography variant="h4" component="h1" gutterBottom>
        My Profile
      </Typography>

      <Grid container spacing={3}>
        {/* Profile Card */}
        <Grid item xs={12} md={4}>
          <Card>
            <CardContent sx={{ textAlign: 'center', py: 4 }}>
              {/* Avatar with camera overlay */}
              <Box sx={{ position: 'relative', display: 'inline-block', mb: 2 }}>
                <Avatar
                  src={displayPicture}
                  sx={{
                    width: 100,
                    height: 100,
                    mx: 'auto',
                    bgcolor: 'primary.main',
                    fontSize: '2.5rem',
                  }}
                  referrerPolicy="no-referrer"
                >
                  {!displayPicture && userInitial}
                </Avatar>

                <Tooltip title="Change profile picture">
                  <IconButton
                    size="small"
                    onClick={() => fileInputRef.current?.click()}
                    sx={{
                      position: 'absolute',
                      bottom: 0,
                      right: -4,
                      bgcolor: 'primary.main',
                      color: 'white',
                      border: '2px solid white',
                      width: 32,
                      height: 32,
                      '&:hover': { bgcolor: 'primary.dark' },
                    }}
                  >
                    <PhotoCameraIcon sx={{ fontSize: 16 }} />
                  </IconButton>
                </Tooltip>

                <input
                  ref={fileInputRef}
                  type="file"
                  accept="image/*"
                  hidden
                  onChange={handleFileChange}
                />
              </Box>

              {previewUrl && (
                <Box sx={{ display: 'flex', gap: 1, justifyContent: 'center', mb: 2 }}>
                  <Button
                    variant="contained"
                    size="small"
                    onClick={handleSavePicture}
                    disabled={uploading}
                    startIcon={uploading ? <CircularProgress size={14} color="inherit" /> : null}
                  >
                    {uploading ? 'Saving…' : 'Save'}
                  </Button>
                  <Button
                    variant="outlined"
                    size="small"
                    onClick={handleCancelPicture}
                    disabled={uploading}
                  >
                    Cancel
                  </Button>
                </Box>
              )}

              {uploadError && (
                <Alert severity="error" sx={{ mb: 2, textAlign: 'left' }}>
                  {uploadError}
                </Alert>
              )}
              {uploadSuccess && (
                <Alert severity="success" sx={{ mb: 2, textAlign: 'left' }}>
                  Profile picture updated.
                </Alert>
              )}

              <Typography variant="h5" gutterBottom>
                {user.name || 'User'}
              </Typography>

              <Typography variant="body2" color="textSecondary" gutterBottom>
                {user.email}
              </Typography>

              <Box sx={{ mt: 2 }}>
                <Chip
                  icon={isAdministrator ? <AdminPanelSettingsIcon /> : <PersonIcon />}
                  label={isAdministrator ? 'Administrator' : isApplicant ? 'Applicant' : 'User'}
                  color={isAdministrator ? 'primary' : 'secondary'}
                  variant="outlined"
                />
              </Box>
            </CardContent>
          </Card>
        </Grid>

        {/* Details Card */}
        <Grid item xs={12} md={8}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Account Information
              </Typography>

              <List>
                <ListItem>
                  <ListItemIcon>
                    <PersonIcon />
                  </ListItemIcon>
                  <ListItemText primary="Full Name" secondary={user.name || 'Not provided'} />
                </ListItem>

                <ListItem>
                  <ListItemIcon>
                    <EmailIcon />
                  </ListItemIcon>
                  <ListItemText primary="Email Address" secondary={user.email || 'Not provided'} />
                </ListItem>

                <ListItem>
                  <ListItemIcon>
                    <BusinessIcon />
                  </ListItemIcon>
                  {organizations.length > 1 ? (
                    <FormControl fullWidth size="small">
                      <InputLabel id="org-select-label">Organization</InputLabel>
                      <Select
                        labelId="org-select-label"
                        value={organizationId || ''}
                        label="Organization"
                        onChange={(event) => setActiveOrganizationId(event.target.value)}
                      >
                        {organizations.map((org) => (
                          <MenuItem key={org.id} value={org.id}>
                            {org.name || org.id}
                          </MenuItem>
                        ))}
                      </Select>
                    </FormControl>
                  ) : (
                    <ListItemText
                      primary="Organization"
                      secondary={(organizations || [])[0]?.name || 'Not assigned'}
                    />
                  )}
                </ListItem>

                <ListItem>
                  <ListItemIcon>
                    <BadgeIcon />
                  </ListItemIcon>
                  <ListItemText
                    primary="Account ID"
                    secondary={
                      <Typography variant="body2" fontFamily="monospace">
                        {user.id || user.subject || 'N/A'}
                      </Typography>
                    }
                  />
                </ListItem>

                {user.nationality && (
                  <ListItem>
                    <ListItemIcon>
                      <PublicIcon />
                    </ListItemIcon>
                    <ListItemText primary="Nationality" secondary={user.nationality} />
                  </ListItem>
                )}

                {user.date_of_birth && (
                  <ListItem>
                    <ListItemIcon>
                      <CakeIcon />
                    </ListItemIcon>
                    <ListItemText
                      primary="Date of Birth"
                      secondary={formatDate(user.date_of_birth)}
                    />
                  </ListItem>
                )}
              </List>

              <Divider sx={{ my: 2 }} />

              <Typography variant="h6" gutterBottom>
                Security Information
              </Typography>

              <List>
                <ListItem>
                  <ListItemIcon>
                    <SecurityIcon />
                  </ListItemIcon>
                  <ListItemText
                    primary="Authentication Provider"
                    secondary="Keycloak OpenID Connect"
                  />
                </ListItem>

                {user.applicant_id && (
                  <ListItem>
                    <ListItemIcon>
                      <BadgeIcon />
                    </ListItemIcon>
                    <ListItemText
                      primary="Applicant Record ID"
                      secondary={
                        <Typography variant="body2" fontFamily="monospace">
                          {user.applicant_id}
                        </Typography>
                      }
                    />
                  </ListItem>
                )}
              </List>

              {/* Roles */}
              {user.roles && user.roles.length > 0 && (
                <>
                  <Divider sx={{ my: 2 }} />
                  <Typography variant="h6" gutterBottom>
                    Assigned Roles
                  </Typography>
                  <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1 }}>
                    {user.roles.map((role) => (
                      <Chip key={role} label={role} size="small" variant="outlined" />
                    ))}
                  </Box>
                </>
              )}
            </CardContent>
          </Card>
        </Grid>
      </Grid>
    </Box>
  );
}

export default ProfilePage;

/**
 * Profile Page Component
 *
 * Shows user profile information from the authenticated account response.
 * Supports viewing and uploading a profile picture.
 * Available to all authenticated users.
 */

import { useLayoutEffect, useRef, useState } from 'react';
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
import { useConsole } from '../contexts/ConsoleContext';
import { updateProfilePicture, startPasskeyEnrollment } from '../services/authApi';
import { formatOfficialReference, pickOfficialReference } from '../utils/officialReferences';
import OrganizationMembershipHub from './organizations/OrganizationMembershipHub';

function ProfilePage() {
  const auth = useAuth();
  const accountId = auth.user?.user_id || auth.user?.sub || auth.user?.id || auth.user?.subject || auth.user?.email;
  return <AccountProfile key={accountId || 'no-account'} auth={auth} />;
}

function AccountProfile({ auth }) {
  const {
    user,
    isAdministrator,
    isApplicant,
    organizationId,
    organizations = [],
    refreshUser,
  } = auth;
  const { activeOrgId, setActiveOrgId } = useConsole();

  const fileInputRef = useRef(null);
  const readerRef = useRef(null);
  const pictureGeneration = useRef(0);
  const savePending = useRef(false);
  const [previewUrl, setPreviewUrl] = useState(null);
  const [readingPhoto, setReadingPhoto] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [uploadError, setUploadError] = useState(null);
  const [uploadSuccess, setUploadSuccess] = useState(false);
  const [enrollingPasskey, setEnrollingPasskey] = useState(false);
  const [passkeyError, setPasskeyError] = useState(null);
  const [passkeyEmailSent, setPasskeyEmailSent] = useState(false);

  const handleCreatePasskey = async () => {
    setEnrollingPasskey(true);
    setPasskeyError(null);
    try {
      const result = await startPasskeyEnrollment(window.location.pathname);
      if (result?.email_sent) {
        setPasskeyEmailSent(true);
        setEnrollingPasskey(false);
      }
    } catch (error) {
      setPasskeyError(error.message);
      setEnrollingPasskey(false);
    }
  };

  useLayoutEffect(() => () => {
    pictureGeneration.current += 1;
    readerRef.current?.abort();
    readerRef.current = null;
  }, []);

  if (!user) {
    return (
      <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'center', minHeight: '40vh' }}>
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
  const fullName = user.name?.trim()
    || [user.given_name, user.family_name].map((name) => name?.trim()).filter(Boolean).join(' ');
  const displayName = fullName || user.username?.trim() || user.preferred_username?.trim() || user.email || 'User';
  const userInitial = displayName[0].toUpperCase();
  const accountReference = pickOfficialReference({
    rawId: user.user_id || user.id || user.subject,
    kind: 'account',
  });
  const applicantReference = pickOfficialReference({
    rawId: user.applicant_id,
    kind: 'applicant',
  });

  const handleFileChange = (e) => {
    const file = e.target.files?.[0];
    if (!file || savePending.current) return;

    const generation = ++pictureGeneration.current;
    readerRef.current?.abort();
    readerRef.current = null;
    // Allow the same file to be selected again after cancellation or a failure.
    e.target.value = '';
    setReadingPhoto(false);
    setPreviewUrl(null);
    setUploadError(null);
    setUploadSuccess(false);

    if (!file.type.startsWith('image/')) {
      setUploadError('Please select an image file (JPEG, PNG, GIF, WebP).');
      return;
    }
    if (file.size > 2 * 1024 * 1024) {
      setUploadError('Image must be smaller than 2 MB.');
      return;
    }

    const reader = new FileReader();
    readerRef.current = reader;
    setReadingPhoto(true);
    const isCurrentRead = () => pictureGeneration.current === generation && readerRef.current === reader;
    const readFailed = () => {
      if (!isCurrentRead()) return;
      readerRef.current = null;
      setReadingPhoto(false);
      setUploadError('Unable to read this image. Please select it again.');
    };
    reader.onload = (ev) => {
      if (!isCurrentRead()) return;
      if (typeof ev.target?.result !== 'string' || !ev.target.result) {
        readFailed();
        return;
      }
      readerRef.current = null;
      setReadingPhoto(false);
      setPreviewUrl(ev.target.result);
    };
    reader.onerror = readFailed;
    try {
      reader.readAsDataURL(file);
    } catch {
      readFailed();
    }
  };

  const handleSavePicture = async () => {
    if (!previewUrl || readerRef.current || savePending.current) return;

    const generation = pictureGeneration.current;
    const isCurrentSave = () => pictureGeneration.current === generation;
    savePending.current = true;
    setUploading(true);
    setUploadError(null);
    setUploadSuccess(false);

    try {
      const result = await updateProfilePicture(previewUrl);
      if (!isCurrentSave()) return;
      if (result.success) {
        setUploadSuccess(true);
        setPreviewUrl(null);
        try {
          await refreshUser();
        } catch {
          if (isCurrentSave()) setUploadError('Your picture was saved, but account details could not be refreshed. Reload the page to see it.');
        }
      } else {
        setUploadError(result.error || 'Failed to update profile picture.');
      }
    } catch {
      if (isCurrentSave()) setUploadError('Failed to update profile picture.');
    } finally {
      if (isCurrentSave()) {
        savePending.current = false;
        setUploading(false);
      }
    }
  };

  const handleCancelPicture = () => {
    if (savePending.current) return;
    pictureGeneration.current += 1;
    readerRef.current?.abort();
    readerRef.current = null;
    setReadingPhoto(false);
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
        <Grid size={{ xs: 12, md: 4 }}>
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
                  <span>
                    <IconButton
                      size="small"
                      aria-label="Change profile picture"
                      disabled={uploading}
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
                  </span>
                </Tooltip>

                <input
                  ref={fileInputRef}
                  type="file"
                  accept="image/*"
                  hidden
                  disabled={uploading}
                  onChange={handleFileChange}
                />
              </Box>

              {(previewUrl || readingPhoto) && (
                <Box sx={{ display: 'flex', gap: 1, justifyContent: 'center', mb: 2 }}>
                  <Button
                    variant="contained"
                    size="small"
                    onClick={handleSavePicture}
                    disabled={uploading || readingPhoto}
                    startIcon={uploading || readingPhoto ? <CircularProgress size={14} color="inherit" /> : null}
                  >
                    {uploading ? 'Saving…' : readingPhoto ? 'Reading…' : 'Save'}
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
                {displayName}
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
        <Grid size={{ xs: 12, md: 8 }}>
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
                  <ListItemText primary="Full Name" secondary={fullName || 'Not provided'} />
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
                  <ListItemText
                    primary="Default applicant organization"
                    secondary={
                      organizations.find((organization) => organization.id === organizationId)?.name
                      || (organizationId ? formatOfficialReference(organizationId, 'organization') : 'Not assigned')
                    }
                  />
                </ListItem>

                <ListItem>
                  <ListItemIcon>
                    <BadgeIcon />
                  </ListItemIcon>
                  <ListItemText
                    primary="Account Reference"
                    secondary={
                      <Typography variant="body2" sx={{ fontFamily: 'monospace' }}>
                        {accountReference}
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
                      primary="Applicant Reference"
                      secondary={
                        <Typography variant="body2" sx={{ fontFamily: 'monospace' }}>
                          {applicantReference}
                        </Typography>
                      }
                    />
                  </ListItem>
                )}
              </List>

              {/* Roles */}
              {user.passkey_enrollment_available && (
                <Box sx={{ my: 2 }} data-testid="profile-passkey-enrollment">
                  <Typography variant="h6" gutterBottom>Passkeys</Typography>
                  <Typography variant="body2" sx={{ mb: 2 }}>
                    Create a passkey for this account using your phone, computer, or security key.
                    Your other sign-in options stay available. You will confirm your account before enrollment.
                  </Typography>
                  {passkeyError && <Alert severity="error" sx={{ mb: 2 }}>{passkeyError}</Alert>}
                  {passkeyEmailSent && <Alert severity="success" sx={{ mb: 2 }}>
                    Check your account email for a link to finish creating your passkey. The link expires in 5 minutes.
                  </Alert>}
                  <Button variant="outlined" onClick={handleCreatePasskey} disabled={enrollingPasskey || passkeyEmailSent}>
                    {passkeyEmailSent ? 'Enrollment email sent' : enrollingPasskey ? 'Opening passkey setup…' : 'Create a passkey'}
                  </Button>
                  {user.passkey_management_url && (
                    <Box sx={{ mt: 2 }}>
                      <Button component="a" href={user.passkey_management_url}>Manage passkeys</Button>
                      <Typography variant="body2" color="text.secondary">
                        Confirm your account in the identity account console to rename or remove passkeys.
                        Keep another passkey or a working password before removing your last passkey.
                      </Typography>
                    </Box>
                  )}
                </Box>
              )}
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

        <Grid size={12}>
          <Card>
            <CardContent>
              <OrganizationMembershipHub
                organizations={organizations}
                activeOrgId={activeOrgId || organizationId}
                onSwitchToOrg={setActiveOrgId}
                embedded
                showManagePageLink
                managePath="/console/organizations"
                discoverPath="/console/organizations/discover"
                joinPath="/console/organizations/join"
                dataTestId="profile-organization-membership-section"
                title="Organization Memberships"
                description="Manage your current memberships and jump into the existing organizations flow to discover public organizations or join one with a code."
              />
            </CardContent>
          </Card>
        </Grid>
      </Grid>
    </Box>
  );
}

export default ProfilePage;

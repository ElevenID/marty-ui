/**
 * Profile Page Component
 *
 * Shows user profile information from OIDC claims.
 * Available to all authenticated users.
 */

import React from 'react';
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
} from '@mui/material';
import PersonIcon from '@mui/icons-material/Person';
import EmailIcon from '@mui/icons-material/Email';
import BadgeIcon from '@mui/icons-material/Badge';
import PublicIcon from '@mui/icons-material/Public';
import CakeIcon from '@mui/icons-material/Cake';
import SecurityIcon from '@mui/icons-material/Security';
import AdminPanelSettingsIcon from '@mui/icons-material/AdminPanelSettings';
import BusinessIcon from '@mui/icons-material/Business';
import { useAuth } from '../hooks/useAuth';

function ProfilePage() {
  const {
    user,
    isAdministrator,
    isApplicant,
    organizationId,
    organizations,
    setActiveOrganizationId,
  } = useAuth();

  if (!user) {
    return (
      <Box>
        <Typography>Loading profile...</Typography>
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
              <Avatar
                sx={{
                  width: 100,
                  height: 100,
                  mx: 'auto',
                  mb: 2,
                  bgcolor: isAdministrator ? 'primary.main' : 'secondary.main',
                  fontSize: '2.5rem',
                }}
              >
                {user.name?.charAt(0).toUpperCase() || 'U'}
              </Avatar>

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
                      secondary={organizations[0]?.name || 'Not assigned'}
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

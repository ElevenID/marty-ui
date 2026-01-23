/**
 * Vendor Create Organization Step Component
 * 
 * Step 2 for Vendors: Create a new organization with settings
 */

import React from 'react';
import {
  Box,
  Typography,
  TextField,
  Paper,
  FormControl,
  FormControlLabel,
  RadioGroup,
  Radio,
  Divider,
  Alert,
  Switch,
  Fade,
  InputAdornment,
  CircularProgress,
  InputLabel,
  Select,
  MenuItem,
} from '@mui/material';
import LockIcon from '@mui/icons-material/Lock';
import LockOpenIcon from '@mui/icons-material/LockOpen';
import HowToRegIcon from '@mui/icons-material/HowToReg';
import VisibilityIcon from '@mui/icons-material/Visibility';
import VisibilityOffIcon from '@mui/icons-material/VisibilityOff';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';

const VendorCreateOrgStep = ({
  orgName,
  onOrgNameChange,
  orgDescription,
  onOrgDescriptionChange,
  orgType,
  onOrgTypeChange,
  jurisdiction,
  onJurisdictionChange,
  isDiscoverable,
  onDiscoverableChange,
  membershipMode,
  onMembershipModeChange,
  orgDetailsLocked = false,
  orgNameChecking = false,
  orgNameAvailable = null,
  orgNameError = null,
}) => {
  return (
    <Fade in>
      <Box data-testid="vendor-create-org-step">
        <Typography variant="h5" gutterBottom textAlign="center">
          {orgDetailsLocked ? 'Organization Settings' : 'Create Your Organization'}
        </Typography>
        <Typography
          variant="body1"
          color="text.secondary"
          textAlign="center"
          sx={{ mb: 4 }}
        >
          {orgDetailsLocked
            ? 'Review visibility and membership settings for your organization'
            : 'Set up your organization to start issuing travel documents'}
        </Typography>

        <Box sx={{ maxWidth: 600, mx: 'auto' }} data-testid="org-details-form">
          {orgDetailsLocked && (
            <Alert severity="info" sx={{ mb: 3 }}>
              You're completing setup for <strong>{orgName || 'your organization'}</strong>.
            </Alert>
          )}

          {/* Organization Info */}
          <Typography variant="subtitle1" fontWeight="bold" sx={{ mb: 2 }}>
            Organization Details
          </Typography>
          <TextField
            fullWidth
            label="Organization Name"
            value={orgName}
            onChange={(e) => onOrgNameChange(e.target.value)}
            placeholder="e.g., Acme Travel Services"
            required
            disabled={orgDetailsLocked}
            error={!orgDetailsLocked && orgNameAvailable === false}
            helperText={
              !orgDetailsLocked && orgName && orgName.trim().length >= 3
                ? orgNameChecking
                  ? 'Checking availability...'
                  : orgNameAvailable === true
                  ? '✓ Name available'
                  : orgNameError || ''
                : !orgDetailsLocked && orgName && orgName.trim().length > 0 && orgName.trim().length < 3
                ? 'Name must be at least 3 characters'
                : ''
            }
            InputProps={{
              endAdornment: !orgDetailsLocked && orgName && orgName.trim().length >= 3 && (
                <InputAdornment position="end">
                  {orgNameChecking ? (
                    <CircularProgress size={20} />
                  ) : orgNameAvailable === true ? (
                    <CheckCircleIcon color="success" />
                  ) : null}
                </InputAdornment>
              ),
            }}
            sx={{
              mb: 2,
              '& .MuiFormHelperText-root': {
                color: orgNameAvailable === true ? 'success.main' : undefined,
              },
            }}
            data-testid="org-name-input"
          />
          
          <FormControl fullWidth sx={{ mb: 2 }}>
            <InputLabel id="org-type-label">Organization Type</InputLabel>
            <Select
              labelId="org-type-label"
              value={orgType || ''}
              onChange={(e) => onOrgTypeChange(e.target.value)}
              label="Organization Type"
              disabled={orgDetailsLocked}
              data-testid="org-type-select"
            >
              <MenuItem value="government">Government Agency</MenuItem>
              <MenuItem value="enterprise">Enterprise / Corporation</MenuItem>
              <MenuItem value="educational">Educational Institution</MenuItem>
              <MenuItem value="healthcare">Healthcare Provider</MenuItem>
              <MenuItem value="financial">Financial Services</MenuItem>
              <MenuItem value="other">Other</MenuItem>
            </Select>
          </FormControl>
          
          <FormControl fullWidth sx={{ mb: 2 }}>
            <InputLabel id="jurisdiction-label">Jurisdiction</InputLabel>
            <Select
              labelId="jurisdiction-label"
              value={jurisdiction || ''}
              onChange={(e) => onJurisdictionChange(e.target.value)}
              label="Jurisdiction"
              disabled={orgDetailsLocked}
              data-testid="jurisdiction-select"
            >
              <MenuItem value="US">United States</MenuItem>
              <MenuItem value="US-CA">United States - California</MenuItem>
              <MenuItem value="US-TX">United States - Texas</MenuItem>
              <MenuItem value="US-NY">United States - New York</MenuItem>
              <MenuItem value="US-FL">United States - Florida</MenuItem>
              <MenuItem value="CA">Canada</MenuItem>
              <MenuItem value="CA-ON">Canada - Ontario</MenuItem>
              <MenuItem value="CA-BC">Canada - British Columbia</MenuItem>
              <MenuItem value="CA-QC">Canada - Quebec</MenuItem>
              <MenuItem value="UK">United Kingdom</MenuItem>
              <MenuItem value="EU">European Union</MenuItem>
              <MenuItem value="DE">Germany</MenuItem>
              <MenuItem value="FR">France</MenuItem>
              <MenuItem value="ES">Spain</MenuItem>
              <MenuItem value="IT">Italy</MenuItem>
              <MenuItem value="NL">Netherlands</MenuItem>
              <MenuItem value="AU">Australia</MenuItem>
              <MenuItem value="NZ">New Zealand</MenuItem>
              <MenuItem value="JP">Japan</MenuItem>
              <MenuItem value="SG">Singapore</MenuItem>
              <MenuItem value="AE">United Arab Emirates</MenuItem>
              <MenuItem value="OTHER">Other</MenuItem>
            </Select>
          </FormControl>
          
          <TextField
            fullWidth
            label="Description (optional)"
            value={orgDescription}
            onChange={(e) => onOrgDescriptionChange(e.target.value)}
            placeholder="Brief description of your organization"
            multiline
            rows={2}
            disabled={orgDetailsLocked}
            sx={{ mb: 4 }}
            data-testid="org-description-input"
          />

          <Divider sx={{ my: 3 }} />

          {/* Visibility Settings */}
          <Typography variant="subtitle1" fontWeight="bold" sx={{ mb: 2 }}>
            Visibility Settings
          </Typography>
          
          <Paper variant="outlined" sx={{ p: 2, mb: 3 }}>
            <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                {isDiscoverable ? <VisibilityIcon color="primary" /> : <VisibilityOffIcon color="action" />}
                <Box>
                  <Typography variant="body1">Discoverable</Typography>
                  <Typography variant="body2" color="text.secondary">
                    {isDiscoverable
                      ? 'Your organization will appear in public listings'
                      : 'Only users with an invite code can find your organization'}
                  </Typography>
                </Box>
              </Box>
              <Switch
                checked={isDiscoverable}
                onChange={(e) => onDiscoverableChange(e.target.checked)}
              />
            </Box>
          </Paper>

          {/* Membership Mode */}
          <Typography variant="subtitle1" fontWeight="bold" sx={{ mb: 2 }}>
            How can users join?
          </Typography>
          
          <FormControl component="fieldset" sx={{ width: '100%' }}>
            <RadioGroup
              value={membershipMode}
              onChange={(e) => onMembershipModeChange(e.target.value)}
            >
              <Paper
                variant="outlined"
                sx={{
                  p: 2,
                  mb: 1,
                  cursor: 'pointer',
                  borderColor: membershipMode === 'invite_only' ? 'primary.main' : 'divider',
                }}
                onClick={() => onMembershipModeChange('invite_only')}
              >
                <FormControlLabel
                  value="invite_only"
                  control={<Radio />}
                  label={
                    <Box>
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                        <LockIcon fontSize="small" color="action" />
                        <Typography fontWeight="medium">Invite Only</Typography>
                      </Box>
                      <Typography variant="body2" color="text.secondary">
                        Users can only join via email invitation or invite code
                      </Typography>
                    </Box>
                  }
                  sx={{ m: 0, width: '100%' }}
                />
              </Paper>
              
              <Paper
                variant="outlined"
                sx={{
                  p: 2,
                  mb: 1,
                  cursor: 'pointer',
                  borderColor: membershipMode === 'approval' ? 'primary.main' : 'divider',
                }}
                onClick={() => onMembershipModeChange('approval')}
              >
                <FormControlLabel
                  value="approval"
                  control={<Radio />}
                  label={
                    <Box>
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                        <HowToRegIcon fontSize="small" color="warning" />
                        <Typography fontWeight="medium">Approval Required</Typography>
                      </Box>
                      <Typography variant="body2" color="text.secondary">
                        Users can request to join, you approve or deny requests
                      </Typography>
                    </Box>
                  }
                  sx={{ m: 0, width: '100%' }}
                />
              </Paper>
              
              <Paper
                variant="outlined"
                sx={{
                  p: 2,
                  cursor: 'pointer',
                  borderColor: membershipMode === 'open' ? 'primary.main' : 'divider',
                }}
                onClick={() => onMembershipModeChange('open')}
              >
                <FormControlLabel
                  value="open"
                  control={<Radio />}
                  label={
                    <Box>
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                        <LockOpenIcon fontSize="small" color="success" />
                        <Typography fontWeight="medium">Open</Typography>
                      </Box>
                      <Typography variant="body2" color="text.secondary">
                        Anyone can join directly without approval
                      </Typography>
                    </Box>
                  }
                  sx={{ m: 0, width: '100%' }}
                />
              </Paper>
            </RadioGroup>
          </FormControl>

          <Alert severity="info" sx={{ mt: 3 }}>
            <Typography variant="body2">
              {orgDetailsLocked
                ? 'You will see or regenerate your invite code after completing setup.'
                : "You'll receive an invite code after creating your organization. Share this code with users who need to join directly."}
            </Typography>
          </Alert>
        </Box>
      </Box>
    </Fade>
  );
};

export default VendorCreateOrgStep;

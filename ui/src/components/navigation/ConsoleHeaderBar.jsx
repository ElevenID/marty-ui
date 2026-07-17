/**
 * Console Header Bar
 * 
 * Top header bar for authenticated console pages.
 * Contains org switcher and user menu.
 */

import { useState } from 'react';
import {
  AppBar,
  Toolbar,
  Box,
  IconButton,
  Typography,
  Menu,
  MenuItem,
  Avatar,
  Divider,
  ListItemIcon,
  ListItemText,
  useMediaQuery,
  useTheme,
  Chip,
  Button,
  ToggleButtonGroup,
  ToggleButton,
  TextField,
  InputAdornment,
} from '@mui/material';
import { Link as RouterLink } from 'react-router-dom';
import { useNavigate } from 'react-router-dom';
import MenuIcon from '@mui/icons-material/Menu';
import PersonIcon from '@mui/icons-material/Person';
import LogoutIcon from '@mui/icons-material/Logout';
import SettingsIcon from '@mui/icons-material/Settings';
import HelpOutlineIcon from '@mui/icons-material/HelpOutlined';
import BusinessIcon from '@mui/icons-material/Business';
import ArrowDropDownIcon from '@mui/icons-material/ArrowDropDown';
import CheckIcon from '@mui/icons-material/Check';
import SearchIcon from '@mui/icons-material/Search';

import { useAuth } from '../../hooks/useAuth';
import { useBranding } from '../../hooks/useBranding';
import { useConsole } from '../../contexts/ConsoleContext';
import LanguageSwitcher from '../common/LanguageSwitcher';

const DEFAULT_MOBILE_LOGO_SRC = '/apple-touch-icon.png';

function getMembershipRoleSummary(organization) {
  const roles = organization?.membership?.roles || [];
  if (roles.length === 0) {
    return null;
  }

  if (roles.length === 1) {
    return roles[0].display_name || roles[0].name;
  }

  return `${roles.length} roles`;
}

function getCompactLabel(label, fallback = '', maxChars = 3) {
  const words = (label || '')
    .trim()
    .split(/\s+/)
    .filter(Boolean);

  if (words.length === 0) {
    return fallback;
  }

  if (words.length === 1) {
    return words[0].slice(0, maxChars).toUpperCase();
  }

  return words
    .slice(0, maxChars)
    .map((word) => word[0])
    .join('')
    .toUpperCase();
}

function isCanvasLtiUser(user) {
  return Boolean(
    user?.user_id?.startsWith?.('canvas-lti-')
    || (Array.isArray(user?.roles) && user.roles.includes('canvas_lti_learner'))
  );
}

function shortenIdentifier(value, maxChars = 28) {
  const normalized = String(value || '').trim();
  if (!normalized) {
    return '';
  }

  const localPart = normalized.includes('@') ? normalized.split('@')[0] : normalized;
  if (localPart.length <= maxChars) {
    return localPart;
  }

  const visibleChars = Math.max(2, maxChars - 3);
  const headChars = Math.ceil(visibleChars / 2);
  const tailChars = Math.floor(visibleChars / 2);
  return `${localPart.slice(0, headChars)}...${localPart.slice(-tailChars)}`;
}

function isOpaqueCanvasIdentifier(value) {
  const normalized = String(value || '').trim();
  if (!normalized) {
    return false;
  }

  return (
    normalized.startsWith('canvas-lti-')
    || /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(normalized)
    || /^[0-9a-f]{24,}$/i.test(normalized)
  );
}

function getFullName(user) {
  return [user?.given_name, user?.family_name]
    .map((value) => (typeof value === 'string' ? value.trim() : ''))
    .filter(Boolean)
    .join(' ');
}

function getFriendlyCanvasIdentifier(user) {
  for (const value of [user?.preferred_username, user?.username]) {
    const normalized = String(value || '').trim();
    if (normalized && !isOpaqueCanvasIdentifier(normalized)) {
      return shortenIdentifier(normalized);
    }
  }

  return '';
}

export function getAccountMenuDisplayName(user) {
  if (!user) {
    return 'User';
  }

  const identifier = shortenIdentifier(user.username || user.preferred_username || user.email || user.user_id);
  const fullName = getFullName(user);
  if (isCanvasLtiUser(user)) {
    return (
      getFriendlyCanvasIdentifier(user)
      || fullName
      || shortenIdentifier(user.email)
      || identifier
      || 'Canvas learner'
    );
  }

  return fullName || identifier || 'User';
}

export function getAccountAvatarInitial(user) {
  const displayName = getAccountMenuDisplayName(user);
  return displayName?.[0]?.toUpperCase() || 'U';
}

/**
 * Console Header Bar Component
 */
export function ConsoleHeaderBar({ onMobileMenuToggle }) {
  const navigate = useNavigate();
  const theme = useTheme();
  const isMobile = useMediaQuery(theme.breakpoints.down('md'));
  const { branding } = useBranding();
  const {
    user,
    logout,
    organizationId,
    organizationName,
    isAdministrator,
    isVendor,
    isApplicant,
  } = useAuth();
  const { mode, activeOrgId, memberships, isOrgBlocked, setActiveOrgId, setMode, isApplicantConsoleAvailable, isOrgConsoleAvailable } = useConsole();
  const [anchorEl, setAnchorEl] = useState(null);
  const [orgMenuAnchor, setOrgMenuAnchor] = useState(null);
  const [orgSearch, setOrgSearch] = useState('');
  const showConsoleSwitcher = isApplicantConsoleAvailable && isOrgConsoleAvailable;
  const selectableOrganizations = Array.isArray(memberships) ? memberships : [];
  const selectedOrgId = mode === 'org' ? activeOrgId : organizationId;
  const filteredOrganizations = [...selectableOrganizations]
    .filter((org) => {
      const haystack = `${org.display_name || ''} ${org.name || ''} ${org.id || ''}`.toLowerCase();
      return haystack.includes(orgSearch.trim().toLowerCase());
    })
    .sort((left, right) => {
      if (left.id === selectedOrgId) return -1;
      if (right.id === selectedOrgId) return 1;
      return String(left.display_name || left.name || left.id).localeCompare(String(right.display_name || right.name || right.id));
    });
  const brandLogoSrc = branding.logoUrl || DEFAULT_MOBILE_LOGO_SRC;

  // Find active org details
  const activeOrg = selectableOrganizations.find((org) => org.id === selectedOrgId)
    || (memberships || []).find((org) => org.id === activeOrgId)
    || null;
  const activeOrgName = activeOrg?.display_name || activeOrg?.name || organizationName || null;
  const compactOrgLabel = getCompactLabel(activeOrgName, 'Org');

  // Determine user role for display
  const userRole = isAdministrator ? 'Administrator' : isVendor ? 'Vendor' : isApplicant ? 'Person' : 'User';
  const profilePath = isApplicant ? '/console/applicant/profile' : '/console/org/profile';
  const settingsPath = mode === 'org' ? '/console/org/settings' : '/console/applicant/settings';
  const accountDisplayName = getAccountMenuDisplayName(user);
  const userInitials = getAccountAvatarInitial(user);

  const handleUserMenuOpen = (event) => {
    setAnchorEl(event.currentTarget);
  };

  const handleUserMenuClose = () => {
    setAnchorEl(null);
  };

  const handleLogout = () => {
    handleUserMenuClose();
    logout();
  };

  const handleSelectOrganization = async (organization) => {
    setOrgMenuAnchor(null);
    setOrgSearch('');

    try {
      await setActiveOrgId(organization.id);
    } catch (error) {
      console.error('[ConsoleHeaderBar] Failed to switch organization:', error);
    }
  };

  return (
    <AppBar
      position="fixed"
      elevation={1}
      sx={{
        bgcolor: 'primary.main',
        zIndex: theme.zIndex.drawer + 1,
      }}
    >
      <Toolbar sx={{ justifyContent: 'space-between', gap: 1, px: { xs: 1, sm: 2 } }}>
        {/* Left side: Mobile menu + Logo */}
        <Box sx={{ display: 'flex', alignItems: 'center', gap: isMobile ? 0.75 : 1, minWidth: 0 }}>
          {isMobile && (
            <IconButton
              color="inherit"
              aria-label="open drawer"
              edge="start"
              onClick={onMobileMenuToggle}
              sx={{
                color: 'text.primary',
                bgcolor: 'common.white',
                border: '1px solid',
                borderColor: 'grey.300',
                '&:hover': {
                  bgcolor: 'grey.100',
                  borderColor: 'grey.400',
                },
              }}
            >
              <MenuIcon />
            </IconButton>
          )}
          {isMobile ? (
            <Box
              component={RouterLink}
              to="/"
              aria-label={branding.appName}
              sx={{
                display: 'inline-flex',
                alignItems: 'center',
                textDecoration: 'none',
              }}
            >
              <Box
                component="img"
                src={brandLogoSrc}
                alt={branding.appName}
                sx={{
                  width: 30,
                  height: 30,
                  objectFit: 'contain',
                  bgcolor: 'common.white',
                  borderRadius: 1,
                  p: 0.25,
                }}
              />
            </Box>
          ) : (
            <Typography
              variant="h6"
              component={RouterLink}
              to="/"
              sx={{
                color: 'white',
                textDecoration: 'none',
                fontWeight: 600,
              }}
            >
              {branding.appName}
            </Typography>
          )}
        </Box>

        {/* Center: Console switcher (mobile only) */}
        {isMobile && showConsoleSwitcher && (
          <ToggleButtonGroup
            value={mode}
            exclusive
            onChange={(_, newMode) => { if (newMode) setMode(newMode); }}
            size="small"
            sx={{
              bgcolor: 'rgba(255,255,255,0.15)',
              borderRadius: '8px',
              '& .MuiToggleButton-root': {
                color: 'rgba(255,255,255,0.7)',
                border: 'none',
                px: 1.5,
                py: 0.5,
                textTransform: 'none',
                fontSize: '0.75rem',
                fontWeight: 500,
                '&.Mui-selected': {
                  bgcolor: 'rgba(255,255,255,0.25)',
                  color: 'white',
                  fontWeight: 700,
                  '&:hover': { bgcolor: 'rgba(255,255,255,0.3)' },
                },
                '&:hover': { bgcolor: 'rgba(255,255,255,0.1)' },
              },
            }}
          >
            <ToggleButton value="applicant" disabled={!isApplicantConsoleAvailable}>
              Me
            </ToggleButton>
            {isOrgConsoleAvailable && (
              <ToggleButton value="org">
                Org
              </ToggleButton>
            )}
          </ToggleButtonGroup>
        )}

        {/* Right side: User Menu */}
        <Box sx={{ display: 'flex', alignItems: 'center', gap: isMobile ? 0.5 : 1, minWidth: 0, flexShrink: 0 }}>
          <LanguageSwitcher
            variant="standard"
            compact={isMobile}
            sx={{
              minWidth: isMobile ? 72 : 130,
              mr: isMobile ? 0 : 1,
              bgcolor: 'common.white',
              border: '1px solid',
              borderColor: 'grey.300',
              borderRadius: 1,
              px: isMobile ? 0.5 : 1,
              '& .MuiInputBase-root': {
                color: 'text.primary',
              },
              '& .MuiOutlinedInput-notchedOutline': {
                borderColor: 'transparent',
              },
              '& .MuiSvgIcon-root': {
                color: 'text.primary',
              },
              '&:hover': {
                bgcolor: 'grey.100',
                borderColor: 'grey.400',
              },
            }}
          />

          {/* Organization status pill */}
          <Button
            onClick={(e) => {
              if (selectableOrganizations.length > 0) {
                setOrgMenuAnchor(e.currentTarget);
              }
            }}
            size="small"
            endIcon={<ArrowDropDownIcon />}
            startIcon={<BusinessIcon fontSize="small" />}
            disabled={selectableOrganizations.length === 0}
            title={activeOrgName || 'Select Organization'}
            sx={{
              mr: isMobile ? 0 : 1,
              color: 'text.primary',
              bgcolor: 'common.white',
              boxShadow: 'none',
              border: '1px solid',
              borderColor: 'grey.300',
              borderRadius: '20px',
              minWidth: isMobile ? 76 : 'auto',
              maxWidth: isMobile ? 88 : 260,
              px: isMobile ? 1.25 : 2,
              py: 0.5,
              textTransform: 'none',
              '& .MuiButton-startIcon': {
                mr: isMobile ? 0.5 : 1,
              },
              '& .MuiButton-endIcon': {
                ml: isMobile ? 0 : 0.5,
              },
              '&:hover': {
                bgcolor: 'grey.100',
                borderColor: 'grey.400',
                boxShadow: 'none',
              },
            }}
          >
            {isMobile ? compactOrgLabel : (activeOrgName || 'Select Organization')}
          </Button>
          <Menu
            anchorEl={orgMenuAnchor}
            open={Boolean(orgMenuAnchor)}
            onClose={() => { setOrgMenuAnchor(null); setOrgSearch(''); }}
            transformOrigin={{ horizontal: 'right', vertical: 'top' }}
            anchorOrigin={{ horizontal: 'right', vertical: 'bottom' }}
            PaperProps={{
              elevation: 0,
              sx: {
                overflow: 'hidden',
                filter: 'drop-shadow(0px 2px 8px rgba(0,0,0,0.1))',
                mt: 1,
                minWidth: 280,
                maxWidth: 'calc(100vw - 24px)',
              },
            }}
          >
            {selectableOrganizations.length > 0 && (
              <Box sx={{ px: 1.5, pt: 1.25, pb: 0.75 }}>
                <Typography variant="caption" color="text.secondary" fontWeight={600}>
                  Your Organizations
                </Typography>
                <TextField
                  autoFocus
                  fullWidth
                  size="small"
                  placeholder="Search organizations"
                  value={orgSearch}
                  onChange={(event) => setOrgSearch(event.target.value)}
                  onKeyDown={(event) => event.stopPropagation()}
                  sx={{ mt: 0.75 }}
                  InputProps={{
                    startAdornment: (
                      <InputAdornment position="start"><SearchIcon fontSize="small" /></InputAdornment>
                    ),
                  }}
                />
              </Box>
            )}
            <Box sx={{ maxHeight: 360, overflowY: 'auto' }}>
              {filteredOrganizations.map((org) => (
                <MenuItem
                  key={org.id}
                  selected={org.id === selectedOrgId}
                  onClick={() => handleSelectOrganization(org)}
                >
                  <ListItemIcon><BusinessIcon fontSize="small" /></ListItemIcon>
                  <ListItemText
                    primary={org.display_name || org.name || org.id}
                    secondary={getMembershipRoleSummary(org)}
                    primaryTypographyProps={{ variant: 'body2', noWrap: true }}
                    secondaryTypographyProps={{ variant: 'caption' }}
                  />
                  {org.id === selectedOrgId && <CheckIcon fontSize="small" color="primary" sx={{ ml: 1 }} />}
                </MenuItem>
              ))}
              {filteredOrganizations.length === 0 && (
                <MenuItem disabled>No matching organizations</MenuItem>
              )}
            </Box>
            {selectableOrganizations.length > 0 && <Divider />}
            <MenuItem
              onClick={() => {
                setOrgMenuAnchor(null);
                navigate('/organizations/discover');
              }}
            >
              <ListItemIcon>
                <SearchIcon fontSize="small" />
              </ListItemIcon>
              <ListItemText>Search &amp; Join Organizations</ListItemText>
            </MenuItem>
          </Menu>

          {!isMobile && (
            <Button
              onClick={handleLogout}
              startIcon={<LogoutIcon />}
              size="small"
              variant="contained"
              sx={{
                color: 'text.primary',
                bgcolor: 'common.white',
                boxShadow: 'none',
                border: '1px solid',
                borderColor: 'grey.300',
                '&:hover': {
                  bgcolor: 'grey.100',
                  borderColor: 'grey.400',
                  boxShadow: 'none',
                },
              }}
            >
              Logout
            </Button>
          )}

          <IconButton
            onClick={handleUserMenuOpen}
            size="small"
            data-testid="console-account-menu-button"
            aria-label={`Account menu for ${accountDisplayName}`}
            sx={{
              ml: isMobile ? 0 : 2,
              bgcolor: 'common.white',
              border: '1px solid',
              borderColor: 'grey.300',
              '&:hover': {
                bgcolor: 'grey.100',
                borderColor: 'grey.400',
              },
            }}
            aria-controls={anchorEl ? 'account-menu' : undefined}
            aria-haspopup="true"
            aria-expanded={anchorEl ? 'true' : undefined}
          >
            <Avatar
                sx={{ width: 32, height: 32, bgcolor: 'primary.main', color: 'common.white' }}
                src={user?.picture || undefined}
              >
                {!user?.picture && userInitials}
              </Avatar>
          </IconButton>
        </Box>

        {/* User Menu Dropdown */}
        <Menu
          anchorEl={anchorEl}
          id="account-menu"
          open={Boolean(anchorEl)}
          onClose={handleUserMenuClose}
          onClick={handleUserMenuClose}
          transformOrigin={{ horizontal: 'right', vertical: 'top' }}
          anchorOrigin={{ horizontal: 'right', vertical: 'bottom' }}
          PaperProps={{
            elevation: 0,
            sx: {
              overflow: 'visible',
              filter: 'drop-shadow(0px 2px 8px rgba(0,0,0,0.1))',
              mt: 1.5,
              minWidth: 200,
            },
          }}
        >
          <Box sx={{ px: 2, py: 1 }}>
            <Typography variant="subtitle2" fontWeight={600}>
              {accountDisplayName}
            </Typography>
            <Chip
              label={userRole}
              size="small"
              color="primary"
              variant="outlined"
              sx={{ mt: 0.5, height: 20, fontSize: '0.7rem' }}
            />
          </Box>
          <Divider />
          <MenuItem component={RouterLink} to={profilePath}>
            <ListItemIcon>
              <PersonIcon fontSize="small" />
            </ListItemIcon>
            <ListItemText>Profile</ListItemText>
          </MenuItem>
          <MenuItem component={RouterLink} to={settingsPath}>
            <ListItemIcon>
              <SettingsIcon fontSize="small" />
            </ListItemIcon>
            <ListItemText>Settings</ListItemText>
          </MenuItem>
          <MenuItem component={RouterLink} to="/docs">
            <ListItemIcon>
              <HelpOutlineIcon fontSize="small" />
            </ListItemIcon>
            <ListItemText>Help & Docs</ListItemText>
          </MenuItem>
          <Divider />
          <MenuItem onClick={handleLogout}>
            <ListItemIcon>
              <LogoutIcon fontSize="small" />
            </ListItemIcon>
            <ListItemText>Sign out</ListItemText>
          </MenuItem>
        </Menu>
      </Toolbar>
    </AppBar>
  );
}

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
} from '@mui/material';
import { Link as RouterLink } from 'react-router-dom';
import { useNavigate } from 'react-router-dom';
import MenuIcon from '@mui/icons-material/Menu';
import PersonIcon from '@mui/icons-material/Person';
import LogoutIcon from '@mui/icons-material/Logout';
import SettingsIcon from '@mui/icons-material/Settings';
import HelpOutlineIcon from '@mui/icons-material/HelpOutline';
import BusinessIcon from '@mui/icons-material/Business';
import ArrowDropDownIcon from '@mui/icons-material/ArrowDropDown';
import CheckIcon from '@mui/icons-material/Check';
import SearchIcon from '@mui/icons-material/Search';

import { useAuth } from '../../hooks/useAuth';
import { useConsole } from '../../contexts/ConsoleContext';
import LanguageSwitcher from '../common/LanguageSwitcher';

/**
 * Console Header Bar Component
 */
export function ConsoleHeaderBar({ onMobileMenuToggle }) {
  const navigate = useNavigate();
  const theme = useTheme();
  const isMobile = useMediaQuery(theme.breakpoints.down('md'));
  const { user, logout, organizationName, isAdministrator, isVendor, isApplicant } = useAuth();
  const { mode, activeOrgId, memberships, isOrgBlocked, setActiveOrgId, setMode, isApplicantConsoleAvailable, isOrgConsoleAvailable } = useConsole();
  const [anchorEl, setAnchorEl] = useState(null);
  const [orgMenuAnchor, setOrgMenuAnchor] = useState(null);
  const showConsoleSwitcher = isApplicantConsoleAvailable && isOrgConsoleAvailable;

  // Find active org details
  const activeOrg = (memberships || []).find(org => org.id === activeOrgId);
  const activeOrgName = activeOrg?.display_name || activeOrg?.name || null;

  // Determine user role for display
  const userRole = isAdministrator ? 'Administrator' : isVendor ? 'Vendor' : isApplicant ? 'Person' : 'User';
  const profilePath = isApplicant ? '/console/applicant/profile' : '/console/org/profile';

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

  const userInitials = user?.given_name?.[0] || user?.email?.[0]?.toUpperCase() || 'U';

  return (
    <AppBar
      position="fixed"
      elevation={1}
      sx={{
        bgcolor: 'primary.main',
        zIndex: theme.zIndex.drawer + 1,
      }}
    >
      <Toolbar sx={{ justifyContent: 'space-between' }}>
        {/* Left side: Mobile menu + Logo */}
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
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
            ElevenID LLC
          </Typography>
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
              <PersonIcon sx={{ fontSize: 16, mr: 0.5 }} />
              Me
            </ToggleButton>
            {isOrgConsoleAvailable && (
              <ToggleButton value="org">
                <BusinessIcon sx={{ fontSize: 16, mr: 0.5 }} />
                Org
              </ToggleButton>
            )}
          </ToggleButtonGroup>
        )}

        {/* Right side: User Menu */}
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          <LanguageSwitcher
            variant="standard"
            sx={{
              minWidth: 130,
              mr: 1,
              bgcolor: 'common.white',
              border: '1px solid',
              borderColor: 'grey.300',
              borderRadius: 1,
              px: 1,
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
            onClick={(e) => setOrgMenuAnchor(e.currentTarget)}
            size="small"
            endIcon={<ArrowDropDownIcon />}
            startIcon={<BusinessIcon fontSize="small" />}
            sx={{
              mr: 1,
              color: 'text.primary',
              bgcolor: 'common.white',
              boxShadow: 'none',
              border: '1px solid',
              borderColor: 'grey.300',
              borderRadius: '20px',
              px: 2,
              py: 0.5,
              textTransform: 'none',
              '&:hover': {
                bgcolor: 'grey.100',
                borderColor: 'grey.400',
                boxShadow: 'none',
              },
            }}
          >
            {activeOrgName || 'Select Organization'}
          </Button>
          <Menu
            anchorEl={orgMenuAnchor}
            open={Boolean(orgMenuAnchor)}
            onClose={() => setOrgMenuAnchor(null)}
            transformOrigin={{ horizontal: 'right', vertical: 'top' }}
            anchorOrigin={{ horizontal: 'right', vertical: 'bottom' }}
            PaperProps={{
              elevation: 0,
              sx: {
                overflow: 'visible',
                filter: 'drop-shadow(0px 2px 8px rgba(0,0,0,0.1))',
                mt: 1,
                minWidth: 220,
              },
            }}
          >
            {(memberships || []).length > 0 && (
              <Box sx={{ px: 2, py: 0.5 }}>
                <Typography variant="caption" color="text.secondary" fontWeight={600}>
                  Your Organizations
                </Typography>
              </Box>
            )}
            {(memberships || []).map((org) => (
              <MenuItem
                key={org.id}
                selected={org.id === activeOrgId}
                onClick={async () => {
                  await setActiveOrgId(org.id);
                  setOrgMenuAnchor(null);
                }}
              >
                <ListItemIcon>
                  <BusinessIcon fontSize="small" />
                </ListItemIcon>
                <ListItemText
                  primary={org.display_name || org.name || org.id}
                  secondary={org.membership?.role || null}
                  primaryTypographyProps={{ variant: 'body2' }}
                  secondaryTypographyProps={{ variant: 'caption' }}
                />
                {org.id === activeOrgId && (
                  <CheckIcon fontSize="small" color="primary" sx={{ ml: 1 }} />
                )}
              </MenuItem>
            ))}
            {(memberships || []).length > 0 && <Divider />}
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

          <IconButton
            onClick={handleUserMenuOpen}
            size="small"
            sx={{
              ml: 2,
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
              {user?.given_name || user?.email || 'User'}
            </Typography>
            {organizationName && (
              <Typography variant="caption" color="text.secondary">
                {organizationName}
              </Typography>
            )}
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
          <MenuItem component={RouterLink} to="/console/applicant/settings">
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

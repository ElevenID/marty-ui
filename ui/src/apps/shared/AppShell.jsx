import { useContext, useEffect, useMemo, useState } from 'react';
import { useLocation } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { ThemeProvider, createTheme } from '@mui/material/styles';
import CssBaseline from '@mui/material/CssBaseline';
import {
  AppBar,
  Avatar,
  Box,
  Button,
  Chip,
  Divider,
  IconButton,
  ListItemIcon,
  ListItemText,
  Menu,
  MenuItem,
  Toolbar,
  Tooltip,
  Typography,
} from '@mui/material';
import LoginIcon from '@mui/icons-material/Login';
import LogoutIcon from '@mui/icons-material/Logout';
import AdminPanelSettingsIcon from '@mui/icons-material/AdminPanelSettings';
import PersonIcon from '@mui/icons-material/Person';
import BusinessIcon from '@mui/icons-material/Business';
import StorefrontIcon from '@mui/icons-material/Storefront';
import SettingsIcon from '@mui/icons-material/Settings';
import NotificationsIcon from '@mui/icons-material/Notifications';
import PaymentIcon from '@mui/icons-material/Payment';

import { AuthContext } from '../../contexts/AuthContext';
import { BrandingContext } from '../../contexts/BrandingContext';
import {
  DISABLE_PUBLIC_LOGIN_BUTTON,
  SHOW_PUBLIC_LOGIN_BUTTON,
} from '@ui-public-config';
import { NotificationBell, LanguageSwitcher } from '../../components/common';
import ImpersonationBanner from '../../components/ImpersonationBanner';
import { initAnalytics, trackPageView, trackWebVitals } from '../../utils/analytics';
import { isAdminImpersonationEnabled } from '../../utils/runtimeConfig';

function createDynamicTheme(branding) {
  return createTheme({
    palette: {
      primary: {
        main: branding.primaryColor || '#1976d2',
      },
      secondary: {
        main: branding.secondaryColor || '#dc004e',
      },
    },
  });
}

function AppShell({ children, showAppBar = true }) {
  const location = useLocation();
  const { t } = useTranslation('common');
  const auth = useContext(AuthContext) || {};
  const brandingContext = useContext(BrandingContext);
  const fallbackBranding = useMemo(() => ({
    appName: 'ElevenID LLC',
    primaryColor: '#1976d2',
    secondaryColor: '#dc004e',
    logoUrl: null,
  }), []);

  const {
    isAuthenticated = false,
    isAdministrator = false,
    isApplicant = false,
    isVendor = false,
    organizationName = null,
    user = null,
    login = () => {},
    logout = () => {},
  } = auth;

  const runtimeBranding = brandingContext?.branding;
  const branding = useMemo(
    () => runtimeBranding || fallbackBranding,
    [runtimeBranding, fallbackBranding],
  );

  const [settingsAnchorEl, setSettingsAnchorEl] = useState(null);
  const settingsMenuOpen = Boolean(settingsAnchorEl);

  const handleSettingsClick = (event) => {
    setSettingsAnchorEl(event.currentTarget);
  };

  const handleSettingsClose = () => {
    setSettingsAnchorEl(null);
  };

  const theme = useMemo(() => createDynamicTheme(branding), [branding]);
  const adminImpersonationEnabled = isAdminImpersonationEnabled();

  useEffect(() => {
    initAnalytics();
    trackWebVitals();
  }, []);

  useEffect(() => {
    trackPageView(`${location.pathname}${location.search}`, document.title);
  }, [location.pathname, location.search]);

  const getUserDisplayName = () => {
    if (!user) return t('common.user');
    return user.given_name || user.username || user.email || t('common.user');
  };

  const getUserTypeLabel = () => {
    if (isAdministrator) return t('userTypes.administrator');
    if (isVendor) return t('common.organizationMember', 'Organization Member');
    if (isApplicant) return t('common.person', 'Person');
    return t('userTypes.user');
  };

  const getUserTypeIcon = () => {
    if (isAdministrator) return <AdminPanelSettingsIcon />;
    if (isVendor) return <StorefrontIcon />;
    return <PersonIcon />;
  };

  return (
    <ThemeProvider theme={theme}>
      <CssBaseline />
      {adminImpersonationEnabled && isAuthenticated && <ImpersonationBanner />}
      {showAppBar && (
        <AppBar position="static">
          <Toolbar>
            {branding.logoUrl && (
              <Box component="img" src={branding.logoUrl} alt={branding.appName} sx={{ height: 32, mr: 2 }} />
            )}
            <Typography variant="h6" component="div" sx={{ flexGrow: 1 }}>
              {branding.appName}
            </Typography>

            <LanguageSwitcher
              variant="standard"
              sx={{
                mr: 2,
                minWidth: 120,
                '& .MuiInputBase-root': {
                  color: 'common.white',
                },
                '& .MuiSelect-select': {
                  color: 'common.white',
                },
                '& .MuiSvgIcon-root': {
                  color: 'common.white',
                },
                '& .MuiInputAdornment-root .MuiSvgIcon-root': {
                  color: 'common.white',
                },
                '& .MuiInput-underline:before': {
                  borderBottomColor: 'rgba(255, 255, 255, 0.7)',
                },
                '& .MuiInput-underline:hover:not(.Mui-disabled):before': {
                  borderBottomColor: 'rgba(255, 255, 255, 0.9)',
                },
                '& .MuiInput-underline:after': {
                  borderBottomColor: 'common.white',
                },
              }}
            />

            <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
              {isAuthenticated ? (
                <>
                  {isVendor && organizationName && (
                    <Tooltip title={t('common.yourOrganization')}>
                      <Chip
                        icon={<BusinessIcon />}
                        label={organizationName}
                        size="small"
                        variant="filled"
                        sx={{ bgcolor: 'rgba(255, 255, 255, 0.2)', color: 'white' }}
                      />
                    </Tooltip>
                  )}

                  <Chip
                    icon={getUserTypeIcon()}
                    label={getUserTypeLabel()}
                    size="small"
                    variant="outlined"
                    sx={{ borderColor: 'white', color: 'white' }}
                    data-testid="user-type-badge"
                  />

                  <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                    <Avatar
                      src={user?.picture || undefined}
                      sx={{ width: 32, height: 32, bgcolor: 'rgba(255, 255, 255, 0.3)' }}
                    >
                      {!user?.picture && getUserDisplayName().charAt(0).toUpperCase()}
                    </Avatar>
                    <Typography variant="body2" sx={{ color: 'white' }}>
                      {getUserDisplayName()}
                    </Typography>
                  </Box>

                  {isVendor && <NotificationBell />}

                  {isVendor && (
                    <>
                      <Tooltip title={t('common.settings')}>
                        <IconButton
                          onClick={handleSettingsClick}
                          size="small"
                          sx={{ color: 'white' }}
                          aria-controls={settingsMenuOpen ? 'settings-menu' : undefined}
                          aria-haspopup="true"
                          aria-expanded={settingsMenuOpen ? 'true' : undefined}
                          data-testid="settings-button"
                        >
                          <SettingsIcon />
                        </IconButton>
                      </Tooltip>
                      <Menu
                        id="settings-menu"
                        anchorEl={settingsAnchorEl}
                        open={settingsMenuOpen}
                        onClose={handleSettingsClose}
                        MenuListProps={{
                          'aria-labelledby': 'settings-button',
                        }}
                        transformOrigin={{ horizontal: 'right', vertical: 'top' }}
                        anchorOrigin={{ horizontal: 'right', vertical: 'bottom' }}
                      >
                        <MenuItem component="a" href="/console/org/settings" onClick={handleSettingsClose}>
                          <ListItemIcon>
                            <BusinessIcon fontSize="small" />
                          </ListItemIcon>
                          <ListItemText>{t('common.organizationProfile')}</ListItemText>
                        </MenuItem>
                        <MenuItem component="a" href="/console/org/notifications" onClick={handleSettingsClose}>
                          <ListItemIcon>
                            <NotificationsIcon fontSize="small" />
                          </ListItemIcon>
                          <ListItemText>{t('common.notifications')}</ListItemText>
                        </MenuItem>
                        <MenuItem disabled>
                          <ListItemIcon>
                            <PaymentIcon fontSize="small" />
                          </ListItemIcon>
                          <ListItemText>{t('common.billingSubscription')}</ListItemText>
                        </MenuItem>
                        <Divider />
                        <MenuItem disabled>
                          <ListItemText sx={{ color: 'error.main' }}>{t('common.deleteOrganization')}</ListItemText>
                        </MenuItem>
                      </Menu>
                    </>
                  )}

                  <Button
                    variant="outlined"
                    size="small"
                    startIcon={<LogoutIcon />}
                    onClick={logout}
                    sx={{ borderColor: 'white', color: 'white', '&:hover': { borderColor: 'white', bgcolor: 'rgba(255, 255, 255, 0.1)' } }}
                    data-testid="logout-button"
                  >
                    {t('common.logout')}
                  </Button>
                </>
              ) : SHOW_PUBLIC_LOGIN_BUTTON ? (
                <Tooltip
                  title={DISABLE_PUBLIC_LOGIN_BUTTON ? t('common.loginComingSoon', 'Login coming soon') : ''}
                  disableFocusListener={!DISABLE_PUBLIC_LOGIN_BUTTON}
                  disableHoverListener={!DISABLE_PUBLIC_LOGIN_BUTTON}
                  disableTouchListener={!DISABLE_PUBLIC_LOGIN_BUTTON}
                >
                  <span>
                    <Button
                      variant="contained"
                      size="small"
                      startIcon={<LoginIcon />}
                      onClick={DISABLE_PUBLIC_LOGIN_BUTTON ? undefined : login}
                      disabled={DISABLE_PUBLIC_LOGIN_BUTTON}
                      sx={{
                        bgcolor: DISABLE_PUBLIC_LOGIN_BUTTON ? 'rgba(255, 255, 255, 0.16)' : 'white',
                        color: DISABLE_PUBLIC_LOGIN_BUTTON ? 'rgba(255, 255, 255, 0.62)' : 'primary.main',
                        border: DISABLE_PUBLIC_LOGIN_BUTTON ? '1px solid rgba(255, 255, 255, 0.18)' : 'none',
                        boxShadow: 'none',
                        '&:hover': DISABLE_PUBLIC_LOGIN_BUTTON ? undefined : { bgcolor: 'rgba(255, 255, 255, 0.9)' },
                        '&.Mui-disabled': {
                          bgcolor: 'rgba(255, 255, 255, 0.16)',
                          color: 'rgba(255, 255, 255, 0.62)',
                          border: '1px solid rgba(255, 255, 255, 0.18)',
                          opacity: 1,
                        },
                      }}
                      data-testid="login-button"
                    >
                      {t('common.login')}
                    </Button>
                  </span>
                </Tooltip>
              ) : null}
            </Box>
          </Toolbar>
        </AppBar>
      )}

      {children}
    </ThemeProvider>
  );
}

export default AppShell;

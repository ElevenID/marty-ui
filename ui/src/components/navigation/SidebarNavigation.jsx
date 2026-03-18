/**
 * SidebarNavigation Component
 * 
 * Collapsible sidebar navigation for authenticated users.
 * Supports console mode switching and nested navigation items.
 */

import { useState, useMemo, useCallback, useEffect } from 'react';
import { useLocation, useNavigate, Link } from 'react-router-dom';
import {
  Drawer,
  List,
  ListItem,
  ListItemButton,
  ListItemIcon,
  ListItemText,
  Collapse,
  Box,
  Typography,
  IconButton,
  Tooltip,
  Divider,
  useTheme,
  useMediaQuery,
  ToggleButtonGroup,
  ToggleButton,
  Alert,
  Button,
} from '@mui/material';
import ExpandLess from '@mui/icons-material/ExpandLess';
import ExpandMore from '@mui/icons-material/ExpandMore';
import MenuIcon from '@mui/icons-material/Menu';
import ChevronLeftIcon from '@mui/icons-material/ChevronLeft';
import StarIcon from '@mui/icons-material/Star';
import PersonIcon from '@mui/icons-material/Person';
import BusinessIcon from '@mui/icons-material/Business';
import Badge from '@mui/material/Badge';
import { useAuth } from '../../hooks/useAuth';
import { usePermissions } from '../../hooks/usePermissions';
import { useConsole } from '../../contexts/ConsoleContext';
import { getApplicantStats } from '../../services/dashboardApi';
import { ADMIN_VENDOR_NAV, APPLICANT_NAV, findActiveNavItem } from '../../config/navigation';

const DRAWER_WIDTH = 260;
const DRAWER_WIDTH_COLLAPSED = 72;

/**
 * Navigation Item Component
 * Renders a single nav item with optional children
 * Supports visual hierarchy: primary items, badges, and section-specific styling
 */
function NavItem({ item, isActive, isChildActive, expanded, onToggle, collapsed, depth = 0, parentId = null, badgeCounts = {} }) {
  const theme = useTheme();
  const navigate = useNavigate();
  const location = useLocation();
  const hasChildren = item.children && item.children.length > 0;
  const Icon = item.icon;
  
  // Visual hierarchy rules
  const isPrimary = item.primary;
  const isDesignSection = parentId === 'design' || item.id === 'design';
  const isDeploySection = parentId === 'deploy' || item.id === 'deploy';
  const hasBadge = item.badge;
  const badgeCount = badgeCounts[item.id] || 0;

  const handleClick = useCallback(() => {
    if (hasChildren) {
      onToggle(item.id);
    } else {
      navigate(item.path);
    }
  }, [hasChildren, item.id, item.path, navigate, onToggle]);

  const isItemActive = isActive || isChildActive;

  // Determine colors based on section and primary status
  const getItemColors = () => {
    if (isPrimary) {
      return {
        iconColor: isItemActive ? 'primary.main' : 'primary.light',
        textColor: isItemActive ? 'primary.main' : 'primary.dark',
        bgColor: isItemActive ? 'action.selected' : 'transparent',
        borderColor: isItemActive ? theme.palette.primary.main : 'transparent',
      };
    }
    
    if (isDesignSection && depth > 0) {
      return {
        iconColor: isItemActive ? 'text.primary' : 'text.disabled',
        textColor: isItemActive ? 'text.primary' : 'text.secondary',
        bgColor: isItemActive ? 'action.selected' : 'transparent',
        borderColor: isItemActive ? theme.palette.grey[400] : 'transparent',
      };
    }
    
    return {
      iconColor: isItemActive ? 'primary.main' : 'text.secondary',
      textColor: isItemActive ? 'primary.main' : 'text.primary',
      bgColor: isItemActive ? 'action.selected' : 'transparent',
      borderColor: isItemActive ? theme.palette.primary.main : 'transparent',
    };
  };

  const colors = getItemColors();

  return (
    <>
      <ListItem disablePadding sx={{ display: 'block' }}>
        <Tooltip title={collapsed ? item.label : ''} placement="right" arrow>
          <ListItemButton
            onClick={handleClick}
            sx={{
              minHeight: isPrimary ? 52 : 48,
              justifyContent: collapsed ? 'center' : 'initial',
              px: 2.5,
              pl: depth > 0 ? 4 : 2.5,
              bgcolor: colors.bgColor,
              borderLeft: `3px solid ${colors.borderColor}`,
              '&:hover': {
                bgcolor: 'action.hover',
              },
            }}
          >
            {Icon && (
              <ListItemIcon
                sx={{
                  minWidth: 0,
                  mr: collapsed ? 0 : 3,
                  justifyContent: 'center',
                  color: colors.iconColor,
                  position: 'relative',
                }}
              >
                <Icon />
                {isPrimary && !collapsed && (
                  <StarIcon
                    sx={{
                      position: 'absolute',
                      top: -4,
                      right: -4,
                      fontSize: 12,
                      color: 'primary.main',
                    }}
                  />
                )}
              </ListItemIcon>
            )}
            {!collapsed && (
              <>
                <ListItemText
                  primary={
                    hasBadge ? (
                      <Badge badgeContent={badgeCount} color="error" sx={{ '& .MuiBadge-badge': { position: 'relative', transform: 'none', ml: 1 } }}>
                        {item.label}
                      </Badge>
                    ) : (
                      item.label
                    )
                  }
                  sx={{
                    opacity: 1,
                    '& .MuiTypography-root': {
                      fontWeight: isItemActive || isPrimary ? 600 : 400,
                      fontSize: isPrimary ? '0.95rem' : '0.875rem',
                      color: colors.textColor,
                    },
                  }}
                />
                {hasChildren && (expanded ? <ExpandLess /> : <ExpandMore />)}
              </>
            )}
          </ListItemButton>
        </Tooltip>
      </ListItem>

      {/* Child items */}
      {hasChildren && !collapsed && (
        <Collapse in={expanded} timeout="auto" unmountOnExit>
          <List component="div" disablePadding>
            {item.children.map((child) => {
              const childActive = isChildActive && child.path === location.pathname;
              const childColors = child.primary 
                ? {
                    textColor: childActive ? 'primary.main' : 'primary.dark',
                    iconColor: childActive ? 'primary.main' : 'primary.light',
                  }
                : isDesignSection
                ? {
                    textColor: childActive ? 'text.primary' : 'text.secondary',
                    iconColor: childActive ? 'text.primary' : 'text.disabled',
                  }
                : {
                    textColor: childActive ? 'primary.main' : 'text.secondary',
                    iconColor: childActive ? 'primary.main' : 'text.secondary',
                  };
              
              const ChildIcon = child.icon;
              return (
                <ListItem key={child.id} disablePadding>
                  <ListItemButton
                    component={Link}
                    to={child.path}
                    sx={{
                      pl: 6,
                      minHeight: child.primary ? 44 : 40,
                      bgcolor: childActive ? 'action.selected' : 'transparent',
                      borderLeft: childActive ? `3px solid ${child.primary ? theme.palette.primary.main : theme.palette.grey[400]}` : '3px solid transparent',
                      '&:hover': {
                        bgcolor: 'action.hover',
                      },
                    }}
                  >
                    {ChildIcon && (
                      <ListItemIcon
                        sx={{
                          minWidth: 0,
                          mr: 2,
                          justifyContent: 'center',
                          color: childColors.iconColor,
                          position: 'relative',
                        }}
                      >
                        <ChildIcon fontSize="small" />
                        {child.primary && (
                          <StarIcon
                            sx={{
                              position: 'absolute',
                              top: -4,
                              right: -4,
                              fontSize: 10,
                              color: 'primary.main',
                            }}
                          />
                        )}
                      </ListItemIcon>
                    )}
                    <ListItemText
                      primary={child.label}
                      sx={{
                        '& .MuiTypography-root': {
                          fontSize: child.primary ? '0.875rem' : '0.8125rem',
                          fontWeight: childActive || child.primary ? 600 : 400,
                          color: childColors.textColor,
                        },
                      }}
                    />
                  </ListItemButton>
                </ListItem>
              );
            })}
          </List>
        </Collapse>
      )}
    </>
  );
}

/**
 * Sidebar Navigation Component
 */
function SidebarNavigation({ mobileOpen, onMobileClose }) {
  const theme = useTheme();
  const location = useLocation();
  const navigate = useNavigate();
  const isMobile = useMediaQuery(theme.breakpoints.down('md'));
  const { isAdministrator, isVendor, isApplicant, organizationId } = useAuth();
  const { mode, setMode, activeOrgId, memberships, isOrgConsoleAvailable, isApplicantConsoleAvailable, isOrgBlocked } = useConsole();
  const isJoinOnlyMode = memberships.length === 0;
  const showConsoleSwitcher = isApplicantConsoleAvailable && (isOrgConsoleAvailable || isJoinOnlyMode);

  // Badge counts fetched from API
  const [badgeCounts, setBadgeCounts] = useState({});
  useEffect(() => {
    if (!organizationId) return;
    let mounted = true;
    getApplicantStats(organizationId).then((stats) => {
      if (mounted) setBadgeCounts({ applications: stats.pending || 0 });
    });
    return () => { mounted = false; };
  }, [organizationId]);

  // Collapsed state for desktop — persisted so mode switches don't reset it
  const [collapsed, setCollapsed] = useState(() => {
    try { return localStorage.getItem('sidebar-collapsed') === 'true'; } catch { return false; }
  });

  // Track which parent items are expanded
  const [expandedItems, setExpandedItems] = useState({});

  const { can } = usePermissions();

  // Console mode switching
  const handleModeChange = useCallback((event, newMode) => {
    if (newMode && newMode !== mode) {
      setMode(newMode);
    }
  }, [mode, setMode]);

  // Get nav items based on console mode, filtered by permissions
  const navItems = useMemo(() => {
    const items = mode === 'org' ? ADMIN_VENDOR_NAV : APPLICANT_NAV;

    // Filter items and their children by requiredPermission
    const filterByPermission = (list) =>
      list
        .filter((item) => {
          if (!item.requiredPermission) return true;
          const { resource, action } = item.requiredPermission;
          return can(resource, action);
        })
        .map((item) => {
          if (!item.children) return item;
          const filteredChildren = filterByPermission(item.children);
          return { ...item, children: filteredChildren };
        });

    return filterByPermission(items);
  }, [mode, can]);

  // Find active item
  const activeItem = useMemo(() => {
    return findActiveNavItem(navItems, location.pathname);
  }, [navItems, location.pathname]);

  // Auto-expand parent of active child
  useMemo(() => {
    if (activeItem.parent && activeItem.child) {
      setExpandedItems((prev) => ({
        ...prev,
        [activeItem.parent.id]: true,
      }));
    }
  }, [activeItem]);

  const handleToggle = useCallback((itemId) => {
    setExpandedItems((prev) => ({
      ...prev,
      [itemId]: !prev[itemId],
    }));
  }, []);

  const handleCollapseToggle = useCallback(() => {
    setCollapsed((prev) => {
      const next = !prev;
      try { localStorage.setItem('sidebar-collapsed', String(next)); } catch {}
      if (next) setExpandedItems({});
      return next;
    });
  }, []);

  const drawerContent = (
    <Box
      sx={{
        display: 'flex',
        flexDirection: 'column',
        height: '100%',
        bgcolor: 'background.paper',
      }}
    >
      {/* Section A - Console Switcher */}
      {!collapsed && showConsoleSwitcher && (
        <Box sx={{ p: 2 }}>
          <Typography variant="caption" color="text.secondary" sx={{ mb: 1, display: 'block' }}>
            Console
          </Typography>
          <ToggleButtonGroup
            value={mode}
            exclusive
            onChange={handleModeChange}
            size="small"
            fullWidth
            sx={{ mb: 1 }}
          >
            <ToggleButton value="applicant" disabled={!isApplicantConsoleAvailable} sx={{ textTransform: 'none', minWidth: 0, px: 1 }}>
              <PersonIcon fontSize="small" sx={{ mr: 0.5, flexShrink: 0 }} />
              <Box component="span" sx={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>Applicant</Box>
            </ToggleButton>
            {(isOrgConsoleAvailable || isJoinOnlyMode) && (
              <ToggleButton value="org" sx={{ textTransform: 'none', minWidth: 0, px: 1 }}>
                <BusinessIcon fontSize="small" sx={{ mr: 0.5, flexShrink: 0 }} />
                <Box component="span" sx={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>Org</Box>
              </ToggleButton>
            )}
          </ToggleButtonGroup>
        </Box>
      )}

      {/* Collapsed console switcher icons */}
      {collapsed && showConsoleSwitcher && (
        <Box sx={{ display: 'flex', flexDirection: 'column', alignItems: 'center', py: 1, gap: 0.5 }}>
          <Tooltip title="Applicant Console" placement="right">
            <IconButton
              size="small"
              onClick={() => setMode('applicant')}
              disabled={!isApplicantConsoleAvailable}
              sx={{
                bgcolor: mode === 'applicant' ? 'action.selected' : 'transparent',
                '&:hover': { bgcolor: 'action.hover' },
              }}
            >
              <PersonIcon fontSize="small" />
            </IconButton>
          </Tooltip>
          {(isOrgConsoleAvailable || isJoinOnlyMode) && (
            <Tooltip title="Organization Console" placement="right">
              <IconButton
                size="small"
                onClick={() => setMode('org')}
                sx={{
                  bgcolor: mode === 'org' ? 'action.selected' : 'transparent',
                  '&:hover': { bgcolor: 'action.hover' },
                }}
              >
                <BusinessIcon fontSize="small" />
              </IconButton>
            </Tooltip>
          )}
        </Box>
      )}

      <Divider />

      {/* Collapse toggle for desktop */}
      {!isMobile && !collapsed && (
        <Box sx={{ display: 'flex', justifyContent: 'flex-end', px: 2, py: 1 }}>
          <IconButton onClick={handleCollapseToggle} size="small">
            <ChevronLeftIcon />
          </IconButton>
        </Box>
      )}

      {!isMobile && collapsed && (
        <Box sx={{ display: 'flex', justifyContent: 'center', py: 1 }}>
          <IconButton onClick={handleCollapseToggle} size="small">
            <MenuIcon />
          </IconButton>
        </Box>
      )}

      {/* Section C - Navigation Items */}
      <List
        sx={{
          flex: 1,
          pt: 1,
          // Disable navigation when org console is blocked
          opacity: (isOrgBlocked || isJoinOnlyMode) ? 0.5 : 1,
          pointerEvents: (isOrgBlocked || isJoinOnlyMode) ? 'none' : 'auto',
        }}
      >
        {navItems.map((item) => (
          <NavItem
            key={item.id}
            item={item}
            isActive={activeItem.parent?.id === item.id && !activeItem.child}
            isChildActive={activeItem.parent?.id === item.id && !!activeItem.child}
            expanded={expandedItems[item.id] || false}
            onToggle={handleToggle}
            collapsed={collapsed}
            parentId={null}
            badgeCounts={badgeCounts}
          />
        ))}
      </List>

      {/* Footer - Help link */}
      {!collapsed && (
        <>
          <Divider />
          <Box sx={{ p: 2 }}>
            <Typography variant="caption" color="text.secondary">
              Need help?{' '}
              <Link to="/docs" style={{ color: theme.palette.primary.main }}>
                View API Docs
              </Link>
            </Typography>
          </Box>
        </>
      )}
    </Box>
  );

  // Mobile drawer
  if (isMobile) {
    return (
      <Drawer
        variant="temporary"
        open={mobileOpen}
        onClose={onMobileClose}
        ModalProps={{ keepMounted: true }}
        sx={{
          display: { xs: 'block', md: 'none' },
          '& .MuiDrawer-paper': {
            boxSizing: 'border-box',
            width: DRAWER_WIDTH,
          },
        }}
      >
        {drawerContent}
      </Drawer>
    );
  }

  // Desktop drawer
  return (
    <Drawer
      variant="permanent"
      sx={{
        width: collapsed ? DRAWER_WIDTH_COLLAPSED : DRAWER_WIDTH,
        flexShrink: 0,
        '& .MuiDrawer-paper': {
          width: collapsed ? DRAWER_WIDTH_COLLAPSED : DRAWER_WIDTH,
          boxSizing: 'border-box',
          position: 'relative',
          height: '100%',
          transition: theme.transitions.create('width', {
            easing: theme.transitions.easing.sharp,
            duration: theme.transitions.duration.enteringScreen,
          }),
          overflowX: 'hidden',
        },
      }}
    >
      {drawerContent}
    </Drawer>
  );
}

export default SidebarNavigation;

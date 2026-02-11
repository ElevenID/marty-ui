/**
 * SidebarNavigation Component
 * 
 * Collapsible sidebar navigation for authenticated users.
 * Supports nested navigation items with expand/collapse functionality.
 */

import { useState, useMemo, useCallback } from 'react';
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
} from '@mui/material';
import ExpandLess from '@mui/icons-material/ExpandLess';
import ExpandMore from '@mui/icons-material/ExpandMore';
import MenuIcon from '@mui/icons-material/Menu';
import ChevronLeftIcon from '@mui/icons-material/ChevronLeft';
import StarIcon from '@mui/icons-material/Star';
import Badge from '@mui/material/Badge';
import { useAuth } from '../../hooks/useAuth';
import { ADMIN_VENDOR_NAV, APPLICANT_NAV, findActiveNavItem } from '../../config/navigation';
import { OrgSwitcher } from './OrgSwitcher';

const DRAWER_WIDTH = 260;
const DRAWER_WIDTH_COLLAPSED = 72;

/**
 * Navigation Item Component
 * Renders a single nav item with optional children
 * Supports visual hierarchy: primary items, badges, and section-specific styling
 */
function NavItem({ item, isActive, isChildActive, expanded, onToggle, collapsed, depth = 0, parentId = null }) {
  const theme = useTheme();
  const navigate = useNavigate();
  const location = useLocation();
  const hasChildren = item.children && item.children.length > 0;
  const Icon = item.icon;
  
  // Visual hierarchy rules
  const isPrimary = item.primary;
  const isDesignSection = parentId === 'design' || item.id === 'design';
  const isDeploySection = parentId === 'deploy' || item.id === 'deploy';
  const hasBadge = item.badge; // TODO: Wire up actual badge counts from context/API

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
                      <Badge badgeContent={0} color="error" sx={{ '& .MuiBadge-badge': { position: 'relative', transform: 'none', ml: 1 } }}>
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
  const isMobile = useMediaQuery(theme.breakpoints.down('md'));
  const { isAdministrator, isVendor, isApplicant } = useAuth();

  // Debug logging
  console.log('[SidebarNavigation] Rendering');
  console.log('[SidebarNavigation] isAdministrator:', isAdministrator, 'isVendor:', isVendor, 'isApplicant:', isApplicant);

  // Collapsed state for desktop
  const [collapsed, setCollapsed] = useState(false);

  // Track which parent items are expanded
  const [expandedItems, setExpandedItems] = useState({});

  // Get nav items based on role
  const navItems = useMemo(() => {
    if (isAdministrator || isVendor) return ADMIN_VENDOR_NAV;
    if (isApplicant) return APPLICANT_NAV;
    return [];
  }, [isAdministrator, isVendor, isApplicant]);

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
    setCollapsed((prev) => !prev);
    // Collapse all expanded items when collapsing sidebar
    if (!collapsed) {
      setExpandedItems({});
    }
  }, [collapsed]);

  const drawerContent = (
    <Box
      sx={{
        display: 'flex',
        flexDirection: 'column',
        height: '100%',
        bgcolor: 'background.paper',
      }}
    >
      {/* Header */}
      <Box
        sx={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: collapsed ? 'center' : 'space-between',
          p: 2,
          minHeight: 64,
        }}
      >
        {!collapsed && (
          <Typography variant="subtitle1" fontWeight={600} color="primary">
            Console
          </Typography>
        )}
        {!isMobile && (
          <IconButton onClick={handleCollapseToggle} size="small">
            {collapsed ? <MenuIcon /> : <ChevronLeftIcon />}
          </IconButton>
        )}
      </Box>

      <Divider />

      {/* Organization Switcher */}
      <OrgSwitcher collapsed={collapsed} />

      {/* Navigation Items */}
      <List sx={{ flex: 1, pt: 1 }}>
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

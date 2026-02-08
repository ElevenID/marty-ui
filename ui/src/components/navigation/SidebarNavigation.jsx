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
import { useAuth } from '../../hooks/useAuth';
import { ADMIN_VENDOR_NAV, APPLICANT_NAV, findActiveNavItem } from '../../config/navigation';
import { OrgSwitcher } from './OrgSwitcher';

const DRAWER_WIDTH = 260;
const DRAWER_WIDTH_COLLAPSED = 72;

/**
 * Navigation Item Component
 * Renders a single nav item with optional children
 */
function NavItem({ item, isActive, isChildActive, expanded, onToggle, collapsed, depth = 0 }) {
  const theme = useTheme();
  const navigate = useNavigate();
  const hasChildren = item.children && item.children.length > 0;
  const Icon = item.icon;

  const handleClick = useCallback(() => {
    if (hasChildren) {
      onToggle(item.id);
    } else {
      navigate(item.path);
    }
  }, [hasChildren, item.id, item.path, navigate, onToggle]);

  const isItemActive = isActive || isChildActive;

  return (
    <>
      <ListItem disablePadding sx={{ display: 'block' }}>
        <Tooltip title={collapsed ? item.label : ''} placement="right" arrow>
          <ListItemButton
            onClick={handleClick}
            sx={{
              minHeight: 48,
              justifyContent: collapsed ? 'center' : 'initial',
              px: 2.5,
              pl: depth > 0 ? 4 : 2.5,
              bgcolor: isItemActive ? 'action.selected' : 'transparent',
              borderLeft: isItemActive ? `3px solid ${theme.palette.primary.main}` : '3px solid transparent',
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
                  color: isItemActive ? 'primary.main' : 'text.secondary',
                }}
              >
                <Icon />
              </ListItemIcon>
            )}
            {!collapsed && (
              <>
                <ListItemText
                  primary={item.label}
                  sx={{
                    opacity: 1,
                    '& .MuiTypography-root': {
                      fontWeight: isItemActive ? 600 : 400,
                      color: isItemActive ? 'primary.main' : 'text.primary',
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
            {item.children.map((child) => (
              <ListItem key={child.id} disablePadding>
                <ListItemButton
                  component={Link}
                  to={child.path}
                  sx={{
                    pl: 6,
                    minHeight: 40,
                    bgcolor: isChildActive && child.path === window.location.pathname ? 'action.selected' : 'transparent',
                    '&:hover': {
                      bgcolor: 'action.hover',
                    },
                  }}
                >
                  <ListItemText
                    primary={child.label}
                    sx={{
                      '& .MuiTypography-root': {
                        fontSize: '0.875rem',
                        fontWeight: isChildActive && child.path === window.location.pathname ? 600 : 400,
                        color: isChildActive && child.path === window.location.pathname ? 'primary.main' : 'text.secondary',
                      },
                    }}
                  />
                </ListItemButton>
              </ListItem>
            ))}
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

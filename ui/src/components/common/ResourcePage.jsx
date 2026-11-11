/**
 * ResourcePage Component
 * 
 * Standard layout wrapper for resource pages in the console.
 * Provides consistent header, tabs, and action button placement.
 */

import { useEffect, useRef } from 'react';
import { Box, Typography, Tabs, Tab, Paper, Breadcrumbs, Link as MuiLink } from '@mui/material';
import { Link, useLocation } from 'react-router';
import NavigateNextIcon from '@mui/icons-material/NavigateNext';
import BuildButton from './BuildButton';

/**
 * ResourcePage Component
 * 
 * @param {string} title - Page title
 * @param {string} description - Optional page description
 * @param {string} resourceName - Name for Build button (e.g., "Trust Profile")
 * @param {string} buildPath - Path for Build wizard
 * @param {string} newPath - Path for advanced form (optional)
 * @param {array} tabs - Array of tab objects { label, path }
 * @param {array} breadcrumbs - Array of breadcrumb objects { label, path }
 * @param {string} pageTestId - Optional stable test id for the page wrapper
 * @param {node} actions - Additional action buttons
 * @param {node} children - Page content
 */
function ResourcePage({
  title,
  description,
  resourceName,
  buildPath,
  newPath,
  tabs,
  breadcrumbs,
  pageTestId,
  actions,
  children,
}) {
  const location = useLocation();
  const tabScrollerRef = useRef(null);

  // Prefer the most specific matching tab when nested tab paths share a prefix.
  const activeTab = tabs?.reduce((bestMatchIndex, tab, index, allTabs) => {
    const isMatch = location.pathname === tab.path || location.pathname.startsWith(tab.path + '/');
    if (!isMatch) {
      return bestMatchIndex;
    }

    if (bestMatchIndex < 0) {
      return index;
    }

    return allTabs[index].path.length > allTabs[bestMatchIndex].path.length
      ? index
      : bestMatchIndex;
  }, -1) ?? -1;

  // Keep the active destination visible when the scroller narrows after layout.
  useEffect(() => {
    const scroller = tabScrollerRef.current;
    if (!scroller) return undefined;
    const selected = scroller.querySelector('[role="tab"][aria-selected="true"]');
    if (!selected) return undefined;
    let frame;
    const reveal = () => {
      const viewport = scroller.getBoundingClientRect();
      const tab = selected.getBoundingClientRect();
      if (tab.left < viewport.left || tab.width > viewport.width) {
        scroller.scrollLeft += tab.left - viewport.left;
      } else if (tab.right > viewport.right) {
        scroller.scrollLeft += tab.right - viewport.right;
      }
    };
    const scheduleReveal = () => {
      cancelAnimationFrame(frame);
      frame = requestAnimationFrame(reveal);
    };
    const observer = typeof ResizeObserver === 'undefined' ? null : new ResizeObserver(scheduleReveal);
    observer?.observe(scroller);
    observer?.observe(selected);
    scheduleReveal();
    return () => {
      cancelAnimationFrame(frame);
      observer?.disconnect();
    };
  }, [activeTab, location.pathname, tabs?.length]);

  return (
    <Box data-testid={pageTestId} sx={{ minWidth: 0, maxWidth: '100%' }}>
      {/* Breadcrumbs */}
      {breadcrumbs && breadcrumbs.length > 0 && (
        <Breadcrumbs
          separator={<NavigateNextIcon fontSize="small" />}
          sx={{ mb: 2 }}
        >
          {breadcrumbs.map((crumb, index) => (
            index < breadcrumbs.length - 1 ? (
              <MuiLink
                key={crumb.path}
                component={Link}
                to={crumb.path}
                color="inherit"
                underline="hover"
              >
                {crumb.label}
              </MuiLink>
            ) : (
              <Typography key={crumb.path} color="text.primary">
                {crumb.label}
              </Typography>
            )
          ))}
        </Breadcrumbs>
      )}

      {/* Header */}
      <Box
        sx={{
          display: 'flex',
          flexDirection: { xs: 'column', sm: 'row' },
          justifyContent: 'space-between',
          alignItems: 'flex-start',
          gap: 2,
          mb: 3,
        }}
      >
        <Box sx={{ minWidth: 0, maxWidth: '100%' }}>
          <Typography variant="h4" component="h1" gutterBottom>
            {title}
          </Typography>
          {description && (
            <Typography variant="body1" color="text.secondary">
              {description}
            </Typography>
          )}
        </Box>

        {/* Actions */}
        <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 2, alignItems: 'center', maxWidth: '100%' }}>
          {actions}
          {resourceName && buildPath && (
            <BuildButton
              resourceName={resourceName}
              buildPath={buildPath}
              newPath={newPath}
            />
          )}
        </Box>
      </Box>

      {/* Tabs */}
      {tabs && tabs.length > 0 && (
        <Paper sx={{ mb: 3 }}>
          <Tabs
            value={activeTab >= 0 ? activeTab : 0}
            variant="scrollable"
            scrollButtons
            allowScrollButtonsMobile
            slotProps={{ scroller: { ref: tabScrollerRef } }}
            indicatorColor="primary"
            textColor="primary"
          >
            {tabs.map((tab) => (
              <Tab
                key={tab.path}
                label={tab.label}
                component={Link}
                to={tab.path}
              />
            ))}
          </Tabs>
        </Paper>
      )}

      {/* Content */}
      <Box>{children}</Box>
    </Box>
  );
}

export default ResourcePage;

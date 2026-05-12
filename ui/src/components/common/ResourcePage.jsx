/**
 * ResourcePage Component
 * 
 * Standard layout wrapper for resource pages in the console.
 * Provides consistent header, tabs, and action button placement.
 */

import { Box, Typography, Tabs, Tab, Paper, Breadcrumbs, Link as MuiLink } from '@mui/material';
import { Link, useLocation } from 'react-router-dom';
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

  return (
    <Box data-testid={pageTestId}>
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
          justifyContent: 'space-between',
          alignItems: 'flex-start',
          mb: 3,
        }}
      >
        <Box>
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
        <Box sx={{ display: 'flex', gap: 2, alignItems: 'center' }}>
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

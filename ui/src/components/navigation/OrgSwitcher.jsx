/**
 * Organization Switcher Component
 * 
 * Allows users (especially Admins) to switch between organizations.
 * - Vendors: Shows current org (non-interactive if single org)
 * - Admins: Dropdown with org list
 * 
 * Supports two variants:
 * - "sidebar": Full width for sidebar placement (default)
 * - "header": Compact for header bar placement
 */

import {
  Box,
  Select,
  MenuItem,
  Typography,
  FormControl,
  Divider,
} from '@mui/material';
import CheckIcon from '@mui/icons-material/Check';
import BusinessIcon from '@mui/icons-material/Business';
import ArrowDropDownIcon from '@mui/icons-material/ArrowDropDown';

import { useAuth } from '../../hooks/useAuth';
import { useConsole } from '../../contexts/ConsoleContext';

/**
 * Organization Switcher Component
 */
export function OrgSwitcher({ collapsed, variant = 'sidebar' }) {
  const { isAdministrator } = useAuth();
  const { activeOrgId, memberships, setActiveOrgId } = useConsole();

  // Find active organization details
  const activeOrg = memberships.find(org => org.id === activeOrgId);
  const organizationName = activeOrg?.display_name || activeOrg?.name || '';

  const handleChange = (event) => {
    const newOrgId = event.target.value;
    setActiveOrgId(newOrgId);
  };

  // Header variant: compact dropdown
  if (variant === 'header') {
    if (memberships.length === 0) {
      return null;
    }

    if (memberships.length === 1 && !isAdministrator && activeOrgId) {
      return (
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
          <BusinessIcon fontSize="small" color="action" />
          <Typography variant="body2" color="text.secondary">
            {organizationName}
          </Typography>
        </Box>
      );
    }

    return (
      <FormControl size="small">
        <Select
          value={activeOrgId || ''}
          onChange={handleChange}
          displayEmpty
          IconComponent={ArrowDropDownIcon}
          sx={{
            '& .MuiSelect-select': {
              py: 0.75,
              pl: 1,
              pr: 3,
              fontSize: '0.875rem',
              display: 'flex',
              alignItems: 'center',
              gap: 0.5,
            },
            '& .MuiOutlinedInput-notchedOutline': {
              borderColor: 'divider',
            },
            minWidth: 150,
          }}
          renderValue={() => (
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
              <BusinessIcon fontSize="small" color="action" />
              <Typography variant="body2">
                {organizationName || 'Select Org'}
              </Typography>
            </Box>
          )}
        >
          {memberships.map((org) => (
            <MenuItem key={org.id} value={org.id}>
              <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', width: '100%' }}>
                <Typography variant="body2">
                  {org.display_name || org.name || org.id}
                </Typography>
                {org.id === activeOrgId && (
                  <CheckIcon fontSize="small" color="primary" sx={{ ml: 1 }} />
                )}
              </Box>
            </MenuItem>
          ))}
        </Select>
      </FormControl>
    );
  }

  // Don't show in sidebar if no org or only one org and not admin
  if (!activeOrgId || (memberships.length <= 1 && !isAdministrator)) {
    return null;
  }

  // Sidebar variant (default)
  // If collapsed (icon-only sidebar), show compact version
  if (collapsed) {
    return (
      <Box sx={{ px: 1, py: 1 }}>
        <BusinessIcon color="action" />
      </Box>
    );
  }

  // If only one org, show as read-only
  if (memberships.length === 1 && !isAdministrator) {
    return (
      <Box sx={{ px: 2, py: 1.5 }}>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 0.5 }}>
          <BusinessIcon fontSize="small" color="action" />
          <Typography variant="caption" color="text.secondary">
            Organization
          </Typography>
        </Box>
        <Typography variant="body2" fontWeight={500}>
          {organizationName || 'Current Organization'}
        </Typography>
      </Box>
    );
  }

  // Multi-org dropdown
  return (
    <Box sx={{ px: 2, py: 1.5 }}>
      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1 }}>
        <BusinessIcon fontSize="small" color="action" />
        <Typography variant="caption" color="text.secondary">
          Organization
        </Typography>
      </Box>
      <FormControl fullWidth size="small">
        <Select
          value={activeOrgId || ''}
          onChange={handleChange}
          displayEmpty
          sx={{
            '& .MuiSelect-select': {
              py: 1,
              fontSize: '0.875rem',
            },
          }}
        >
          {memberships.map((org) => (
            <MenuItem key={org.id} value={org.id}>
              <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', width: '100%' }}>
                <Typography variant="body2">
                  {org.display_name || org.name || org.id}
                </Typography>
                {org.id === activeOrgId && (
                  <CheckIcon fontSize="small" color="primary" />
                )}
              </Box>
            </MenuItem>
          ))}
        </Select>
      </FormControl>
      {isAdministrator && (
        <Typography variant="caption" color="text.secondary" sx={{ mt: 0.5, display: 'block' }}>
          Admin view
        </Typography>
      )}
      <Divider sx={{ mt: 1.5 }} />
    </Box>
  );
}

/**
 * Permission Tooltip Component
 * 
 * Wraps disabled buttons/actions with a tooltip explaining the required permission.
 * Used for role-based access control UI feedback.
 */

import { Tooltip } from '@mui/material';
import { useAuth } from '../../hooks/useAuth';

/**
 * Permission Tooltip Component
 * 
 * @param {Object} props
 * @param {React.ReactNode} props.children - The component to wrap (typically a disabled button)
 * @param {string[]} props.requiredRoles - Array of roles that have access (e.g., ['administrator', 'vendor'])
 * @param {string} props.action - Description of the action (e.g., "create API keys", "delete members")
 * @param {string} [props.customMessage] - Optional custom message instead of default
 * @param {boolean} [props.disabled] - Whether the wrapped component is disabled
 */
export function PermissionTooltip({ 
  children, 
  requiredRoles = [], 
  action = 'perform this action',
  customMessage,
  disabled = false,
}) {
  const { isAdministrator, isVendor, isApplicant } = useAuth();

  // Map current user roles
  const currentRoles = [];
  if (isAdministrator) currentRoles.push('administrator');
  if (isVendor) currentRoles.push('vendor');
  if (isApplicant) currentRoles.push('applicant');

  // Check if user has required permission
  const hasPermission = requiredRoles.length === 0 || 
                        requiredRoles.some(role => currentRoles.includes(role));

  // Only show tooltip if disabled and lacks permission
  if (!disabled || hasPermission) {
    return children;
  }

  // Generate tooltip message
  const roleNames = {
    administrator: 'Administrator',
    vendor: 'Vendor',
    applicant: 'Applicant',
    developer: 'Developer',
    operator: 'Operator',
  };

  const requiredRoleNames = requiredRoles
    .map(role => roleNames[role] || role)
    .join(' or ');

  const message = customMessage || 
    `Only ${requiredRoleNames} can ${action}. Your current role does not have permission.`;

  return (
    <Tooltip 
      title={message} 
      placement="top"
      arrow
    >
      <span>
        {children}
      </span>
    </Tooltip>
  );
}

export default PermissionTooltip;

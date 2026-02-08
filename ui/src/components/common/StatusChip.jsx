/**
 * StatusChip Component
 * 
 * Consistent status display across resource pages.
 */

import { Chip } from '@mui/material';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import WarningIcon from '@mui/icons-material/Warning';
import ErrorIcon from '@mui/icons-material/Error';
import PendingIcon from '@mui/icons-material/Pending';
import DraftsIcon from '@mui/icons-material/Drafts';
import BlockIcon from '@mui/icons-material/Block';

/**
 * Status configurations for different resource types
 */
const STATUS_CONFIGS = {
  // Generic statuses
  active: { label: 'Active', color: 'success', icon: CheckCircleIcon },
  draft: { label: 'Draft', color: 'default', icon: DraftsIcon },
  disabled: { label: 'Disabled', color: 'error', icon: BlockIcon },
  pending: { label: 'Pending', color: 'warning', icon: PendingIcon },
  
  // Application-specific statuses
  pending_review: { label: 'Pending Review', color: 'warning', icon: PendingIcon },
  documents_pending: { label: 'Documents Pending', color: 'info', icon: PendingIcon },
  approved: { label: 'Approved', color: 'success', icon: CheckCircleIcon },
  rejected: { label: 'Rejected', color: 'error', icon: ErrorIcon },
  verification_failed: { label: 'Verification Failed', color: 'error', icon: WarningIcon },
  
  // Flow instance statuses
  running: { label: 'Running', color: 'info', icon: PendingIcon },
  completed: { label: 'Completed', color: 'success', icon: CheckCircleIcon },
  failed: { label: 'Failed', color: 'error', icon: ErrorIcon },
  
  // Credential statuses
  issued: { label: 'Issued', color: 'success', icon: CheckCircleIcon },
  revoked: { label: 'Revoked', color: 'error', icon: BlockIcon },
  expired: { label: 'Expired', color: 'warning', icon: WarningIcon },
  
  // Generic fallback
  unknown: { label: 'Unknown', color: 'default', icon: null },
};

/**
 * StatusChip component for consistent status display
 * 
 * @param {string} status - Status key (e.g., 'active', 'draft', 'pending_review')
 * @param {string} [customLabel] - Override the default label
 * @param {string} [size='small'] - MUI Chip size
 * @param {boolean} [showIcon=false] - Whether to show the status icon
 * @param {string} [variant] - MUI Chip variant
 */
function StatusChip({ 
  status, 
  customLabel, 
  size = 'small', 
  showIcon = false,
  variant,
}) {
  const config = STATUS_CONFIGS[status] || STATUS_CONFIGS.unknown;
  const { label, color, icon: IconComponent } = config;

  return (
    <Chip
      label={customLabel || label}
      color={color}
      size={size}
      variant={variant}
      {...(showIcon && IconComponent ? { icon: <IconComponent /> } : {})}
    />
  );
}

export default StatusChip;

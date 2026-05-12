/**
 * StatusChip Component
 * 
 * Consistent status display across resource pages.
 */

import { Chip } from '@mui/material';
import { useTranslation } from 'react-i18next';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import WarningIcon from '@mui/icons-material/Warning';
import ErrorIcon from '@mui/icons-material/Error';
import PendingIcon from '@mui/icons-material/Pending';
import DraftsIcon from '@mui/icons-material/Drafts';
import BlockIcon from '@mui/icons-material/Block';
import SendIcon from '@mui/icons-material/Send';

/**
 * Status configurations for different resource types
 */
const getStatusConfigs = (t) => ({
  // Generic statuses
  active: { label: t('status.active'), color: 'success', icon: CheckCircleIcon },
  draft: { label: t('status.draft'), color: 'default', icon: DraftsIcon },
  disabled: { label: t('status.disabled'), color: 'error', icon: BlockIcon },
  pending: { label: t('status.pending'), color: 'warning', icon: PendingIcon },
  
  // Application-specific statuses
  submitted: { label: t('status.submitted'), color: 'info', icon: PendingIcon },
  under_review: { label: t('status.underReview'), color: 'warning', icon: PendingIcon },
  needs_info: { label: t('status.needsInfo'), color: 'info', icon: WarningIcon },
  vetting_in_progress: { label: t('status.vettingInProgress'), color: 'warning', icon: PendingIcon },
  pending_review: { label: t('status.pendingReview'), color: 'warning', icon: PendingIcon },
  documents_pending: { label: t('status.documentsPending'), color: 'info', icon: PendingIcon },
  approved: { label: t('status.approved'), color: 'success', icon: CheckCircleIcon },
  offered: { label: t('status.offered', 'Wallet Invite Ready'), color: 'info', icon: SendIcon },
  offer_generated: { label: t('status.offerGenerated'), color: 'info', icon: SendIcon },
  rejected: { label: t('status.rejected'), color: 'error', icon: ErrorIcon },
  verification_failed: { label: t('status.verificationFailed'), color: 'error', icon: WarningIcon },
  
  // Flow instance statuses
  running: { label: t('status.running'), color: 'info', icon: PendingIcon },
  completed: { label: t('status.completed'), color: 'success', icon: CheckCircleIcon },
  failed: { label: t('status.failed'), color: 'error', icon: ErrorIcon },
  
  // Credential statuses
  credentialed: { label: t('status.credentialed', 'Credential Issued'), color: 'success', icon: CheckCircleIcon },
  issued: { label: t('status.issued'), color: 'success', icon: CheckCircleIcon },
  revoked: { label: t('status.revoked'), color: 'error', icon: BlockIcon },
  expired: { label: t('status.expired'), color: 'warning', icon: WarningIcon },
  
  // Generic fallback
  unknown: { label: t('status.unknown'), color: 'default', icon: null },
});

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
  const { t } = useTranslation('common');
  const config = getStatusConfigs(t)[status] || getStatusConfigs(t).unknown;
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

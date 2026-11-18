/**
 * Membership Mode Chip Component
 * 
 * Displays a chip indicating the organization's membership mode
 */

import { Chip } from '@mui/material';
import LockIcon from '@mui/icons-material/Lock';
import LockOpenIcon from '@mui/icons-material/LockOpen';
import HowToRegIcon from '@mui/icons-material/HowToReg';
import { useTranslation } from 'react-i18next';

const MembershipModeChip = ({ mode }) => {
  const { t } = useTranslation('onboarding');
  
  const config = {
    invite_only: { labelKey: 'membershipMode.inviteOnly', icon: <LockIcon fontSize="small" />, color: 'default' },
    approval: { labelKey: 'membershipMode.approval', icon: <HowToRegIcon fontSize="small" />, color: 'warning' },
    open: { labelKey: 'membershipMode.open', icon: <LockOpenIcon fontSize="small" />, color: 'success' },
  };
  const { labelKey, icon, color } = config[mode] || config.invite_only;
  return <Chip icon={icon} label={t(labelKey)} color={color} size="small" />;
};

export default MembershipModeChip;

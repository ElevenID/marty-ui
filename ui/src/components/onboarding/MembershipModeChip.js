/**
 * Membership Mode Chip Component
 * 
 * Displays a chip indicating the organization's membership mode
 */

import React from 'react';
import { Chip } from '@mui/material';
import LockIcon from '@mui/icons-material/Lock';
import LockOpenIcon from '@mui/icons-material/LockOpen';
import HowToRegIcon from '@mui/icons-material/HowToReg';

const MembershipModeChip = ({ mode }) => {
  const config = {
    invite_only: { label: 'Invite Only', icon: <LockIcon fontSize="small" />, color: 'default' },
    approval: { label: 'Request to Join', icon: <HowToRegIcon fontSize="small" />, color: 'warning' },
    open: { label: 'Open', icon: <LockOpenIcon fontSize="small" />, color: 'success' },
  };
  const { label, icon, color } = config[mode] || config.invite_only;
  return <Chip icon={icon} label={label} color={color} size="small" />;
};

export default MembershipModeChip;

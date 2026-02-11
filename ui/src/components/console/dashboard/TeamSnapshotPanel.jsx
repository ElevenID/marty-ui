/**
 * Team Snapshot Panel
 * 
 * Shows team visibility without navigating:
 * - # Team members
 * - Roles present (Admin / Dev / Operator)
 * - Pending invites
 * 
 * Quick actions:
 * - Invite user
 * - Review roles
 */

import {
  Box,
  Paper,
  Typography,
  Grid,
  Card,
  CardContent,
  Button,
  Avatar,
  AvatarGroup,
  Tooltip,
} from '@mui/material';
import { Link } from 'react-router-dom';
import PersonAddIcon from '@mui/icons-material/PersonAdd';
import AdminPanelSettingsIcon from '@mui/icons-material/AdminPanelSettings';
import CodeIcon from '@mui/icons-material/Code';
import SettingsIcon from '@mui/icons-material/Settings';
import PeopleIcon from '@mui/icons-material/People';
import EmailIcon from '@mui/icons-material/Email';
import ArrowForwardIcon from '@mui/icons-material/ArrowForward';

/**
 * Role badge configuration
 */
const ROLE_CONFIG = {
  admin: {
    label: 'Admin',
    icon: AdminPanelSettingsIcon,
    color: 'error',
  },
  developer: {
    label: 'Developer',
    icon: CodeIcon,
    color: 'primary',
  },
  operator: {
    label: 'Operator',
    icon: SettingsIcon,
    color: 'info',
  },
};

/**
 * Role summary card
 */
function RoleCard({ role, count }) {
  const config = ROLE_CONFIG[role] || ROLE_CONFIG.operator;
  const Icon = config.icon;

  return (
    <Card sx={{ height: '100%' }}>
      <CardContent>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1 }}>
          <Icon color={config.color} fontSize="small" />
          <Typography variant="caption" color="text.secondary">
            {config.label}
          </Typography>
        </Box>
        <Typography variant="h4" fontWeight={600}>
          {count}
        </Typography>
      </CardContent>
    </Card>
  );
}

/**
 * Team Snapshot Panel Component
 */
export function TeamSnapshotPanel({ teamData }) {
  const {
    members = [],
    pendingInvites = [],
    roleDistribution = {},
  } = teamData || {};

  // Calculate role counts
  const adminCount = roleDistribution.admin || 0;
  const developerCount = roleDistribution.developer || 0;
  const operatorCount = roleDistribution.operator || 0;
  const totalMembers = members.length || 0;

  // Get first few member avatars for display
  const memberAvatars = members.slice(0, 5);

  return (
    <Paper sx={{ p: 3, mb: 3 }}>
      <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 3 }}>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
          <PeopleIcon color="primary" />
          <Box>
            <Typography variant="h6">
              Team
            </Typography>
            <Typography variant="caption" color="text.secondary">
              {totalMembers} member{totalMembers !== 1 ? 's' : ''}
              {pendingInvites.length > 0 && ` • ${pendingInvites.length} pending invite${pendingInvites.length !== 1 ? 's' : ''}`}
            </Typography>
          </Box>
        </Box>
        <Box sx={{ display: 'flex', gap: 1 }}>
          <Button
            component={Link}
            to="/console/org/team/invite"
            variant="contained"
            startIcon={<PersonAddIcon />}
            size="small"
          >
            Invite
          </Button>
          <Button
            component={Link}
            to="/console/org/team"
            variant="outlined"
            size="small"
            endIcon={<ArrowForwardIcon />}
          >
            Manage
          </Button>
        </Box>
      </Box>

      <Grid container spacing={2} sx={{ mb: 3 }}>
        <Grid item xs={12} sm={4}>
          <RoleCard role="admin" count={adminCount} />
        </Grid>
        <Grid item xs={12} sm={4}>
          <RoleCard role="developer" count={developerCount} />
        </Grid>
        <Grid item xs={12} sm={4}>
          <RoleCard role="operator" count={operatorCount} />
        </Grid>
      </Grid>

      {totalMembers > 0 && (
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
          <AvatarGroup max={5}>
            {memberAvatars.map((member, idx) => (
              <Tooltip key={member.id || idx} title={member.name || member.email}>
                <Avatar
                  alt={member.name || member.email}
                  src={member.avatar}
                  sx={{ width: 32, height: 32 }}
                >
                  {(member.name || member.email || '?')[0].toUpperCase()}
                </Avatar>
              </Tooltip>
            ))}
          </AvatarGroup>
          {totalMembers > 5 && (
            <Typography variant="caption" color="text.secondary">
              +{totalMembers - 5} more
            </Typography>
          )}
        </Box>
      )}

      {pendingInvites.length > 0 && (
        <Box sx={{ mt: 2, p: 2, bgcolor: 'info.light', borderRadius: 1, display: 'flex', alignItems: 'center', gap: 1 }}>
          <EmailIcon fontSize="small" color="info" />
          <Typography variant="body2" color="text.secondary">
            {pendingInvites.length} pending invitation{pendingInvites.length !== 1 ? 's' : ''}
          </Typography>
          <Button
            component={Link}
            to="/console/org/team"
            size="small"
            sx={{ ml: 'auto' }}
          >
            Review
          </Button>
        </Box>
      )}

      {totalMembers === 0 && (
        <Box sx={{ textAlign: 'center', py: 3 }}>
          <Typography variant="body2" color="text.secondary" paragraph>
            No team members yet. Invite users to collaborate.
          </Typography>
          <Button
            component={Link}
            to="/console/org/team/invite"
            variant="contained"
            startIcon={<PersonAddIcon />}
          >
            Invite Team Member
          </Button>
        </Box>
      )}
    </Paper>
  );
}

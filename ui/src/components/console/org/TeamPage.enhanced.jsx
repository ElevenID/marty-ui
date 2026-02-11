import { useState, useEffect } from 'react';
import {
  Box,
  Paper,
  Typography,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Button,
  IconButton,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  TextField,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Chip,
  Alert,
  Menu,
  ListItemIcon,
  ListItemText,
  Divider,
} from '@mui/material';
import AddIcon from '@mui/icons-material/Add';
import MoreVertIcon from '@mui/icons-material/MoreVert';
import PersonAddIcon from '@mui/icons-material/PersonAdd';
import DeleteIcon from '@mui/icons-material/Delete';
import EditIcon from '@mui/icons-material/Edit';
import SendIcon from '@mui/icons-material/Send';
import CancelIcon from '@mui/icons-material/Cancel';
import SwapHorizIcon from '@mui/icons-material/SwapHoriz';
import PeopleIcon from '@mui/icons-material/People';
import { formatDistanceToNow } from 'date-fns';

import { ResourcePage } from '../../common';
import { TableSkeleton } from '../../common/skeletons';
import ErrorState from '../../common/ErrorState';
import EmptyState from '../../common/EmptyState';
import teamApi from '../../../services/teamApi';
import { useNotifications } from '../../../hooks/useNotifications';
import { usePermissions } from '../../../hooks/usePermissions';
import { PermissionGate } from '../../common/PermissionGate';

const ORG_TABS = [
  { label: 'Organization', path: '/console/org/settings' },
  { label: 'Team', path: '/console/org/team' },
  { label: 'Notifications', path: '/console/org/notifications' },
];

const BREADCRUMBS = [
  { label: 'Console', path: '/console' },
  { label: 'Org', path: '/console/org' },
  { label: 'Team', path: '/console/org/team' },
];

const ROLES = [
  { value: 'admin', label: 'Admin', description: 'Full access to all resources' },
  { value: 'developer', label: 'Developer', description: 'Can create and manage resources' },
  { value: 'operator', label: 'Operator', description: 'Read-only access' },
];

/**
 * Enhanced Team Page with full CRUD functionality
 */
function TeamPage() {
  const [members, setMembers] = useState([]);
  const [pendingInvites, setPendingInvites] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [inviteDialogOpen, setInviteDialogOpen] = useState(false);
  const [roleDialogOpen, setRoleDialogOpen] = useState(false);
  const [selectedMember, setSelectedMember] = useState(null);

  const { showNotification } = useNotifications();
  const { hasPermission } = usePermissions();

  useEffect(() => {
    loadTeamData();
  }, []);

  const loadTeamData = async () => {
    setLoading(true);
    setError(null);
    try {
      const [membersData, invitesData] = await Promise.all([
        teamApi.listMembers(),
        teamApi.listInvites(),
      ]);
      setMembers(Array.isArray(membersData) ? membersData : membersData.members || []);
      setPendingInvites(Array.isArray(invitesData) ? invitesData : invitesData.invites || []);
    } catch (err) {
      console.error('Failed to load team data:', err);
      setError(err);
    } finally {
      setLoading(false);
    }
  };

  const handleInvite = async (email, role) => {
    try {
      await teamApi.inviteMember({ email, role });
      showNotification?.('Invitation sent successfully', 'success');
      setInviteDialogOpen(false);
      loadTeamData();
    } catch (err) {
      console.error('Failed to invite member:', err);
      showNotification?.('Failed to send invitation', 'error');
    }
  };

  const handleResendInvite = async (inviteId) => {
    try {
      await teamApi.resendInvite(inviteId);
      showNotification?.('Invitation resent', 'success');
    } catch (err) {
      console.error('Failed to resend invite:', err);
      showNotification?.('Failed to resend invitation', 'error');
    }
  };

  const handleRevokeInvite = async (inviteId) => {
    if (!confirm('Revoke this invitation?')) return;
    try {
      await teamApi.revokeInvite(inviteId);
      showNotification?.('Invitation revoked', 'success');
      loadTeamData();
    } catch (err) {
      console.error('Failed to revoke invite:', err);
      showNotification?.('Failed to revoke invitation', 'error');
    }
  };

  const handleChangeRole = async (memberId, newRole) => {
    try {
      await teamApi.updateMemberRole(memberId, newRole);
      showNotification?.('Member role updated', 'success');
      setRoleDialogOpen(false);
      setSelectedMember(null);
      loadTeamData();
    } catch (err) {
      console.error('Failed to update role:', err);
      showNotification?.('Failed to update member role', 'error');
    }
  };

  const handleRemoveMember = async (memberId, memberEmail) => {
    if (!confirm(`Remove ${memberEmail} from the team? They will lose access immediately.`)) return;
    try {
      await teamApi.removeMember(memberId);
      showNotification?.('Member removed from team', 'success');
      loadTeamData();
    } catch (err) {
      console.error('Failed to remove member:', err);
      showNotification?.('Failed to remove member', 'error');
    }
  };

  const getRoleColor = (role) => {
    switch (role) {
      case 'owner': return 'error';
      case 'admin': return 'primary';
      case 'developer': return 'success';
      default: return 'default';
    }
  };

  return (
    <ResourcePage
      title="Team"
      subtitle="Manage team members, roles, and invitations"
      icon={<PeopleIcon />}
      tabs={ORG_TABS}
      breadcrumbs={BREADCRUMBS}
      actions={
        <PermissionGate resource="team" action="invite">
          <Button
            variant="contained"
            startIcon={<AddIcon />}
            onClick={() => setInviteDialogOpen(true)}
          >
            Invite Member
          </Button>
        </PermissionGate>
      }
    >
      {loading ? (
        <TableSkeleton rows={5} columns={4} showActions />
      ) : error ? (
        <ErrorState error={error} onRetry={loadTeamData} variant="inline" />
      ) : (
        <>
          {/* Current Members */}
          <Paper sx={{ mb: 3 }}>
            <Box sx={{ p: 2, borderBottom: 1, borderColor: 'divider' }}>
              <Typography variant="h6">Current Members</Typography>
              <Typography variant="body2" color="text.secondary">
                {members.length} team {members.length === 1 ? 'member' : 'members'}
              </Typography>
            </Box>
            
            {members.length === 0 ? (
              <Box sx={{ p: 3 }}>
                <EmptyState
                  icon={PeopleIcon}
                  title="No team members yet"
                  description="Invite team members to collaborate on your organization."
                />
              </Box>
            ) : (
              <TableContainer>
                <Table>
                  <TableHead>
                    <TableRow>
                      <TableCell>Name</TableCell>
                      <TableCell>Email</TableCell>
                      <TableCell>Role</TableCell>
                      <TableCell>Joined</TableCell>
                      <TableCell align="right">Actions</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {members.map((member) => (
                      <TableRow key={member.id}>
                        <TableCell>{member.name || '—'}</TableCell>
                        <TableCell>{member.email}</TableCell>
                        <TableCell>
                          <Chip
                            label={member.role}
                            size="small"
                            color={getRoleColor(member.role)}
                          />
                        </TableCell>
                        <TableCell>
                          {member.joined_at ? formatDistanceToNow(new Date(member.joined_at), { addSuffix: true }) : '—'}
                        </TableCell>
                        <TableCell align="right">
                          {member.role !== 'owner' && hasPermission('team', 'manage') && (
                            <MemberActionsMenu
                              member={member}
                              onChangeRole={() => {
                                setSelectedMember(member);
                                setRoleDialogOpen(true);
                              }}
                              onRemove={() => handleRemoveMember(member.id, member.email)}
                            />
                          )}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            )}
          </Paper>

          {/* Pending Invitations */}
          {pendingInvites.length > 0 && (
            <Paper>
              <Box sx={{ p: 2, borderBottom: 1, borderColor: 'divider' }}>
                <Typography variant="h6">Pending Invitations</Typography>
                <Typography variant="body2" color="text.secondary">
                  {pendingInvites.length} pending {pendingInvites.length === 1 ? 'invitation' : 'invitations'}
                </Typography>
              </Box>
              <TableContainer>
                <Table>
                  <TableHead>
                    <TableRow>
                      <TableCell>Email</TableCell>
                      <TableCell>Role</TableCell>
                      <TableCell>Invited</TableCell>
                      <TableCell>Expires</TableCell>
                      <TableCell align="right">Actions</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {pendingInvites.map((invite) => (
                      <TableRow key={invite.id}>
                        <TableCell>{invite.email}</TableCell>
                        <TableCell>
                          <Chip label={invite.role} size="small" />
                        </TableCell>
                        <TableCell>
                          {formatDistanceToNow(new Date(invite.created_at), { addSuffix: true })}
                        </TableCell>
                        <TableCell>
                          {invite.expires_at ? formatDistanceToNow(new Date(invite.expires_at), { addSuffix: true }) : '—'}
                        </TableCell>
                        <TableCell align="right">
                          <IconButton
                            size="small"
                            onClick={() => handleResendInvite(invite.id)}
                            title="Resend invitation"
                          >
                            <SendIcon fontSize="small" />
                          </IconButton>
                          <IconButton
                            size="small"
                            onClick={() => handleRevokeInvite(invite.id)}
                            title="Revoke invitation"
                          >
                            <CancelIcon fontSize="small" />
                          </IconButton>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            </Paper>
          )}
        </>
      )}

      {/* Invite Dialog */}
      <InviteMemberDialog
        open={inviteDialogOpen}
        onClose={() => setInviteDialogOpen(false)}
        onInvite={handleInvite}
      />

      {/* Change Role Dialog */}
      <ChangeRoleDialog
        open={roleDialogOpen}
        member={selectedMember}
        onClose={() => {
          setRoleDialogOpen(false);
          setSelectedMember(null);
        }}
        onChangeRole={handleChangeRole}
      />
    </ResourcePage>
  );
}

function MemberActionsMenu({ member, onChangeRole, onRemove }) {
  const [anchorEl, setAnchorEl] = useState(null);
  const open = Boolean(anchorEl);

  return (
    <>
      <IconButton
        size="small"
        onClick={(e) => setAnchorEl(e.currentTarget)}
      >
        <MoreVertIcon />
      </IconButton>
      <Menu
        anchorEl={anchorEl}
        open={open}
        onClose={() => setAnchorEl(null)}
      >
        <MenuItem
          onClick={() => {
            setAnchorEl(null);
            onChangeRole();
          }}
        >
          <ListItemIcon>
            <EditIcon fontSize="small" />
          </ListItemIcon>
          <ListItemText>Change Role</ListItemText>
        </MenuItem>
        <Divider />
        <MenuItem
          onClick={() => {
            setAnchorEl(null);
            onRemove();
          }}
          sx={{ color: 'error.main' }}
        >
          <ListItemIcon>
            <DeleteIcon fontSize="small" color="error" />
          </ListItemIcon>
          <ListItemText>Remove Member</ListItemText>
        </MenuItem>
      </Menu>
    </>
  );
}

function InviteMemberDialog({ open, onClose, onInvite }) {
  const [email, setEmail] = useState('');
  const [role, setRole] = useState('developer');

  const handleSubmit = () => {
    if (!email) return;
    onInvite(email, role);
    setEmail('');
    setRole('developer');
  };

  return (
    <Dialog open={open} onClose={onClose} maxWidth="sm" fullWidth>
      <DialogTitle>Invite Team Member</DialogTitle>
      <DialogContent>
        <Alert severity="info" sx={{ mb: 2 }}>
          An invitation email will be sent to the provided address. The invite will expire in 7 days.
        </Alert>
        <TextField
          fullWidth
          label="Email Address"
          type="email"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          margin="normal"
          autoFocus
        />
        <FormControl fullWidth margin="normal">
          <InputLabel>Role</InputLabel>
          <Select
            value={role}
            label="Role"
            onChange={(e) => setRole(e.target.value)}
          >
            {ROLES.map((r) => (
              <MenuItem key={r.value} value={r.value}>
                <Box>
                  <Typography variant="body2">{r.label}</Typography>
                  <Typography variant="caption" color="text.secondary">
                    {r.description}
                  </Typography>
                </Box>
              </MenuItem>
            ))}
          </Select>
        </FormControl>
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose}>Cancel</Button>
        <Button
          onClick={handleSubmit}
          variant="contained"
          disabled={!email}
          startIcon={<SendIcon />}
        >
          Send Invitation
        </Button>
      </DialogActions>
    </Dialog>
  );
}

function ChangeRoleDialog({ open, member, onClose, onChangeRole }) {
  const [newRole, setNewRole] = useState('');

  useEffect(() => {
    if (member) {
      setNewRole(member.role);
    }
  }, [member]);

  const handleSubmit = () => {
    if (!member || !newRole) return;
    onChangeRole(member.id, newRole);
  };

  return (
    <Dialog open={open} onClose={onClose} maxWidth="sm" fullWidth>
      <DialogTitle>Change Member Role</DialogTitle>
      <DialogContent>
        <Alert severity="warning" sx={{ mb: 2 }}>
          Changing a member's role will affect their access to resources immediately.
        </Alert>
        <Typography variant="body2" sx={{ mb: 2 }}>
          Change role for: <strong>{member?.email}</strong>
        </Typography>
        <FormControl fullWidth>
          <InputLabel>New Role</InputLabel>
          <Select
            value={newRole}
            label="New Role"
            onChange={(e) => setNewRole(e.target.value)}
          >
            {ROLES.map((r) => (
              <MenuItem key={r.value} value={r.value}>
                <Box>
                  <Typography variant="body2">{r.label}</Typography>
                  <Typography variant="caption" color="text.secondary">
                    {r.description}
                  </Typography>
                </Box>
              </MenuItem>
            ))}
          </Select>
        </FormControl>
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose}>Cancel</Button>
        <Button
          onClick={handleSubmit}
          variant="contained"
          disabled={!newRole || newRole === member?.role}
        >
          Update Role
        </Button>
      </DialogActions>
    </Dialog>
  );
}

export default TeamPage;

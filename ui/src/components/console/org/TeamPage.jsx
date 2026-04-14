import { useState, useEffect } from 'react';
import { useAsyncData } from '../../../hooks/useAsyncData';
import { useTranslation } from 'react-i18next';
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
  Checkbox,
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
import { listRoles, setMemberRoles } from '../../../services/rbacApi';
import { useAuth } from '../../../hooks/useAuth';
import { useConsole } from '../../../contexts/ConsoleContext';
import { useNotifications } from '../../../hooks/useNotifications';
import { useDialog } from '../../../hooks/useDialog';
import { usePermissions } from '../../../hooks/usePermissions';
import { PermissionGate } from '../../common/PermissionGate';

/**
 * Get organization tabs with translations
 */
const getOrgTabs = (t) => [
  { label: t('org.tabs.organization'), path: '/console/org/settings' },
  { label: t('org.tabs.team'), path: '/console/org/team' },
  { label: 'Roles', path: '/console/org/roles' },
  { label: t('org.tabs.notifications'), path: '/console/org/notifications' },
];

/**
 * Get breadcrumbs with translations
 */
const getBreadcrumbs = (t) => [
  { label: t('org.breadcrumbs.console'), path: '/console' },
  { label: t('org.breadcrumbs.org'), path: '/console/org' },
  { label: t('org.breadcrumbs.team'), path: '/console/org/team' },
];

/**
 * Get roles with translations
 */
const getRoles = (t) => [
  { value: 'admin', label: t('org.team.roles.admin.label'), description: t('org.team.roles.admin.description') },
  { value: 'developer', label: t('org.team.roles.developer.label'), description: t('org.team.roles.developer.description') },
  { value: 'operator', label: t('org.team.roles.operator.label'), description: t('org.team.roles.operator.description') },
];

/**
 * Enhanced Team Page with full CRUD functionality
 */
function TeamPage() {
  const { t } = useTranslation('console');
  const inviteDialog = useDialog();
  const roleDialog = useDialog();

  const { organizationId } = useAuth();
  const { activeOrgId } = useConsole();
  // Prefer the console's actively selected org; fall back to the auth session org
  const effectiveOrgId = activeOrgId || organizationId;
  const isMartyOrg = effectiveOrgId === '00000000-0000-0000-0000-000000000001';
  const { showNotification } = useNotifications();
  const { hasPermission, refresh: refreshPermissions } = usePermissions();

  const {
    data: orgData,
    loading,
    error,
    reload,
  } = useAsyncData(async () => {
    if (!effectiveOrgId) {
      return {
        members: [],
        pendingInvites: [],
        availableRoles: [],
      };
    }

    const [membersData, invitesData, rolesData] = await Promise.all([
      teamApi.listMembers(effectiveOrgId),
      teamApi.listInvites(effectiveOrgId).catch(() => []),
      listRoles(effectiveOrgId).catch(() => []),
    ]);

    return {
      members: Array.isArray(membersData) ? membersData : (membersData?.members ?? []),
      pendingInvites: Array.isArray(invitesData) ? invitesData : (invitesData?.invites ?? []),
      availableRoles: rolesData ? (rolesData.roles || rolesData || []) : [],
    };
  }, [effectiveOrgId]);

  const members = orgData?.members ?? [];
  const pendingInvites = orgData?.pendingInvites ?? [];
  const availableRoles = orgData?.availableRoles ?? [];

  const requireOrgId = () => {
    if (!effectiveOrgId) {
      throw new Error('Organization context unavailable');
    }

    return effectiveOrgId;
  };

  const handleInvite = async (email, role) => {
    try {
      await teamApi.inviteMember(requireOrgId(), { email, role });
      showNotification?.(t('org.team.dialog.invite.success'), 'success');
      inviteDialog.close();
      reload();
    } catch (err) {
      console.error('Failed to invite member:', err);
      showNotification?.(t('org.team.dialog.invite.error'), 'error');
    }
  };

  const handleResendInvite = async (inviteId) => {
    try {
      await teamApi.resendInvite(requireOrgId(), inviteId);
      showNotification?.(t('org.team.dialog.resendSuccess'), 'success');
    } catch (err) {
      console.error('Failed to resend invite:', err);
      showNotification?.(t('org.team.dialog.resendError'), 'error');
    }
  };

  const handleRevokeInvite = async (inviteId) => {
    if (!confirm(t('org.team.invites.actions.confirmRevoke'))) return;
    try {
      await teamApi.revokeInvite(requireOrgId(), inviteId);
      showNotification?.(t('org.team.dialog.revokeSuccess'), 'success');
      reload();
    } catch (err) {
      console.error('Failed to revoke invite:', err);
      showNotification?.(t('org.team.dialog.revokeError'), 'error');
    }
  };

  const handleChangeRole = async (memberId, roleIds) => {
    try {
      const orgId = requireOrgId();

      if (availableRoles.length > 0 || roleIds.length > 1) {
        await setMemberRoles(orgId, memberId, roleIds);
      } else {
        // Fallback for legacy single-role
        await teamApi.updateMemberRole(orgId, memberId, roleIds[0]);
      }
      showNotification?.(t('org.team.dialog.changeRole.success'), 'success');
      roleDialog.close();
      await refreshPermissions();
      reload();
    } catch (err) {
      console.error('Failed to update roles:', err);
      showNotification?.(t('org.team.dialog.changeRole.error'), 'error');
    }
  };

  const handleRemoveMember = async (memberId, memberEmail) => {
    if (!confirm(t('org.team.members.actions.confirmRemove', { email: memberEmail }))) return;
    try {
      await teamApi.removeMember(requireOrgId(), memberId);
      showNotification?.(t('org.team.dialog.removeSuccess'), 'success');
      reload();
    } catch (err) {
      console.error('Failed to remove member:', err);
      showNotification?.(t('org.team.dialog.removeError'), 'error');
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
      title={t('org.team.title')}
      subtitle={t('org.team.subtitle')}
      icon={<PeopleIcon />}
      tabs={getOrgTabs(t)}
      breadcrumbs={getBreadcrumbs(t)}
      pageTestId="org.team.page"
      actions={
        <PermissionGate resource="team" action="invite">
          <Button
            variant="contained"
            startIcon={<AddIcon />}
            onClick={inviteDialog.open}
            data-testid="org.team.invite.action"
          >
            {t('org.team.members.actions.invite')}
          </Button>
        </PermissionGate>
      }
    >
      {loading ? (
        <TableSkeleton rows={5} columns={4} showActions />
      ) : error ? (
        <ErrorState error={error} onRetry={reload} variant="inline" />
      ) : (
        <>
          {/* Current Members */}
          <Paper sx={{ mb: 3 }}>
            <Box sx={{ p: 2, borderBottom: 1, borderColor: 'divider' }}>
              <Typography variant="h6">{t('org.team.members.title')}</Typography>
              <Typography variant="body2" color="text.secondary">
                {t('org.team.members.count', { count: members.length })}
              </Typography>
            </Box>
            
            {members.length === 0 ? (
              <Box sx={{ p: 3 }}>
                <EmptyState
                  icon={PeopleIcon}
                  title={t('org.team.members.empty.title')}
                  description={t('org.team.members.empty.description')}
                />
              </Box>
            ) : (
              <TableContainer>
                <Table>
                  <TableHead>
                    <TableRow>
                      <TableCell>{t('org.team.members.tableHeaders.name')}</TableCell>
                      <TableCell>{t('org.team.members.tableHeaders.email')}</TableCell>
                      <TableCell>{t('org.team.members.tableHeaders.role')}</TableCell>
                      <TableCell>{t('org.team.members.tableHeaders.joined')}</TableCell>
                      <TableCell align="right">{t('org.team.members.tableHeaders.actions')}</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {members.map((member) => (
                      <TableRow key={member.id}>
                        <TableCell>{member.name || '—'}</TableCell>
                        <TableCell>{member.email}</TableCell>
                        <TableCell>
                          <Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>
                            {(member.roles && member.roles.length > 0) ? (
                              member.roles.map((r) => (
                                <Chip
                                  key={r.id || r.name}
                                  label={r.display_name || r.name}
                                  size="small"
                                  color={getRoleColor(r.name)}
                                />
                              ))
                            ) : (
                              <Chip
                                label={member.role}
                                size="small"
                                color={getRoleColor(member.role)}
                              />
                            )}
                          </Box>
                        </TableCell>
                        <TableCell>
                          {member.joined_at ? formatDistanceToNow(new Date(member.joined_at), { addSuffix: true }) : '—'}
                        </TableCell>
                        <TableCell align="right">
                          {member.role !== 'owner' && hasPermission('team', 'manage') && !isMartyOrg && (
                            <MemberActionsMenu
                              member={member}
                              onChangeRole={() => roleDialog.open(member)}
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
                <Typography variant="h6">{t('org.team.invites.title')}</Typography>
                <Typography variant="body2" color="text.secondary">
                  {t('org.team.invites.count', { count: pendingInvites.length })}
                </Typography>
              </Box>
              <TableContainer>
                <Table>
                  <TableHead>
                    <TableRow>
                      <TableCell>{t('org.team.invites.tableHeaders.email')}</TableCell>
                      <TableCell>{t('org.team.invites.tableHeaders.role')}</TableCell>
                      <TableCell>{t('org.team.invites.tableHeaders.invited')}</TableCell>
                      <TableCell>{t('org.team.invites.tableHeaders.expires')}</TableCell>
                      <TableCell align="right">{t('org.team.invites.tableHeaders.actions')}</TableCell>
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
                          {hasPermission('team', 'manage') && !isMartyOrg && (
                            <>
                              <IconButton
                                size="small"
                                onClick={() => handleResendInvite(invite.id)}
                                title={t('org.team.invites.actions.resend')}
                              >
                                <SendIcon fontSize="small" />
                              </IconButton>
                              <IconButton
                                size="small"
                                onClick={() => handleRevokeInvite(invite.id)}
                                title={t('org.team.invites.actions.revoke')}
                              >
                                <CancelIcon fontSize="small" />
                              </IconButton>
                            </>
                          )}
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
        open={inviteDialog.isOpen}
        onClose={inviteDialog.close}
        onInvite={handleInvite}
        t={t}
      />

      {/* Change Role Dialog */}
      <ChangeRoleDialog
        open={roleDialog.isOpen}
        member={roleDialog.data}
        availableRoles={availableRoles}
        onClose={roleDialog.close}
        onChangeRole={handleChangeRole}
        t={t}
      />
    </ResourcePage>
  );
}

function MemberActionsMenu({ member, onChangeRole, onRemove }) {
  const { t } = useTranslation('console');
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
          <ListItemText>{t('org.team.members.actions.changeRole')}</ListItemText>
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
          <ListItemText>{t('org.team.members.actions.remove')}</ListItemText>
        </MenuItem>
      </Menu>
    </>
  );
}

function InviteMemberDialog({ open, onClose, onInvite, t }) {
  const [email, setEmail] = useState('');
  const [role, setRole] = useState('developer');
  
  const ROLES = getRoles(t);

  const handleSubmit = () => {
    if (!email) return;
    onInvite(email, role);
    setEmail('');
    setRole('developer');
  };

  return (
    <Dialog open={open} onClose={onClose} maxWidth="sm" fullWidth>
      <DialogTitle>{t('org.team.dialog.invite.title')}</DialogTitle>
      <DialogContent>
        <Alert severity="info" sx={{ mb: 2 }}>
          {t('org.team.dialog.invite.info')}
        </Alert>
        <TextField
          fullWidth
          label={t('org.team.dialog.invite.emailLabel')}
          type="email"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          margin="normal"
          autoFocus
        />
        <FormControl fullWidth margin="normal">
          <InputLabel>{t('org.team.dialog.invite.roleLabel')}</InputLabel>
          <Select
            value={role}
            label={t('org.team.dialog.invite.roleLabel')}
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
        <Button onClick={onClose}>{t('actions.cancel', { ns: 'common' })}</Button>
        <Button
          onClick={handleSubmit}
          variant="contained"
          disabled={!email}
          startIcon={<SendIcon />}
        >
          {t('org.team.dialog.invite.send')}
        </Button>
      </DialogActions>
    </Dialog>
  );
}

function ChangeRoleDialog({ open, member, availableRoles = [], onClose, onChangeRole, t }) {
  const [selectedRoleIds, setSelectedRoleIds] = useState(new Set());

  useEffect(() => {
    if (member) {
      // Pre-select current roles
      const currentIds = new Set(
        (member.roles || []).map(r => r.id).filter(Boolean)
      );
      setSelectedRoleIds(currentIds);
    }
  }, [member]);

  const toggleRole = (roleId) => {
    setSelectedRoleIds(prev => {
      const next = new Set(prev);
      if (next.has(roleId)) {
        next.delete(roleId);
      } else {
        next.add(roleId);
      }
      return next;
    });
  };

  const handleSubmit = () => {
    if (!member || selectedRoleIds.size === 0) return;
    onChangeRole(member.id, Array.from(selectedRoleIds));
  };

  const getRoleColorForName = (name) => {
    switch (name) {
      case 'owner': return 'error';
      case 'admin': return 'primary';
      case 'member': return 'success';
      case 'viewer': return 'default';
      default: return 'info';
    }
  };

  return (
    <Dialog open={open} onClose={onClose} maxWidth="sm" fullWidth>
      <DialogTitle>{t('org.team.dialog.changeRole.title')}</DialogTitle>
      <DialogContent>
        <Alert severity="warning" sx={{ mb: 2 }}>
          {t('org.team.dialog.changeRole.warning')}
        </Alert>
        <Typography variant="body2" sx={{ mb: 2 }}>
          {t('org.team.dialog.changeRole.changingFor', { email: member?.email })}
        </Typography>
        <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
          {availableRoles.map((role) => (
            <Paper
              key={role.id}
              variant="outlined"
              sx={{
                p: 1.5,
                cursor: 'pointer',
                border: selectedRoleIds.has(role.id) ? 2 : 1,
                borderColor: selectedRoleIds.has(role.id) ? 'primary.main' : 'divider',
                '&:hover': { bgcolor: 'action.hover' },
              }}
              onClick={() => toggleRole(role.id)}
            >
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                <Checkbox
                  checked={selectedRoleIds.has(role.id)}
                  size="small"
                  tabIndex={-1}
                />
                <Chip
                  label={role.display_name || role.name}
                  size="small"
                  color={getRoleColorForName(role.name)}
                />
                {role.is_system && (
                  <Chip label="System" size="small" variant="outlined" />
                )}
              </Box>
              {role.description && (
                <Typography variant="caption" color="text.secondary" sx={{ ml: 5 }}>
                  {role.description}
                </Typography>
              )}
            </Paper>
          ))}
        </Box>
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose}>{t('actions.cancel', { ns: 'common' })}</Button>
        <Button
          onClick={handleSubmit}
          variant="contained"
          disabled={selectedRoleIds.size === 0}
        >
          {t('org.team.dialog.changeRole.update')}
        </Button>
      </DialogActions>
    </Dialog>
  );
}

export default TeamPage;

import { useEffect, useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import {
  Alert,
  Box,
  Button,
  Checkbox,
  Chip,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  Divider,
  FormControl,
  IconButton,
  InputLabel,
  ListItemIcon,
  ListItemText,
  Menu,
  MenuItem,
  Paper,
  Select,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  TextField,
  Typography,
} from '@mui/material';
import AddIcon from '@mui/icons-material/Add';
import CancelIcon from '@mui/icons-material/Cancel';
import DeleteIcon from '@mui/icons-material/Delete';
import EditIcon from '@mui/icons-material/Edit';
import MoreVertIcon from '@mui/icons-material/MoreVert';
import PeopleIcon from '@mui/icons-material/People';
import SendIcon from '@mui/icons-material/Send';
import { formatDistanceToNow } from 'date-fns';

import { ResourcePage } from '../../common';
import { TableSkeleton } from '../../common/skeletons';
import EmptyState from '../../common/EmptyState';
import ErrorState from '../../common/ErrorState';
import { PermissionGate } from '../../common/PermissionGate';
import { useDialog } from '../../../hooks/useDialog';
import { useAuth } from '../../../hooks/useAuth';
import { useConsole } from '../../../contexts/ConsoleContext';
import { useNotifications } from '../../../hooks/useNotifications';
import { usePermissions } from '../../../hooks/usePermissions';
import teamApi from '../../../services/teamApi';
import { listRoles, setMemberRoles } from '../../../services/rbacApi';

const MARTY_ORG_ID = '00000000-0000-0000-0000-000000000001';

const getOrgTabs = (t) => [
  { label: t('org.tabs.organization'), path: '/console/org/settings' },
  { label: t('org.tabs.team'), path: '/console/org/team' },
  { label: 'Roles', path: '/console/org/roles' },
  { label: t('org.tabs.notifications'), path: '/console/org/notifications' },
];

const getBreadcrumbs = (t) => [
  { label: t('org.breadcrumbs.console'), path: '/console' },
  { label: t('org.breadcrumbs.org'), path: '/console/org' },
  { label: t('org.breadcrumbs.team'), path: '/console/org/team' },
];

function getRoleColor(roleName) {
  switch (roleName) {
    case 'owner':
      return 'error';
    case 'admin':
      return 'primary';
    case 'access_admin':
      return 'secondary';
    case 'catalog_admin':
      return 'success';
    case 'reviewer':
      return 'info';
    case 'operator':
      return 'warning';
    default:
      return 'default';
  }
}

function getDisplayName(member) {
  return member?.name || member?.email || member?.user_id || member?.id || 'Unknown member';
}

function splitMemberships(records) {
  const activeMembers = [];
  const pendingInvites = [];

  for (const record of records) {
    if (record?.status === 'active') {
      activeMembers.push(record);
    } else {
      pendingInvites.push(record);
    }
  }

  return { activeMembers, pendingInvites };
}

function RoleChips({ roles = [] }) {
  if (!roles.length) {
    return <Chip label="No roles" size="small" variant="outlined" />;
  }

  return (
    <Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>
      {roles.map((role) => (
        <Chip
          key={role.id || role.name}
          label={role.display_name || role.name}
          size="small"
          color={getRoleColor(role.name)}
        />
      ))}
    </Box>
  );
}

function TeamPage() {
  const { t } = useTranslation('console');
  const inviteDialog = useDialog();
  const roleDialog = useDialog();
  const { organizationId } = useAuth();
  const { activeOrgId } = useConsole();
  const { showNotification } = useNotifications();
  const { hasPermission, refresh: refreshPermissions } = usePermissions();

  const effectiveOrgId = activeOrgId;
  const isMartyOrg = effectiveOrgId === MARTY_ORG_ID;

  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [members, setMembers] = useState([]);
  const [pendingInvites, setPendingInvites] = useState([]);
  const [availableRoles, setAvailableRoles] = useState([]);

  const requireOrgId = () => {
    if (!effectiveOrgId) {
      throw new Error('Organization context unavailable');
    }

    return effectiveOrgId;
  };

  const loadData = async () => {
    if (!effectiveOrgId) {
      setMembers([]);
      setPendingInvites([]);
      setAvailableRoles([]);
      setError(new Error('Organization context unavailable'));
      setLoading(false);
      return;
    }

    try {
      setLoading(true);
      setError(null);

      const [memberData, rolesData] = await Promise.all([
        teamApi.listMembers(effectiveOrgId),
        listRoles(effectiveOrgId),
      ]);

      const membershipRecords = Array.isArray(memberData)
        ? memberData
        : (memberData?.members ?? []);
      const nextRoles = rolesData?.roles || rolesData || [];
      const { activeMembers, pendingInvites: pendingMembers } = splitMemberships(membershipRecords);

      setMembers(activeMembers);
      setPendingInvites(pendingMembers);
      setAvailableRoles(nextRoles);
    } catch (err) {
      console.error('Failed to load team data:', err);
      setError(err);
      setMembers([]);
      setPendingInvites([]);
      setAvailableRoles([]);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, [effectiveOrgId]);

  const defaultInviteRoleIds = useMemo(() => {
    const explicitDefaults = availableRoles
      .filter((role) => role.is_default_for_new_members)
      .map((role) => role.id);

    if (explicitDefaults.length > 0) {
      return explicitDefaults;
    }

    return availableRoles[0]?.id ? [availableRoles[0].id] : [];
  }, [availableRoles]);

  const handleInvite = async (email, roleIds) => {
    try {
      await teamApi.inviteMember(requireOrgId(), {
        email,
        role_ids: roleIds,
      });
      showNotification?.(t('org.team.dialog.invite.success'), 'success');
      inviteDialog.close();
      await loadData();
    } catch (err) {
      console.error('Failed to invite member:', err);
      showNotification?.(t('org.team.dialog.invite.error'), 'error');
    }
  };

  const handleChangeRole = async (memberId, roleIds) => {
    try {
      await setMemberRoles(requireOrgId(), memberId, roleIds);
      showNotification?.(t('org.team.dialog.changeRole.success'), 'success');
      roleDialog.close();
      await refreshPermissions();
      await loadData();
    } catch (err) {
      console.error('Failed to update roles:', err);
      showNotification?.(t('org.team.dialog.changeRole.error'), 'error');
    }
  };

  const handleRemoveMember = async (memberId, memberEmail) => {
    if (!confirm(t('org.team.members.actions.confirmRemove', { email: memberEmail }))) {
      return;
    }

    try {
      await teamApi.removeMember(requireOrgId(), memberId);
      showNotification?.(t('org.team.dialog.removeSuccess'), 'success');
      await loadData();
    } catch (err) {
      console.error('Failed to remove member:', err);
      showNotification?.(t('org.team.dialog.removeError'), 'error');
    }
  };

  const handleRevokeInvite = async (memberId, email) => {
    if (!confirm(t('org.team.invites.actions.confirmRevoke'))) {
      return;
    }

    try {
      await teamApi.removeMember(requireOrgId(), memberId);
      showNotification?.(t('org.team.dialog.revokeSuccess'), 'success');
      await loadData();
    } catch (err) {
      console.error('Failed to revoke invite:', err);
      showNotification?.(t('org.team.dialog.revokeError'), 'error');
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
            disabled={loading || Boolean(error)}
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
        <ErrorState error={error} onRetry={loadData} variant="inline" />
      ) : (
        <>
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
                        <TableCell>{getDisplayName(member)}</TableCell>
                        <TableCell>{member.email || '-'}</TableCell>
                        <TableCell>
                          <RoleChips roles={member.roles} />
                        </TableCell>
                        <TableCell>
                          {member.joined_at
                            ? formatDistanceToNow(new Date(member.joined_at), { addSuffix: true })
                            : '-'}
                        </TableCell>
                        <TableCell align="right">
                          {!member.is_owner && hasPermission('team', 'manage') && !isMartyOrg && (
                            <MemberActionsMenu
                              onChangeRole={() => roleDialog.open(member)}
                              onRemove={() => handleRemoveMember(member.id, member.email || getDisplayName(member))}
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
                        <TableCell>{invite.email || getDisplayName(invite)}</TableCell>
                        <TableCell>
                          <RoleChips roles={invite.roles} />
                        </TableCell>
                        <TableCell>
                          {invite.invited_at
                            ? formatDistanceToNow(new Date(invite.invited_at), { addSuffix: true })
                            : '-'}
                        </TableCell>
                        <TableCell>-</TableCell>
                        <TableCell align="right">
                          {hasPermission('team', 'manage') && !isMartyOrg && (
                            <IconButton
                              size="small"
                              onClick={() => handleRevokeInvite(invite.id, invite.email || getDisplayName(invite))}
                              title={t('org.team.invites.actions.revoke')}
                            >
                              <CancelIcon fontSize="small" />
                            </IconButton>
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

      <InviteMemberDialog
        open={inviteDialog.isOpen}
        availableRoles={availableRoles}
        defaultRoleIds={defaultInviteRoleIds}
        onClose={inviteDialog.close}
        onInvite={handleInvite}
        t={t}
      />

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

function MemberActionsMenu({ onChangeRole, onRemove }) {
  const { t } = useTranslation('console');
  const [anchorEl, setAnchorEl] = useState(null);
  const open = Boolean(anchorEl);

  return (
    <>
      <IconButton size="small" onClick={(event) => setAnchorEl(event.currentTarget)}>
        <MoreVertIcon />
      </IconButton>
      <Menu anchorEl={anchorEl} open={open} onClose={() => setAnchorEl(null)}>
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

function InviteMemberDialog({ open, availableRoles, defaultRoleIds, onClose, onInvite, t }) {
  const [email, setEmail] = useState('');
  const [selectedRoleIds, setSelectedRoleIds] = useState([]);

  useEffect(() => {
    if (!open) {
      return;
    }

    setEmail('');
    setSelectedRoleIds(defaultRoleIds);
  }, [defaultRoleIds, open]);

  const handleToggleRole = (roleId) => {
    setSelectedRoleIds((previous) => (
      previous.includes(roleId)
        ? previous.filter((currentId) => currentId !== roleId)
        : [...previous, roleId]
    ));
  };

  const handleSubmit = () => {
    if (!email || selectedRoleIds.length === 0) {
      return;
    }

    onInvite(email, selectedRoleIds);
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
          onChange={(event) => setEmail(event.target.value)}
          margin="normal"
          autoFocus
        />
        <FormControl fullWidth margin="normal">
          <InputLabel shrink>{t('org.team.dialog.invite.roleLabel')}</InputLabel>
          <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1, mt: 2 }}>
            {availableRoles.map((role) => (
              <Paper
                key={role.id}
                variant="outlined"
                sx={{
                  p: 1.5,
                  cursor: 'pointer',
                  border: selectedRoleIds.includes(role.id) ? 2 : 1,
                  borderColor: selectedRoleIds.includes(role.id) ? 'primary.main' : 'divider',
                  '&:hover': { bgcolor: 'action.hover' },
                }}
                onClick={() => handleToggleRole(role.id)}
              >
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                  <Checkbox checked={selectedRoleIds.includes(role.id)} size="small" tabIndex={-1} />
                  <Chip
                    label={role.display_name || role.name}
                    size="small"
                    color={getRoleColor(role.name)}
                  />
                </Box>
                {role.description && (
                  <Typography variant="caption" color="text.secondary" sx={{ ml: 5 }}>
                    {role.description}
                  </Typography>
                )}
              </Paper>
            ))}
          </Box>
        </FormControl>
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose}>{t('actions.cancel', { ns: 'common' })}</Button>
        <Button
          onClick={handleSubmit}
          variant="contained"
          disabled={!email || selectedRoleIds.length === 0}
          startIcon={<SendIcon />}
        >
          {t('org.team.dialog.invite.send')}
        </Button>
      </DialogActions>
    </Dialog>
  );
}

function ChangeRoleDialog({ open, member, availableRoles = [], onClose, onChangeRole, t }) {
  const [selectedRoleIds, setSelectedRoleIds] = useState([]);

  useEffect(() => {
    if (!member) {
      setSelectedRoleIds([]);
      return;
    }

    setSelectedRoleIds((member.roles || []).map((role) => role.id).filter(Boolean));
  }, [member]);

  const handleToggleRole = (roleId) => {
    setSelectedRoleIds((previous) => (
      previous.includes(roleId)
        ? previous.filter((currentId) => currentId !== roleId)
        : [...previous, roleId]
    ));
  };

  const handleSubmit = () => {
    if (!member || selectedRoleIds.length === 0) {
      return;
    }

    onChangeRole(member.id, selectedRoleIds);
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
                border: selectedRoleIds.includes(role.id) ? 2 : 1,
                borderColor: selectedRoleIds.includes(role.id) ? 'primary.main' : 'divider',
                '&:hover': { bgcolor: 'action.hover' },
              }}
              onClick={() => handleToggleRole(role.id)}
            >
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                <Checkbox checked={selectedRoleIds.includes(role.id)} size="small" tabIndex={-1} />
                <Chip
                  label={role.display_name || role.name}
                  size="small"
                  color={getRoleColor(role.name)}
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
          disabled={selectedRoleIds.length === 0}
        >
          {t('org.team.dialog.changeRole.update')}
        </Button>
      </DialogActions>
    </Dialog>
  );
}

export default TeamPage;

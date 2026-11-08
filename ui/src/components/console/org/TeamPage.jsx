import { useEffect, useLayoutEffect, useMemo, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useSearchParams } from 'react-router';
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
  FormControlLabel,
  IconButton,
  InputLabel,
  ListItemIcon,
  ListItemText,
  Menu,
  MenuItem,
  Paper,
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
import { useAsyncData } from '../../../hooks/useAsyncData';
import { useDialog } from '../../../hooks/useDialog';
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
  const [searchParams, setSearchParams] = useSearchParams();
  const inviteDialog = useDialog();
  const roleDialog = useDialog();
  const { activeOrgId } = useConsole();
  const { showNotification } = useNotifications();
  const { hasPermission, isLoading: permissionsLoading, refresh: refreshPermissions } = usePermissions();

  const effectiveOrgId = activeOrgId;
  const currentOrgId = useRef(effectiveOrgId);
  currentOrgId.current = effectiveOrgId;
  const currentRoleDialog = useRef(null);
  const active = useRef(false);
  useLayoutEffect(() => {
    active.current = true;
    return () => { active.current = false; };
  }, []);
  const isMartyOrg = effectiveOrgId === MARTY_ORG_ID;
  const canInvite = !permissionsLoading && hasPermission('team', 'invite');
  const canManage = !permissionsLoading && !isMartyOrg && hasPermission('team', 'manage');
  currentRoleDialog.current = roleDialog.isOpen && canManage
    && roleDialog.data?.organizationId === effectiveOrgId ? roleDialog.data : null;

  const { data: teamData, loading: dataLoading, error, reload: loadData } = useAsyncData(async () => {
    if (!effectiveOrgId) throw new Error('Organization context unavailable');
    const [memberData, rolesData] = await Promise.all([
      teamApi.listMembers(effectiveOrgId),
      listRoles(effectiveOrgId),
    ]);
    const membershipRecords = Array.isArray(memberData) ? memberData : (memberData?.members ?? []);
    return {
      organizationId: effectiveOrgId,
      ...splitMemberships(membershipRecords),
      availableRoles: rolesData?.roles || rolesData || [],
    };
  }, [effectiveOrgId]);
  const currentTeam = teamData?.organizationId === effectiveOrgId ? teamData : null;
  const loading = dataLoading || Boolean(effectiveOrgId && !currentTeam && !error);
  const { activeMembers: members = [], pendingInvites = [], availableRoles = [] } = currentTeam || {};
  const teamReady = Boolean(effectiveOrgId && currentTeam && !loading && !error);
  const inviteRequested = searchParams.get('invite') === '1';
  const { open: openInvite, close: closeInvite } = inviteDialog;
  const { close: closeRole } = roleDialog;

  useEffect(() => {
    if (!inviteRequested || !teamReady || permissionsLoading) return;
    const remainingParams = new URLSearchParams(searchParams);
    remainingParams.delete('invite');
    setSearchParams(remainingParams, { replace: true });
    if (canInvite) openInvite(effectiveOrgId);
  }, [inviteRequested, teamReady, permissionsLoading, canInvite, effectiveOrgId, searchParams, setSearchParams, openInvite]);

  useEffect(() => {
    if (inviteDialog.isOpen && (!canInvite || inviteDialog.data !== effectiveOrgId)) closeInvite();
  }, [inviteDialog.isOpen, inviteDialog.data, effectiveOrgId, canInvite, closeInvite]);

  useEffect(() => {
    if (roleDialog.isOpen && (!canManage || roleDialog.data?.organizationId !== effectiveOrgId)) closeRole();
  }, [roleDialog.isOpen, roleDialog.data, effectiveOrgId, canManage, closeRole]);

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
    if (!canInvite || !teamReady || inviteDialog.data !== effectiveOrgId) return;
    const invitedOrgId = effectiveOrgId;
    try {
      await teamApi.inviteMember(invitedOrgId, {
        email,
        role_ids: roleIds,
      });
      if (currentOrgId.current !== invitedOrgId) return;
      showNotification?.(t('org.team.dialog.invite.success'), 'success');
      inviteDialog.close();
      await loadData();
    } catch (err) {
      if (currentOrgId.current !== invitedOrgId) return;
      console.error('Failed to invite member:', err);
      showNotification?.(t('org.team.dialog.invite.error'), 'error');
    }
  };

  const handleChangeRole = async (memberId, roleIds) => {
    const dialogContext = roleDialog.data;
    if (!roleDialog.isOpen || !canManage || !teamReady || dialogContext?.organizationId !== effectiveOrgId
      || dialogContext?.member?.id !== memberId) return;
    const updatedOrgId = effectiveOrgId;
    const applies = () => active.current && currentOrgId.current === updatedOrgId
      && currentRoleDialog.current === dialogContext;
    try {
      await setMemberRoles(updatedOrgId, memberId, roleIds);
      if (!applies()) return;
      showNotification?.(t('org.team.dialog.changeRole.success'), 'success');
      roleDialog.close();
      await refreshPermissions();
      if (!active.current || currentOrgId.current !== updatedOrgId) return;
      await loadData();
    } catch (err) {
      if (!applies()) return;
      console.error('Failed to update roles:', err);
      throw err;
    }
  };

  const handleRemoveMember = async (memberId, memberEmail) => {
    if (!canManage || !teamReady) return;
    const removedOrgId = effectiveOrgId;
    const applies = () => active.current && currentOrgId.current === removedOrgId;
    if (!confirm(t('org.team.members.actions.confirmRemove', { email: memberEmail }))) {
      return;
    }

    try {
      await teamApi.removeMember(removedOrgId, memberId);
      if (!applies()) return;
      showNotification?.(t('org.team.dialog.removeSuccess'), 'success');
      await loadData();
    } catch (err) {
      if (!applies()) return;
      console.error('Failed to remove member:', err);
      showNotification?.(t('org.team.dialog.removeError'), 'error');
    }
  };

  const handleRevokeInvite = async (memberId) => {
    if (!canManage || !teamReady) return;
    const revokedOrgId = effectiveOrgId;
    const applies = () => active.current && currentOrgId.current === revokedOrgId;
    if (!confirm(t('org.team.invites.actions.confirmRevoke'))) {
      return;
    }

    try {
      await teamApi.removeMember(revokedOrgId, memberId);
      if (!applies()) return;
      showNotification?.(t('org.team.dialog.revokeSuccess'), 'success');
      await loadData();
    } catch (err) {
      if (!applies()) return;
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
            onClick={() => openInvite(effectiveOrgId)}
            disabled={!canInvite || !teamReady}
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
                          {!member.is_owner && canManage && teamReady && (
                            <MemberActionsMenu
                              onChangeRole={() => roleDialog.open({ member, organizationId: effectiveOrgId })}
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
                              onClick={() => handleRevokeInvite(invite.id)}
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
        open={inviteDialog.isOpen && inviteDialog.data === effectiveOrgId && canInvite && teamReady}
        availableRoles={availableRoles}
        defaultRoleIds={defaultInviteRoleIds}
        onClose={inviteDialog.close}
        onInvite={handleInvite}
        t={t}
      />

      <ChangeRoleDialog
        key={`${effectiveOrgId}:${roleDialog.data?.member?.id || ''}:${roleDialog.isOpen}`}
        open={roleDialog.isOpen && roleDialog.data?.organizationId === effectiveOrgId && canManage && teamReady}
        member={roleDialog.data?.member}
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
      <IconButton size="small" aria-label={t('org.team.members.tableHeaders.actions')} onClick={(event) => setAnchorEl(event.currentTarget)}>
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

function RoleSelection({ availableRoles, selectedRoleIds, onToggle, disabled = false, showSystem = false }) {
  return (
    <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
      {availableRoles.map((role) => (
        <Paper
          key={role.id}
          variant="outlined"
          sx={{
            p: 1.5,
            border: selectedRoleIds.includes(role.id) ? 2 : 1,
            borderColor: selectedRoleIds.includes(role.id) ? 'primary.main' : 'divider',
            '&:hover': { bgcolor: disabled ? undefined : 'action.hover' },
          }}
        >
          <FormControlLabel
            disabled={disabled}
            sx={{ m: 0, width: '100%', alignItems: 'flex-start' }}
            control={(
              <Checkbox
                checked={selectedRoleIds.includes(role.id)}
                onChange={() => onToggle(role.id)}
                size="small"
                slotProps={{ input: { 'aria-label': role.display_name || role.name } }}
              />
            )}
            label={(
              <Box component="span" sx={{ pt: 0.5, display: 'block' }}>
                <Box component="span" sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                  <Chip component="span" label={role.display_name || role.name} size="small" color={getRoleColor(role.name)} />
                  {showSystem && role.is_system && <Chip component="span" label="System" size="small" variant="outlined" />}
                </Box>
                {role.description && (
                  <Typography variant="caption" color="text.secondary" sx={{ display: 'block', mt: 0.5 }}>
                    {role.description}
                  </Typography>
                )}
              </Box>
            )}
          />
        </Paper>
      ))}
    </Box>
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
          <Box sx={{ mt: 2 }}>
            <RoleSelection availableRoles={availableRoles} selectedRoleIds={selectedRoleIds} onToggle={handleToggleRole} />
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
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');

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

  const handleSubmit = async () => {
    if (!member || selectedRoleIds.length === 0 || saving) {
      return;
    }

    setSaving(true);
    setError('');
    try {
      await onChangeRole(member.id, selectedRoleIds);
    } catch (saveError) {
      setError(saveError instanceof Error ? saveError.message : t('org.team.dialog.changeRole.error'));
    } finally {
      setSaving(false);
    }
  };

  return (
    <Dialog open={open} onClose={saving ? undefined : onClose} maxWidth="sm" fullWidth>
      <DialogTitle>{t('org.team.dialog.changeRole.title')}</DialogTitle>
      <DialogContent>
        <Alert severity="warning" sx={{ mb: 2 }}>
          {t('org.team.dialog.changeRole.warning')}
        </Alert>
        <Typography variant="body2" sx={{ mb: 2 }}>
          {t('org.team.dialog.changeRole.changingFor', { email: member?.email })}
        </Typography>
        {error && <Alert severity="error" sx={{ mb: 2 }}>{error}</Alert>}
        <RoleSelection availableRoles={availableRoles} selectedRoleIds={selectedRoleIds} onToggle={handleToggleRole} disabled={saving} showSystem />
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose} disabled={saving}>{t('actions.cancel', { ns: 'common' })}</Button>
        <Button
          onClick={handleSubmit}
          variant="contained"
          disabled={saving || selectedRoleIds.length === 0}
        >
          {t('org.team.dialog.changeRole.update')}
        </Button>
      </DialogActions>
    </Dialog>
  );
}

export default TeamPage;

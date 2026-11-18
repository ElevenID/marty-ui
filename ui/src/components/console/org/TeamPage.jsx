import { useEffect, useLayoutEffect, useMemo, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Link, useSearchParams } from 'react-router';
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
import { useAsyncData } from '../../../hooks/useAsyncData';
import { useAuth } from '../../../hooks/useAuth';
import { useDialog } from '../../../hooks/useDialog';
import { useConsole } from '../../../contexts/ConsoleContext';
import { useNotifications } from '../../../hooks/useNotifications';
import { usePermissions } from '../../../hooks/usePermissions';
import teamApi from '../../../services/teamApi';
import { listRoles, setMemberRoles } from '../../../services/rbacApi';

const MARTY_ORG_ID = '00000000-0000-0000-0000-000000000001';

const getOrgTabs = (t, can) => [
  { label: t('org.tabs.organization'), path: '/console/org/settings', allowed: can('organization', 'view') },
  { label: t('org.tabs.team'), path: '/console/org/team', allowed: can('team', 'view') },
  { label: t('org.team.access.rolesTitle'), path: '/console/org/roles', allowed: can('role', 'view') },
  { label: t('org.tabs.notifications'), path: '/console/org/notifications', allowed: can('notification', 'view') },
].filter(tab => tab.allowed);

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

function memberForDisplay(member, currentUser) {
  const principalId = currentUser?.user_id || currentUser?.sub || currentUser?.id;
  if (!principalId || member?.user_id !== principalId) return member;
  // Native owner memberships may omit profile fields. Use the known session
  // identity only for this principal, without changing the membership record.
  const name = currentUser.name?.trim()
    || [currentUser.given_name, currentUser.family_name].map((part) => part?.trim()).filter(Boolean).join(' ');
  return {
    ...member,
    name: member.name || name,
    email: member.email || currentUser.email,
  };
}

function splitMemberships(records) {
  const activeMembers = [];
  const pendingInvites = [];
  const otherMemberships = [];

  for (const record of records) {
    if (record?.status === 'active') {
      activeMembers.push(record);
    } else if (record?.status === 'invited') {
      pendingInvites.push(record);
    } else {
      // Pending approvals and deactivated memberships are not invitations.
      // Keep unknown future statuses visible without assigning them actions.
      otherMemberships.push(record);
    }
  }

  return { activeMembers, pendingInvites, otherMemberships };
}

function membershipStatusLabel(member, t) {
  if (member.status === 'pending') return t('org.team.memberships.pending');
  if (member.status === 'deactivated') return t('org.team.memberships.deactivated');
  return typeof member.status === 'string' && member.status.trim()
    ? member.status : t('org.team.memberships.unknown');
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

function TeamContent({ organizationId, currentUser, reconcileMembershipRemoval }) {
  const { t } = useTranslation('console');
  const [searchParams, setSearchParams] = useSearchParams();
  const inviteDialog = useDialog();
  const roleDialog = useDialog();
  const { showNotification } = useNotifications();
  const { hasPermission, isLoading: permissionsLoading, error: permissionError, refresh: refreshPermissions } = usePermissions();
  const removalPending = useRef(false);
  const [removing, setRemoving] = useState(false);

  const effectiveOrgId = organizationId;
  const currentOrgId = useRef(effectiveOrgId);
  currentOrgId.current = effectiveOrgId;
  const currentRoleDialog = useRef(null);
  const currentInviteDialog = useRef(null);
  const inviteSequence = useRef(0);
  const active = useRef(false);
  useLayoutEffect(() => {
    active.current = true;
    return () => { active.current = false; };
  }, []);
  const isMartyOrg = effectiveOrgId === MARTY_ORG_ID;
  const currentPermission = (resource, action) => Boolean(currentUser && effectiveOrgId
    && !permissionsLoading && hasPermission(resource, action));
  const canView = currentPermission('team', 'view');
  const canViewRoles = canView && currentPermission('role', 'view');
  const canInvite = canView && currentPermission('team', 'invite');
  const canManage = canView && !isMartyOrg && currentPermission('team', 'manage');
  const canAssignRoles = canView && !isMartyOrg && currentPermission('role', 'assign');
  const canViewRequests = canView;
  const currentAccess = useRef({ canView });
  currentAccess.current = { canView };
  currentInviteDialog.current = inviteDialog.isOpen && canInvite && canViewRoles
    && inviteDialog.data?.organizationId === effectiveOrgId ? inviteDialog.data : null;
  currentRoleDialog.current = roleDialog.isOpen && canAssignRoles && canViewRoles
    && roleDialog.data?.organizationId === effectiveOrgId ? roleDialog.data : null;

  const { data: teamData, loading: dataLoading, error, reload: loadData } = useAsyncData(async () => {
    if (!canView || !currentAccess.current.canView || !active.current) return null;
    const memberData = await teamApi.listMembers(effectiveOrgId, {}, {
      isCurrent: () => active.current && currentAccess.current.canView && currentOrgId.current === effectiveOrgId,
    });
    const membershipRecords = Array.isArray(memberData) ? memberData : (memberData?.members ?? []);
    return {
      organizationId: effectiveOrgId,
      ...splitMemberships(membershipRecords),
    };
  }, [effectiveOrgId, canView]);
  const { data: roleData, loading: rolesLoading, error: rolesError, reload: loadRoles } = useAsyncData(async () => {
    if (!canViewRoles) return null;
    const response = await listRoles(effectiveOrgId);
    const roles = response?.roles || response;
    if (!Array.isArray(roles)) throw new Error(t('org.team.access.rolesLoadFailed'));
    return { organizationId: effectiveOrgId, roles };
  }, [effectiveOrgId, canViewRoles]);
  const currentTeam = canView && teamData?.organizationId === effectiveOrgId ? teamData : null;
  const currentRoles = canViewRoles && roleData?.organizationId === effectiveOrgId ? roleData : null;
  const availableRoles = useMemo(() => currentRoles?.roles || [], [currentRoles]);
  const rolesReady = Boolean(currentRoles && !rolesLoading && !rolesError);
  const loading = dataLoading || Boolean(effectiveOrgId && !currentTeam && !error);
  const { activeMembers: teamMembers = [], pendingInvites = [], otherMemberships = [] } = currentTeam || {};
  const members = teamMembers.map((member) => memberForDisplay(member, currentUser));
  const remainingMemberships = otherMemberships.map((member) => memberForDisplay(member, currentUser));
  const teamReady = Boolean(effectiveOrgId && currentTeam && !loading && !error);
  const inviteRequested = searchParams.get('invite') === '1';
  const { open: openInvite, close: closeInvite } = inviteDialog;
  const { close: closeRole } = roleDialog;

  useEffect(() => {
    if (!inviteRequested || !teamReady || permissionsLoading || (canInvite && canViewRoles && !rolesReady)) return;
    const remainingParams = new URLSearchParams(searchParams);
    remainingParams.delete('invite');
    setSearchParams(remainingParams, { replace: true });
    if (canInvite && rolesReady) openInvite({ organizationId: effectiveOrgId, generation: ++inviteSequence.current });
  }, [inviteRequested, teamReady, permissionsLoading, canInvite, canViewRoles, rolesReady, effectiveOrgId, searchParams, setSearchParams, openInvite]);

  useEffect(() => {
    if (inviteDialog.isOpen && (!canInvite || !canViewRoles || inviteDialog.data?.organizationId !== effectiveOrgId)) closeInvite();
  }, [inviteDialog.isOpen, inviteDialog.data, effectiveOrgId, canInvite, canViewRoles, closeInvite]);

  useEffect(() => {
    if (roleDialog.isOpen && (!canAssignRoles || !canViewRoles || roleDialog.data?.organizationId !== effectiveOrgId)) closeRole();
  }, [roleDialog.isOpen, roleDialog.data, effectiveOrgId, canAssignRoles, canViewRoles, closeRole]);

  const defaultInviteRoleIds = useMemo(() => {
    const explicitDefaults = availableRoles
      .filter((role) => role.is_default_for_new_members)
      .map((role) => role.id);

    // An unconfigured default is not authority to select the first catalog
    // role, which could be an administrator role. Require an explicit choice.
    return explicitDefaults;
  }, [availableRoles]);

  const handleInvite = async (email, roleIds) => {
    const dialogContext = inviteDialog.data;
    if (!inviteDialog.isOpen || !canInvite || !teamReady || !rolesReady || dialogContext?.organizationId !== effectiveOrgId) return;
    const invitedOrgId = effectiveOrgId;
    const applies = () => active.current && currentOrgId.current === invitedOrgId
      && currentInviteDialog.current === dialogContext;
    try {
      await teamApi.inviteMember(invitedOrgId, {
        email,
        role_ids: roleIds,
      });
      if (!applies()) return;
      showNotification?.(t('org.team.dialog.invite.success'), 'success');
      inviteDialog.close();
      await loadData();
    } catch (err) {
      if (!applies()) return;
      console.error('Failed to invite member:', err);
      throw err;
    }
  };

  const handleChangeRole = async (memberId, roleIds) => {
    const dialogContext = roleDialog.data;
    if (!roleDialog.isOpen || !canAssignRoles || !teamReady || !rolesReady || dialogContext?.organizationId !== effectiveOrgId
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
    if (!canManage || !teamReady || removalPending.current) return;
    const removedOrgId = effectiveOrgId;
    const applies = () => active.current && currentOrgId.current === removedOrgId;
    if (!confirm(t('org.team.members.actions.confirmRemove', { email: memberEmail }))) {
      return;
    }

    removalPending.current = true;
    setRemoving(true);
    try {
      await teamApi.removeMember(removedOrgId, memberId);
      if (!applies()) return;
      const principalId = currentUser?.user_id || currentUser?.sub || currentUser?.id;
      if (principalId && teamMembers.some(member => member.id === memberId && member.user_id === principalId)) {
        reconcileMembershipRemoval(removedOrgId);
        showNotification?.(t('org.team.dialog.removeSuccess'), 'success');
        return;
      }
      showNotification?.(t('org.team.dialog.removeSuccess'), 'success');
      await loadData();
    } catch (err) {
      if (!applies() || err?.name === 'AbortError') return;
      console.error('Failed to remove member:', err);
      showNotification?.(t('org.team.dialog.removeError'), 'error');
    } finally {
      removalPending.current = false;
      if (applies()) setRemoving(false);
    }
  };

  const handleRevokeInvite = async (memberId) => {
    if (!canManage || !teamReady || removalPending.current || !pendingInvites.some((invite) => invite.id === memberId)) return;
    const revokedOrgId = effectiveOrgId;
    const applies = () => active.current && currentOrgId.current === revokedOrgId;
    if (!confirm(t('org.team.invites.actions.confirmRevoke'))) {
      return;
    }

    removalPending.current = true;
    setRemoving(true);
    try {
      await teamApi.removeMember(revokedOrgId, memberId);
      if (!applies()) return;
      showNotification?.(t('org.team.dialog.revokeSuccess'), 'success');
      await loadData();
    } catch (err) {
      if (!applies()) return;
      console.error('Failed to revoke invite:', err);
      showNotification?.(t('org.team.dialog.revokeError'), 'error');
    } finally {
      removalPending.current = false;
      if (applies()) setRemoving(false);
    }
  };

  return (
    <ResourcePage
      title={t('org.team.title')}
      subtitle={t('org.team.subtitle')}
      icon={<PeopleIcon />}
      tabs={getOrgTabs(t, currentPermission)}
      breadcrumbs={getBreadcrumbs(t)}
      pageTestId="org.team.page"
      actions={
        canInvite && (
          <Button
            variant="contained"
            startIcon={<AddIcon />}
            onClick={() => openInvite({ organizationId: effectiveOrgId, generation: ++inviteSequence.current })}
            disabled={!canInvite || !teamReady || !rolesReady}
            data-testid="org.team.invite.action"
          >
            {t('org.team.members.actions.invite')}
          </Button>
        )
      }
    >
      {!currentUser ? (
        <Alert severity="info">{t('org.team.access.signIn')}</Alert>
      ) : !effectiveOrgId ? (
        <Alert severity="info">{t('org.team.access.selectOrganization')}</Alert>
      ) : permissionsLoading ? (
        <TableSkeleton rows={5} columns={4} showActions />
      ) : permissionError ? (
        <ErrorState error={permissionError} onRetry={refreshPermissions} variant="compact" />
      ) : !canView ? (
        <Alert severity="info">{t('org.team.access.readDenied')}</Alert>
      ) : loading ? (
        <TableSkeleton rows={5} columns={4} showActions />
      ) : error ? (
        <ErrorState error={error} onRetry={loadData} variant="inline" />
      ) : (
        <>
          {rolesError && canViewRoles && (
            <Alert severity="error" sx={{ mb: 3 }} action={
              <Button color="inherit" onClick={loadRoles}>{t('actions.retry', { ns: 'common' })}</Button>
            }>
              {typeof rolesError?.message === 'string' && rolesError.message.trim()
                ? rolesError.message : t('org.team.access.rolesLoadFailed')}
            </Alert>
          )}
          {!canViewRoles && (canInvite || canAssignRoles) && (
            <Alert severity="info" sx={{ mb: 3 }}>{t('org.team.access.rolesReadRequired')}</Alert>
          )}
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
                <Table aria-label={t('org.team.members.title')}>
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
                          {!member.is_owner && (canManage || (canAssignRoles && canViewRoles)) && teamReady && (
                            <MemberActionsMenu
                              disabled={removing}
                              onChangeRole={canAssignRoles && canViewRoles ? () => roleDialog.open({ member, organizationId: effectiveOrgId }) : undefined}
                              roleDisabled={!rolesReady}
                              onRemove={canManage ? () => handleRemoveMember(member.id, member.email || getDisplayName(member)) : undefined}
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
            <Paper sx={{ mb: 3 }}>
              <Box sx={{ p: 2, borderBottom: 1, borderColor: 'divider' }}>
                <Typography variant="h6">{t('org.team.invites.title')}</Typography>
                <Typography variant="body2" color="text.secondary">
                  {t('org.team.invites.count', { count: pendingInvites.length })}
                </Typography>
              </Box>
              <TableContainer>
                <Table aria-label={t('org.team.invites.title')}>
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
                          {canManage && teamReady && (
                            <IconButton
                              size="small"
                              disabled={removing}
                              onClick={() => handleRevokeInvite(invite.id)}
                              title={t('org.team.invites.actions.revoke')}
                              aria-label={t('org.team.invites.actions.revoke')}
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

          {remainingMemberships.length > 0 && (
            <Paper>
              <Box sx={{ p: 2, borderBottom: 1, borderColor: 'divider' }}>
                <Typography variant="h6">{t('org.team.memberships.title')}</Typography>
                {canViewRequests && remainingMemberships.some((member) => member.status === 'pending') && (
                  <Button component={Link} to="/console/org/membership-requests" sx={{ mt: 1 }}>
                    {t('org.team.memberships.reviewRequests')}
                  </Button>
                )}
              </Box>
              <TableContainer>
                <Table aria-label={t('org.team.memberships.title')}>
                  <TableHead>
                    <TableRow>
                      <TableCell>{t('org.team.members.tableHeaders.name')}</TableCell>
                      <TableCell>{t('org.team.members.tableHeaders.email')}</TableCell>
                      <TableCell>{t('org.team.members.tableHeaders.role')}</TableCell>
                      <TableCell>{t('org.team.memberships.status')}</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {remainingMemberships.map((member) => (
                      <TableRow key={member.id}>
                        <TableCell>{getDisplayName(member)}</TableCell>
                        <TableCell>{member.email || '-'}</TableCell>
                        <TableCell><RoleChips roles={member.roles} /></TableCell>
                        <TableCell>
                          <Chip
                            label={membershipStatusLabel(member, t)}
                            size="small"
                            variant="outlined"
                            color={member.status === 'pending' ? 'warning' : 'default'}
                          />
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
        key={`${effectiveOrgId}:${inviteDialog.data?.generation || 0}:${inviteDialog.isOpen}`}
        open={inviteDialog.isOpen && inviteDialog.data?.organizationId === effectiveOrgId && canInvite && teamReady && rolesReady}
        availableRoles={availableRoles}
        defaultRoleIds={defaultInviteRoleIds}
        onClose={inviteDialog.close}
        onInvite={handleInvite}
        t={t}
      />

      <ChangeRoleDialog
        key={`${effectiveOrgId}:${roleDialog.data?.member?.id || ''}:${roleDialog.isOpen}`}
        open={roleDialog.isOpen && roleDialog.data?.organizationId === effectiveOrgId && canAssignRoles && teamReady && rolesReady}
        member={roleDialog.data?.member}
        availableRoles={availableRoles}
        onClose={roleDialog.close}
        onChangeRole={handleChangeRole}
        t={t}
      />
    </ResourcePage>
  );
}

function MemberActionsMenu({ onChangeRole, roleDisabled, onRemove, disabled = false }) {
  const { t } = useTranslation('console');
  const [anchorEl, setAnchorEl] = useState(null);
  const open = Boolean(anchorEl);

  return (
    <>
      <IconButton size="small" disabled={disabled} aria-label={t('org.team.members.tableHeaders.actions')} onClick={(event) => setAnchorEl(event.currentTarget)}>
        <MoreVertIcon />
      </IconButton>
      <Menu anchorEl={anchorEl} open={open} onClose={() => setAnchorEl(null)}>
        {onChangeRole && <MenuItem
          disabled={disabled || roleDisabled}
          onClick={() => {
            setAnchorEl(null);
            onChangeRole();
          }}
        >
          <ListItemIcon>
            <EditIcon fontSize="small" />
          </ListItemIcon>
          <ListItemText>{t('org.team.members.actions.changeRole')}</ListItemText>
        </MenuItem>}
        {onChangeRole && onRemove && <Divider />}
        {onRemove && <MenuItem
          disabled={disabled}
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
        </MenuItem>}
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
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');
  const requestPending = useRef(false);
  const active = useRef(false);

  useLayoutEffect(() => {
    active.current = true;
    return () => { active.current = false; };
  }, []);

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

  const handleSubmit = async () => {
    if (!email.trim() || selectedRoleIds.length === 0 || requestPending.current) {
      return;
    }

    requestPending.current = true;
    setSaving(true);
    setError('');
    try {
      await onInvite(email.trim(), selectedRoleIds);
    } catch (inviteError) {
      if (active.current) {
        setError(inviteError instanceof Error ? inviteError.message : t('org.team.dialog.invite.error'));
      }
    } finally {
      requestPending.current = false;
      if (active.current) setSaving(false);
    }
  };

  return (
    <Dialog open={open} onClose={saving ? undefined : onClose} maxWidth="sm" fullWidth>
      <DialogTitle>{t('org.team.dialog.invite.title')}</DialogTitle>
      <DialogContent>
        <Alert severity="info" sx={{ mb: 2 }}>
          {t('org.team.dialog.invite.info')}
        </Alert>
        {error && <Alert severity="error" sx={{ mb: 2 }}>{error}</Alert>}
        <TextField
          fullWidth
          label={t('org.team.dialog.invite.emailLabel')}
          type="email"
          value={email}
          onChange={(event) => setEmail(event.target.value)}
          disabled={saving}
          margin="normal"
          autoFocus
        />
        <FormControl fullWidth margin="normal">
          <InputLabel shrink>{t('org.team.dialog.invite.roleLabel')}</InputLabel>
          <Box sx={{ mt: 2 }}>
            <RoleSelection availableRoles={availableRoles} selectedRoleIds={selectedRoleIds} onToggle={handleToggleRole} disabled={saving} />
          </Box>
        </FormControl>
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose} disabled={saving}>{t('actions.cancel', { ns: 'common' })}</Button>
        <Button
          onClick={handleSubmit}
          variant="contained"
          disabled={saving || !email.trim() || selectedRoleIds.length === 0}
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

export default function TeamPage() {
  const { activeOrgId, reconcileMembershipRemoval } = useConsole();
  const { user, isAuthenticated } = useAuth();
  const principalId = isAuthenticated ? user?.user_id || user?.sub || user?.id || 'unknown-user' : 'signed-out';
  return (
    <TeamContent
      key={`${activeOrgId || 'no-organization'}:${principalId}`}
      organizationId={activeOrgId}
      currentUser={isAuthenticated ? user : null}
      reconcileMembershipRemoval={reconcileMembershipRemoval}
    />
  );
}

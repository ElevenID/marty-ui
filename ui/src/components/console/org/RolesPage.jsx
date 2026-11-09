import { useState, useEffect, useCallback, useMemo } from 'react';
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
  Chip,
  Alert,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  Checkbox,
  FormControlLabel,
  FormGroup,
  Tooltip,
  CircularProgress,
  Switch,
  MenuItem,
} from '@mui/material';
import AddIcon from '@mui/icons-material/Add';
import EditIcon from '@mui/icons-material/Edit';
import DeleteIcon from '@mui/icons-material/Delete';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import SecurityIcon from '@mui/icons-material/Security';
import LockIcon from '@mui/icons-material/Lock';
import PeopleIcon from '@mui/icons-material/People';
import StarIcon from '@mui/icons-material/Star';

import { ResourcePage, ConfirmDeleteDialog } from '../../common';
import { TableSkeleton } from '../../common/skeletons';
import ErrorState from '../../common/ErrorState';
import EmptyState from '../../common/EmptyState';
import { listRoles, createRole, updateRole, deleteRole, listPermissions } from '../../../services/rbacApi';
import { useNotifications } from '../../../hooks/useNotifications';
import { useDialog } from '../../../hooks/useDialog';
import { useAsyncActionScope } from '../../../hooks/useAsyncActionScope';
import { usePermissions } from '../../../hooks/usePermissions';
import { getResourceLabel } from '../../../config/permissions';
import { useConsole } from '../../../contexts/ConsoleContext';

/**
 * Org tabs navigation
 */
const getOrgTabs = (t) => [
  { label: t('org.tabs.organization'), path: '/console/org/settings' },
  { label: t('org.tabs.team'), path: '/console/org/team' },
  { label: 'Roles', path: '/console/org/roles' },
  { label: t('org.tabs.notifications'), path: '/console/org/notifications' },
];

const getBreadcrumbs = (t) => [
  { label: t('org.breadcrumbs.console'), path: '/console' },
  { label: t('org.breadcrumbs.org'), path: '/console/org' },
  { label: 'Roles', path: '/console/org/roles' },
];

/**
 * Group permissions by resource for the permission picker dialog
 */
function groupPermissions(permissions) {
  const groups = Object.create(null);
  for (const perm of permissions) {
    if (!groups[perm.resource]) {
      groups[perm.resource] = [];
    }
    groups[perm.resource].push(perm);
  }
  return groups;
}

/**
 * Role Management Page
 */
function RolesPageContent({ effectiveOrgId, canCreateRoles, canEditRoles, canDeleteRoles, refreshPermissions }) {
  const { t } = useTranslation('console');
  const { showNotification } = useNotifications();
  const beginLoad = useAsyncActionScope();
  const beginMutation = useAsyncActionScope();

  // Data state
  const [roles, setRoles] = useState([]);
  const [allPermissions, setAllPermissions] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  // Dialog state
  const [dialogOpen, setDialogOpen] = useState(false);
  const [editingRole, setEditingRole] = useState(null);
  const deleteDialog = useDialog();
  const [saving, setSaving] = useState(false);
  const [replacementRoleId, setReplacementRoleId] = useState('');

  // Form state
  const [formName, setFormName] = useState('');
  const [formDisplayName, setFormDisplayName] = useState('');
  const [formDescription, setFormDescription] = useState('');
  const [formPermissionIds, setFormPermissionIds] = useState(new Set());
  const [formIsDefault, setFormIsDefault] = useState(false);

  const deletingRole = roles.find(role => role.id === deleteDialog.data?.id) || deleteDialog.data;
  const needsReplacement = deletingRole?.member_count > 0 || deletingRole?.is_default_for_new_members;
  const replacementRoleOptions = useMemo(
    () => roles.filter((role) => role.id !== deleteDialog.data?.id && role.organization_id === effectiveOrgId),
    [deleteDialog.data?.id, effectiveOrgId, roles]
  );
  const selectedReplacement = replacementRoleOptions.find(role => role.id === replacementRoleId);

  // Load data
  const loadData = useCallback(async () => {
    const action = beginLoad();
    if (!action.isCurrent()) return;
    setLoading(true);
    setError(null);
    try {
      const [rolesData, permsData] = await action.run(() => Promise.all([
        listRoles(effectiveOrgId, true),
        listPermissions(effectiveOrgId),
      ]));
      if (!action.isCurrent()) return;
      setRoles(rolesData.roles || rolesData || []);
      setAllPermissions(permsData);
    } catch (err) {
      if (!action.isCurrent() || err?.name === 'AbortError') return;
      console.error('Failed to load roles:', err);
      setError('Failed to load roles. Please try again.');
    } finally {
      if (action.isCurrent()) setLoading(false);
    }
  }, [beginLoad, effectiveOrgId]);

  useEffect(() => {
    loadData();
  }, [loadData]);

  // Open create dialog
  const handleCreate = () => {
    if (loading || error || !effectiveOrgId || !canCreateRoles) return;
    setEditingRole(null);
    setFormName('');
    setFormDisplayName('');
    setFormDescription('');
    setFormPermissionIds(new Set());
    setFormIsDefault(false);
    setDialogOpen(true);
  };

  // Open edit dialog
  const handleEdit = (role) => {
    if (loading || error || saving || !canEditRoles || role.is_system_role) return;
    setEditingRole(role);
    setFormName(role.name);
    setFormDisplayName(role.display_name || '');
    setFormDescription(role.description || '');
    setFormPermissionIds(new Set((role.permissions || []).map(p => p.id)));
    setFormIsDefault(role.is_default_for_new_members || false);
    setDialogOpen(true);
  };

  // Save (create or update)
  const handleSave = async () => {
    if (saving || loading || error
      || (editingRole ? !canEditRoles || editingRole.is_system_role : !canCreateRoles)) return;
    const action = beginMutation();
    if (!action.isCurrent()) return;
    setSaving(true);
    try {
      const data = {
        display_name: formDisplayName || null,
        description: formDescription || null,
        permission_ids: Array.from(formPermissionIds),
        is_default_for_new_members: formIsDefault,
      };

      if (editingRole) {
        await action.run(updateRole, effectiveOrgId, editingRole.id, data);
        if (!action.isCurrent()) return;
        showNotification(`Role "${formDisplayName || formName}" updated`, 'success');
      } else {
        await action.run(createRole, effectiveOrgId, { ...data, name: formName });
        if (!action.isCurrent()) return;
        showNotification(`Role "${formDisplayName || formName}" created`, 'success');
      }

      setDialogOpen(false);
      await action.run(loadData);
      await action.run(refreshPermissions);
    } catch (err) {
      if (!action.isCurrent() || err?.name === 'AbortError') return;
      console.error('Failed to save role:', err);
      showNotification(err.message || 'Failed to save role', 'error');
    } finally {
      if (action.isCurrent()) setSaving(false);
    }
  };

  // Delete
  const handleDeleteConfirm = async () => {
    if (saving || !canDeleteRoles) return;
    const action = beginMutation();
    if (!action.isCurrent()) return;
    setSaving(true);
    try {
      if (needsReplacement && !replacementRoleId) {
        throw new Error('Choose a replacement role before deleting this role.');
      }

      // Recheck current membership counts and the explicitly chosen target before
      // deleting; the native transaction remains authoritative for later races.
      const freshData = await action.run(listRoles, effectiveOrgId, true);
      if (!action.isCurrent()) return;
      const freshRoles = freshData.roles || freshData;
      if (!Array.isArray(freshRoles)) throw new Error('Unable to verify the current roles. Try again.');
      const currentRole = freshRoles.find(role => role.id === deleteDialog.data?.id && role.organization_id === effectiveOrgId);
      if (!currentRole || currentRole.is_system_role) throw new Error('This role is no longer available for deletion.');
      const currentNeedsReplacement = currentRole.member_count > 0 || currentRole.is_default_for_new_members;
      setRoles(freshRoles.filter(role => role.organization_id === effectiveOrgId));
      if (currentNeedsReplacement && !replacementRoleId) {
        throw new Error('Choose a replacement role before deleting this role.');
      }
      if (replacementRoleId && !freshRoles.some(role => role.id === replacementRoleId
        && role.id !== currentRole.id && role.organization_id === effectiveOrgId)) {
        setReplacementRoleId('');
        throw new Error('The selected replacement role is no longer available. Choose another role.');
      }
      await action.run(deleteRole, effectiveOrgId, currentRole.id, replacementRoleId || undefined);
      if (!action.isCurrent()) return;
      showNotification(`Role "${deleteDialog.data.display_name || deleteDialog.data.name}" deleted`, 'success');
      await action.run(loadData);
      await action.run(refreshPermissions);
    } catch (err) {
      if (!action.isCurrent() || err?.name === 'AbortError') return;
      showNotification(err.message || 'Failed to delete role', 'error');
      throw err;
    } finally {
      if (action.isCurrent()) setSaving(false);
    }
  };

  // Toggle a permission in the form
  const togglePermission = (permId) => {
    setFormPermissionIds(prev => {
      const next = new Set(prev);
      if (next.has(permId)) {
        next.delete(permId);
      } else {
        next.add(permId);
      }
      return next;
    });
  };

  // Toggle all permissions for a resource group
  const toggleResourceGroup = (resourcePerms) => {
    setFormPermissionIds(prev => {
      const next = new Set(prev);
      const allSelected = resourcePerms.every(p => next.has(p.id));
      for (const perm of resourcePerms) {
        if (allSelected) {
          next.delete(perm.id);
        } else {
          next.add(perm.id);
        }
      }
      return next;
    });
  };

  const groupedPermissions = groupPermissions(allPermissions);


  // ─ Render ─────────────────────────────────────────────────────────────

  return (
    <ResourcePage
      title="Roles & Permissions"
      icon={SecurityIcon}
      tabs={getOrgTabs(t)}
      breadcrumbs={getBreadcrumbs(t)}
      actions={
        canCreateRoles ? (
          <Button
            variant="contained"
            startIcon={<AddIcon />}
            onClick={handleCreate}
            disabled={loading || !!error || !effectiveOrgId}
          >
            Create Role
          </Button>
        ) : null
      }
    >
      {loading ? (
        <TableSkeleton rows={4} />
      ) : error ? (
        <ErrorState message={error} onRetry={loadData} />
      ) : roles.length === 0 ? (
        <EmptyState
          icon={SecurityIcon}
          title="No roles configured"
          description="Roles define what permissions team members have in this organization."
          action={
            canCreateRoles && (
              <Button variant="contained" startIcon={<AddIcon />} onClick={handleCreate}>
                Create Role
              </Button>
            )
          }
        />
      ) : (
        <TableContainer component={Paper}>
          <Table>
            <TableHead>
              <TableRow>
                <TableCell>Role</TableCell>
                <TableCell>Description</TableCell>
                <TableCell align="center">Permissions</TableCell>
                <TableCell align="center">Members</TableCell>
                <TableCell align="center">Default</TableCell>
                <TableCell align="right">Actions</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {roles.map((role) => (
                <TableRow key={role.id} hover>
                  <TableCell>
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                      <Typography variant="body1" sx={{ fontWeight: 500 }}>
                        {role.display_name || role.name}
                      </Typography>
                      {role.is_system_role && (
                        <Chip label="System" size="small" color="default" variant="outlined" />
                      )}
                    </Box>
                    <Typography variant="caption" color="text.secondary">
                      {role.name}
                    </Typography>
                  </TableCell>
                  <TableCell>
                    <Typography variant="body2" color="text.secondary">
                      {role.description || '—'}
                    </Typography>
                  </TableCell>
                  <TableCell align="center">
                    <Chip
                      label={role.permissions?.length || 0}
                      size="small"
                      color="primary"
                      variant="outlined"
                    />
                  </TableCell>
                  <TableCell align="center">
                    <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 0.5 }}>
                      <PeopleIcon fontSize="small" color="action" />
                      {role.member_count ?? '—'}
                    </Box>
                  </TableCell>
                  <TableCell align="center">
                    {role.is_default_for_new_members ? (
                      <Tooltip title="New members are automatically assigned this role">
                        <StarIcon color="warning" fontSize="small" />
                      </Tooltip>
                    ) : '—'}
                  </TableCell>
                  <TableCell align="right">
                    {role.is_system_role ? (
                      <Tooltip title="System roles cannot be edited">
                        <span>
                          <IconButton disabled aria-label={`System role ${role.display_name || role.name} is read-only`}>
                            <LockIcon fontSize="small" />
                          </IconButton>
                        </span>
                      </Tooltip>
                    ) : (canEditRoles || canDeleteRoles) ? (
                      <>
                        <IconButton
                          size="small"
                          aria-label={`Edit role ${role.display_name || role.name}`}
                          onClick={() => handleEdit(role)}
                          disabled={!canEditRoles}
                        >
                          <EditIcon fontSize="small" />
                        </IconButton>
                        <IconButton
                          size="small"
                          color="error"
                          aria-label={`Delete role ${role.display_name || role.name}`}
                          onClick={() => { setReplacementRoleId(''); deleteDialog.open(role); }}
                          disabled={!canDeleteRoles}
                        >
                          <DeleteIcon fontSize="small" />
                        </IconButton>
                      </>
                    ) : null}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>
      )}

      {/* Create / Edit Dialog */}
      <Dialog
        open={dialogOpen}
        onClose={() => !saving && setDialogOpen(false)}
        maxWidth="md"
        fullWidth
      >
        <DialogTitle>
          {editingRole ? `Edit Role: ${editingRole.display_name || editingRole.name}` : 'Create Custom Role'}
        </DialogTitle>
        <DialogContent dividers>
          <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2, mt: 1 }}>
            <TextField
              label="Name"
              value={formName}
              onChange={(e) => setFormName(e.target.value)}
              required
              helperText="Unique identifier (lowercase, hyphens allowed)"
              disabled={!!editingRole}
              fullWidth
            />
            <TextField
              label="Display Name"
              value={formDisplayName}
              onChange={(e) => setFormDisplayName(e.target.value)}
              fullWidth
            />
            <TextField
              label="Description"
              value={formDescription}
              onChange={(e) => setFormDescription(e.target.value)}
              multiline
              rows={2}
              fullWidth
            />
            <FormControlLabel
              control={
                <Switch
                  checked={formIsDefault}
                  onChange={(e) => setFormIsDefault(e.target.checked)}
                />
              }
              label="Default role for new members"
            />

            <Typography variant="subtitle1" sx={{ mt: 2, mb: 1 }}>
              Permissions
            </Typography>
            <Alert severity="info" sx={{ mb: 1 }}>
              Select which resource actions this role grants access to.
            </Alert>
            
            {Object.entries(groupedPermissions).map(([resource, perms]) => {
              const allSelected = perms.every(p => formPermissionIds.has(p.id));
              const someSelected = perms.some(p => formPermissionIds.has(p.id));
              return (
                <Accordion key={resource} disableGutters>
                  <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                    <Checkbox
                      checked={allSelected}
                      indeterminate={someSelected && !allSelected}
                      onChange={() => toggleResourceGroup(perms)}
                      onClick={(e) => e.stopPropagation()}
                      slotProps={{ input: { 'aria-label': `Select all ${getResourceLabel(resource)} permissions` } }}
                      size="small"
                    />
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                      <Typography variant="subtitle2">
                        {getResourceLabel(resource)}
                      </Typography>
                      <Chip
                        label={`${perms.filter(p => formPermissionIds.has(p.id)).length}/${perms.length}`}
                        size="small"
                        variant="outlined"
                      />
                    </Box>
                  </AccordionSummary>
                  <AccordionDetails>
                    <FormGroup>
                      {perms.map(perm => (
                        <FormControlLabel
                          key={perm.id}
                          control={
                            <Checkbox
                              checked={formPermissionIds.has(perm.id)}
                              onChange={() => togglePermission(perm.id)}
                              size="small"
                            />
                          }
                          label={
                            <Box>
                              <Typography variant="body2">{perm.action}</Typography>
                              {perm.description && (
                                <Typography variant="caption" color="text.secondary">
                                  {perm.description}
                                </Typography>
                              )}
                            </Box>
                          }
                        />
                      ))}
                    </FormGroup>
                  </AccordionDetails>
                </Accordion>
              );
            })}
          </Box>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setDialogOpen(false)} disabled={saving}>Cancel</Button>
          <Button
            variant="contained"
            onClick={handleSave}
            disabled={saving || !formName.trim()}
            startIcon={saving ? <CircularProgress size={16} /> : null}
          >
            {editingRole ? 'Save Changes' : 'Create Role'}
          </Button>
        </DialogActions>
      </Dialog>

      <ConfirmDeleteDialog
        open={deleteDialog.isOpen}
        onClose={() => !saving && deleteDialog.close()}
        onConfirm={handleDeleteConfirm}
        loading={saving}
        title="Delete Role"
        itemName={deleteDialog.data?.display_name || deleteDialog.data?.name}
        warning={
          needsReplacement ? (
            <Box sx={{ mt: 2 }}>
              <Alert severity="warning" sx={{ mb: 2 }}>
                This role is assigned to {deletingRole.member_count} member(s).
                {deletingRole.is_default_for_new_members && ' It is also the default for new members.'}
                {' Choose a replacement role before deleting it.'}
              </Alert>
              <TextField
                select
                label="Replacement role"
                value={replacementRoleId}
                onChange={(event) => setReplacementRoleId(event.target.value)}
                disabled={saving || replacementRoleOptions.length === 0}
                helperText={replacementRoleOptions.length ? 'No role is selected automatically.' : 'Create another role before deleting this role.'}
                fullWidth
              >
                {replacementRoleOptions.map(role => (
                  <MenuItem key={role.id} value={role.id}>{role.display_name || role.name}</MenuItem>
                ))}
              </TextField>
              {selectedReplacement && (
                <Alert severity="info" sx={{ mt: 2 }}>
                  Members will be reassigned to "{selectedReplacement.display_name || selectedReplacement.name}".
                  {deletingRole.is_default_for_new_members && ' This choice will also become the default for new members.'}
                </Alert>
              )}
            </Box>
          ) : null
        }
      />
    </ResourcePage>
  );
}

function RolesPage() {
  const { activeOrgId } = useConsole();
  const { can, isLoading, refresh } = usePermissions();
  if (!activeOrgId) {
    return <EmptyState title="Select an organization" description="Choose an organization to manage its roles." />;
  }
  if (isLoading) return <CircularProgress aria-label="Checking role permissions" />;
  if (!can('role', 'view')) {
    return <ErrorState title="Access denied" message="You do not have permission to view roles in this organization." showSupport={false} />;
  }
  const canCreateRoles = can('role', 'create');
  const canEditRoles = can('role', 'edit');
  const canDeleteRoles = can('role', 'delete');
  // Organization or grant changes discard forms and invalidate every captured
  // loader/mutation. The surrounding ConsoleProvider owns account lifetimes.
  return <RolesPageContent
    key={JSON.stringify([activeOrgId, canCreateRoles, canEditRoles, canDeleteRoles])}
    effectiveOrgId={activeOrgId}
    canCreateRoles={canCreateRoles}
    canEditRoles={canEditRoles}
    canDeleteRoles={canDeleteRoles}
    refreshPermissions={refresh}
  />;
}

export default RolesPage;

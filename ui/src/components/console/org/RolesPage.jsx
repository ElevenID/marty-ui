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
import { useAuth } from '../../../hooks/useAuth';
import { useNotifications } from '../../../hooks/useNotifications';
import { useDialog } from '../../../hooks/useDialog';
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
  const groups = {};
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
function RolesPage() {
  const { t } = useTranslation('console');
  const { organizationId } = useAuth();
  const { activeOrgId } = useConsole();
  const { showNotification } = useNotifications();
  const { can, refresh: refreshPermissions } = usePermissions();
  const effectiveOrgId = activeOrgId || organizationId;

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

  // Form state
  const [formName, setFormName] = useState('');
  const [formDisplayName, setFormDisplayName] = useState('');
  const [formDescription, setFormDescription] = useState('');
  const [formPermissionIds, setFormPermissionIds] = useState(new Set());
  const [formIsDefault, setFormIsDefault] = useState(false);

  const canCreateRoles = can('role', 'create');
  const canEditRoles = can('role', 'edit');
  const canDeleteRoles = can('role', 'delete');
  const replacementRoleOptions = useMemo(
    () => roles.filter((role) => role.id !== deleteDialog.data?.id),
    [deleteDialog.data?.id, roles]
  );

  // Load data
  const loadData = useCallback(async () => {
    if (!effectiveOrgId) {
      setRoles([]);
      setAllPermissions([]);
      setLoading(false);
      return;
    }
    setLoading(true);
    setError(null);
    try {
      const [rolesData, permsData] = await Promise.all([
        listRoles(effectiveOrgId, true),
        listPermissions(effectiveOrgId),
      ]);
      setRoles(rolesData.roles || rolesData || []);
      // permsData is grouped by resource — flatten to a flat list
      const flat = [];
      if (permsData.resources) {
        for (const group of permsData.resources) {
          for (const perm of group.permissions) {
            flat.push({ ...perm, resource: group.resource });
          }
        }
      } else if (Array.isArray(permsData)) {
        flat.push(...permsData);
      }
      setAllPermissions(flat);
    } catch (err) {
      console.error('Failed to load roles:', err);
      setError('Failed to load roles. Please try again.');
    } finally {
      setLoading(false);
    }
  }, [effectiveOrgId]);

  useEffect(() => {
    loadData();
  }, [loadData]);

  // Open create dialog
  const handleCreate = () => {
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
    setSaving(true);
    try {
      const data = {
        name: formName,
        display_name: formDisplayName || null,
        description: formDescription || null,
        permission_ids: Array.from(formPermissionIds),
        is_default_for_new_members: formIsDefault,
      };

      if (editingRole) {
        await updateRole(effectiveOrgId, editingRole.id, data);
        showNotification(`Role "${formDisplayName || formName}" updated`, 'success');
      } else {
        await createRole(effectiveOrgId, data);
        showNotification(`Role "${formDisplayName || formName}" created`, 'success');
      }

      setDialogOpen(false);
      await loadData();
      await refreshPermissions();
    } catch (err) {
      console.error('Failed to save role:', err);
      showNotification(err.message || 'Failed to save role', 'error');
    } finally {
      setSaving(false);
    }
  };

  // Delete
  const handleDeleteConfirm = async () => {
    setSaving(true);
    try {
      const replacementRoleId = deleteDialog.data?.member_count > 0
        ? (replacementRoleOptions.find((role) => role.is_default_for_new_members)?.id || replacementRoleOptions[0]?.id)
        : undefined;

      if (deleteDialog.data?.member_count > 0 && !replacementRoleId) {
        throw new Error('This role still has members assigned and there is no replacement role available.');
      }

      await deleteRole(effectiveOrgId, deleteDialog.data.id, replacementRoleId);
      showNotification(`Role "${deleteDialog.data.display_name || deleteDialog.data.name}" deleted`, 'success');
      await loadData();
      await refreshPermissions();
    } catch (err) {
      showNotification(err.message || 'Failed to delete role', 'error');
      throw err;
    } finally {
      setSaving(false);
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
                      <Typography variant="body1" fontWeight={500}>
                        {role.display_name || role.name}
                      </Typography>
                      {role.is_system && (
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
                    {role.is_system ? (
                      <Tooltip title="System roles cannot be edited">
                        <span>
                          <IconButton disabled>
                            <LockIcon fontSize="small" />
                          </IconButton>
                        </span>
                      </Tooltip>
                    ) : (canEditRoles || canDeleteRoles) ? (
                      <>
                        <IconButton size="small" onClick={() => handleEdit(role)} disabled={!canEditRoles}>
                          <EditIcon fontSize="small" />
                        </IconButton>
                        <IconButton
                          size="small"
                          color="error"
                          onClick={() => deleteDialog.open(role)}
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
        onClose={() => setDialogOpen(false)}
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
          <Button onClick={() => setDialogOpen(false)}>Cancel</Button>
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
          deleteDialog.data?.member_count > 0 ? (
            <Alert severity="warning" sx={{ mt: 2 }}>
              This role is currently assigned to {deleteDialog.data.member_count} member(s).
              They will be reassigned to the default role.
            </Alert>
          ) : null
        }
      />
    </ResourcePage>
  );
}

export default RolesPage;

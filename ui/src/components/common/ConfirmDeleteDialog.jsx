import { useLayoutEffect, useRef, useState } from 'react';
import {
  Alert,
  Button,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  Typography,
} from '@mui/material';
import DeleteIcon from '@mui/icons-material/Delete';

/**
 * ConfirmDeleteDialog — reusable destructive-action confirmation dialog.
 *
 * Covers the ~15 instances of the pattern:
 *   <Dialog open={deleteDialogOpen} onClose={...}>
 *     <DialogTitle>Delete X</DialogTitle>
 *     <DialogContent>Are you sure?</DialogContent>
 *     <DialogActions><Button>Cancel</Button> <Button color="error">Delete</Button></DialogActions>
 *   </Dialog>
 *
 * @example — basic usage
 *   <ConfirmDeleteDialog
 *     open={deleteDialog.isOpen}
 *     onClose={deleteDialog.close}
 *     onConfirm={() => handleDelete(deleteDialog.data.id)}
 *     title="Delete Role"
 *     itemName={deleteDialog.data?.display_name}
 *   />
 *
 * @example — with extra warning content and custom confirm label
 *   <ConfirmDeleteDialog
 *     open={open}
 *     onClose={onClose}
 *     onConfirm={handleRevoke}
 *     title="Revoke API Key"
 *     itemName={selectedKey?.name}
 *     confirmLabel="Revoke"
 *     warning={
 *       <Alert severity="warning" sx={{ mt: 2 }}>
 *         Any applications using this key will stop working immediately.
 *       </Alert>
 *     }
 *   />
 */
function ConfirmDeleteDialogState({
  /** Whether the dialog is visible. */
  open,
  /** Called when the user dismisses the dialog without confirming. */
  onClose,
  /**
   * Called when the user clicks the confirm button.
   * May return a Promise — the button will show a loading spinner until it
   * resolves/rejects, and the dialog will close automatically on success.
   */
  onConfirm,
  /** Dialog title, e.g. "Delete Role". */
  title = 'Confirm Delete',
  /**
   * Name of the item being deleted, rendered in bold inside the body text.
   * When omitted the body just reads "Are you sure? This action cannot be undone."
   */
  itemName,
  /**
   * Additional content rendered below the main confirmation text.
   * Useful for severity warnings, impact notices, etc.
   */
  warning,
  /** Label for the confirm/destructive button. Defaults to "Delete". */
  confirmLabel = 'Delete',
  /**
   * Externally controlled loading state. When true, the confirm button shows a
   * spinner.  Leave undefined to let the dialog manage its own loading state
   * from the Promise returned by onConfirm.
   */
  loading: loadingProp,
}) {
  const [internalLoading, setInternalLoading] = useState(false);
  const [error, setError] = useState('');
  const active = useRef(false);
  const requestPending = useRef(false);
  const loading = Boolean(loadingProp || internalLoading);
  const action = typeof confirmLabel === 'string' ? confirmLabel.toLowerCase() : 'delete';
  const pendingLabel = action === 'revoke' ? 'Revoking…' : action === 'delete' ? 'Deleting…' : 'Working…';

  useLayoutEffect(() => {
    active.current = true;
    return () => { active.current = false; };
  }, []);

  const handleConfirm = async () => {
    if (loading || requestPending.current) return;
    requestPending.current = true;
    setInternalLoading(true);
    setError('');
    try {
      await onConfirm?.();
      if (active.current) onClose?.();
    } catch (actionError) {
      if (active.current) {
        setError((actionError instanceof Error && actionError.message) || 'This action could not be completed. Please try again.');
      }
    } finally {
      requestPending.current = false;
      if (active.current) setInternalLoading(false);
    }
  };

  return (
    <Dialog open={open} onClose={loading ? undefined : onClose} maxWidth="xs" fullWidth>
      <DialogTitle>{title}</DialogTitle>

      <DialogContent>
        <Typography>
          {itemName ? (
            <>
              Are you sure you want to {action} <strong>{itemName}</strong>? This
              action cannot be undone.
            </>
          ) : (
            'Are you sure? This action cannot be undone.'
          )}
        </Typography>

        {warning}
        {error && <Alert severity="error" sx={{ mt: 2 }}>{error}</Alert>}
      </DialogContent>

      <DialogActions>
        <Button onClick={onClose} disabled={loading}>
          Cancel
        </Button>
        <Button
          variant="contained"
          color="error"
          onClick={handleConfirm}
          disabled={loading}
          startIcon={<DeleteIcon />}
        >
          {loading ? pendingLabel : confirmLabel}
        </Button>
      </DialogActions>
    </Dialog>
  );
}

export default function ConfirmDeleteDialog(props) {
  // A replacement target or a reopened dialog must not inherit a prior request.
  return <ConfirmDeleteDialogState key={`${Boolean(props.open)}:${props.itemName ?? ''}`} {...props} />;
}

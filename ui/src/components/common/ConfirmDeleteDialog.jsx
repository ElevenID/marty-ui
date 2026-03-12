import { useState } from 'react';
import {
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
export default function ConfirmDeleteDialog({
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
  const loading = loadingProp !== undefined ? loadingProp : internalLoading;

  const handleConfirm = async () => {
    const result = onConfirm?.();
    if (result && typeof result.then === 'function') {
      setInternalLoading(true);
      try {
        await result;
        onClose?.();
      } finally {
        setInternalLoading(false);
      }
    } else {
      onClose?.();
    }
  };

  return (
    <Dialog open={open} onClose={onClose} maxWidth="xs" fullWidth>
      <DialogTitle>{title}</DialogTitle>

      <DialogContent>
        <Typography>
          {itemName ? (
            <>
              Are you sure you want to delete <strong>{itemName}</strong>? This
              action cannot be undone.
            </>
          ) : (
            'Are you sure? This action cannot be undone.'
          )}
        </Typography>

        {warning}
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
          {loading ? 'Deleting…' : confirmLabel}
        </Button>
      </DialogActions>
    </Dialog>
  );
}

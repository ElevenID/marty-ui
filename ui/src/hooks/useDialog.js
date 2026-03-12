import { useState, useCallback } from 'react';

/**
 * useDialog — manages the open/close state and optional associated data for a
 * single MUI Dialog (or any controlled modal).
 *
 * Eliminates the recurring pattern:
 *   const [dialogOpen, setDialogOpen] = useState(false);
 *   const [editingItem, setEditingItem] = useState(null);
 *   const handleOpen = (item) => { setEditingItem(item); setDialogOpen(true); };
 *   const handleClose = () => { setDialogOpen(false); setEditingItem(null); };
 *
 * @example — create dialog:
 *   const createDialog = useDialog();
 *   // open with no associated item
 *   <Button onClick={() => createDialog.open()}>New item</Button>
 *   <ItemDialog open={createDialog.isOpen} onClose={createDialog.close} />
 *
 * @example — edit dialog with item data:
 *   const editDialog = useDialog();
 *   // open with the item to edit
 *   <IconButton onClick={() => editDialog.open(item)}>Edit</IconButton>
 *   <ItemDialog
 *     open={editDialog.isOpen}
 *     item={editDialog.data}
 *     onClose={editDialog.close}
 *   />
 *
 * @example — confirm-delete dialog:
 *   const deleteDialog = useDialog();
 *   <IconButton onClick={() => deleteDialog.open(item)}>Delete</IconButton>
 *   <ConfirmDialog
 *     open={deleteDialog.isOpen}
 *     title={`Delete "${deleteDialog.data?.name}"?`}
 *     onConfirm={() => { handleDelete(deleteDialog.data.id); deleteDialog.close(); }}
 *     onCancel={deleteDialog.close}
 *   />
 *
 * @param {any} [initialData=null] - Optional default value for `data` when the
 *   dialog is first opened without an argument.
 * @returns {{
 *   isOpen: boolean,
 *   data: any,
 *   open: (data?: any) => void,
 *   close: () => void
 * }}
 */
export function useDialog(initialData = null) {
  const [isOpen, setIsOpen] = useState(false);
  const [data, setData] = useState(initialData);

  /**
   * Open the dialog, optionally associating arbitrary data (e.g. the item
   * being edited or deleted).
   *
   * @param {any} [newData] - Data to attach to this dialog instance.
   *   Defaults to `initialData` when omitted.
   */
  const open = useCallback(
    (newData = initialData) => {
      setData(newData);
      setIsOpen(true);
    },
    [initialData],
  );

  /**
   * Close the dialog and reset associated data to the initial value.
   */
  const close = useCallback(() => {
    setIsOpen(false);
    // Delay the data reset until after the close animation completes so that
    // dialog content doesn't flicker during the exit transition.
    setTimeout(() => setData(initialData), 150);
  }, [initialData]);

  return { isOpen, data, open, close };
}

export default useDialog;

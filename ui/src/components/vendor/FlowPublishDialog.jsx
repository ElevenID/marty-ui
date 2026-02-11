/**
 * Flow Publish Dialog
 * 
 * Confirms publishing a flow and displays the generated public URL/QR code.
 */

import { useState } from 'react';
import {
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Button,
  TextField,
  Alert,
  CircularProgress,
  Box,
  Typography,
  IconButton,
  InputAdornment,
  Divider,
} from '@mui/material';
import PublishIcon from '@mui/icons-material/Publish';
import CloseIcon from '@mui/icons-material/Close';
import ContentCopyIcon from '@mui/icons-material/ContentCopy';
import QrCodeIcon from '@mui/icons-material/QrCode';
import PropTypes from 'prop-types';
import flowsApi from '../../services/flowsApi';

function FlowPublishDialog({ open, onClose, flow, onPublished }) {
  const [changeDescription, setChangeDescription] = useState('');
  const [publishing, setPublishing] = useState(false);
  const [error, setError] = useState(null);
  const [published, setPublished] = useState(false);
  const [publicUrl, setPublicUrl] = useState(null);

  const handlePublish = async () => {
    setPublishing(true);
    setError(null);

    try {
      const result = await flowsApi.publishFlow(flow.id, {
        change_description: changeDescription,
      });
      
      setPublished(true);
      setPublicUrl(result.public_url || `${window.location.origin}/apply/${flow.id}`);
      
      if (onPublished) {
        onPublished(result);
      }
    } catch (err) {
      setError(err.message || 'Failed to publish flow');
    } finally {
      setPublishing(false);
    }
  };

  const handleCopyUrl = () => {
    if (publicUrl) {
      navigator.clipboard.writeText(publicUrl);
      // Could add a snackbar notification here
    }
  };

  const handleClose = () => {
    setChangeDescription('');
    setPublished(false);
    setPublicUrl(null);
    setError(null);
    onClose();
  };

  return (
    <Dialog open={open} onClose={handleClose} maxWidth="sm" fullWidth>
      <DialogTitle>
        {published ? 'Flow Published' : 'Publish Flow'}
        <IconButton
          onClick={handleClose}
          sx={{ position: 'absolute', right: 8, top: 8 }}
        >
          <CloseIcon />
        </IconButton>
      </DialogTitle>
      
      <DialogContent>
        {error && (
          <Alert severity="error" sx={{ mb: 2 }}>
            {error}
          </Alert>
        )}

        {!published ? (
          <>
            <Alert severity="info" sx={{ mb: 3 }}>
              Publishing will make this flow available to applicants and generate a public application URL. 
              This will also lock the referenced Credential Template version.
            </Alert>

            <Typography variant="body2" color="text.secondary" gutterBottom>
              <strong>Flow Name:</strong> {flow?.name || 'Unknown'}
            </Typography>
            
            <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
              <strong>Type:</strong> {flow?.flow_type || 'Unknown'}
            </Typography>

            <TextField
              fullWidth
              multiline
              rows={3}
              label="Change Description (Optional)"
              placeholder="Describe what's new in this version..."
              value={changeDescription}
              onChange={(e) => setChangeDescription(e.target.value)}
              sx={{ mb: 2 }}
            />
          </>
        ) : (
          <>
            <Alert severity="success" sx={{ mb: 3 }}>
              Flow successfully published! Share the URL below with applicants.
            </Alert>

            <Typography variant="subtitle2" gutterBottom>
              Public Application URL
            </Typography>
            
            <TextField
              fullWidth
              value={publicUrl || ''}
              InputProps={{
                readOnly: true,
                endAdornment: (
                  <InputAdornment position="end">
                    <IconButton onClick={handleCopyUrl} edge="end">
                      <ContentCopyIcon />
                    </IconButton>
                  </InputAdornment>
                ),
              }}
              sx={{ mb: 2 }}
            />

            <Divider sx={{ my: 2 }} />

            <Box sx={{ textAlign: 'center' }}>
              <QrCodeIcon sx={{ fontSize: 120, color: 'primary.main', mb: 1 }} />
              <Typography variant="caption" display="block" color="text.secondary">
                QR code generation coming soon
              </Typography>
            </Box>
          </>
        )}
      </DialogContent>

      <DialogActions>
        <Button onClick={handleClose}>
          {published ? 'Close' : 'Cancel'}
        </Button>
        {!published && (
          <Button
            variant="contained"
            onClick={handlePublish}
            disabled={publishing}
            startIcon={publishing ? <CircularProgress size={16} /> : <PublishIcon />}
          >
            {publishing ? 'Publishing...' : 'Publish Flow'}
          </Button>
        )}
      </DialogActions>
    </Dialog>
  );
}

FlowPublishDialog.propTypes = {
  open: PropTypes.bool.isRequired,
  onClose: PropTypes.func.isRequired,
  flow: PropTypes.object,
  onPublished: PropTypes.func,
};

export default FlowPublishDialog;

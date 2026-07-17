/**
 * Flow Publish Dialog
 * 
 * Confirms publishing a flow and displays the generated public URL/QR code.
 */

import { useState } from 'react';
import { useTranslation } from 'react-i18next';
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
import {
  getFlowPublishFailureState,
  getFlowPublishInitialState,
  publishFlowDefinition,
  resetFlowPublishState,
} from '../../application/flows';

function FlowPublishDialog({ open, onClose, flow, onPublished }) {
  const { t } = useTranslation('vendor');
  const [state, setState] = useState(getFlowPublishInitialState());
  const {
    changeDescription,
    publishing,
    error,
    published,
    publicUrl,
  } = state;

  const handlePublish = async () => {
    setState((currentState) => ({
      ...currentState,
      publishing: true,
      error: null,
    }));

    try {
      const { result, state: nextState } = await publishFlowDefinition({
        publishFlow: flowsApi.publishFlow,
        flow,
        changeDescription,
        fallbackOrigin: window.location.origin,
      });
      setState((currentState) => ({
        ...currentState,
        ...nextState,
      }));
      
      if (onPublished) {
        onPublished(result);
      }
    } catch (err) {
      setState((currentState) => ({
        ...currentState,
        ...getFlowPublishFailureState({
          error: err,
          fallbackMessage: t('flowPublishDialog.failedToPublish'),
        }),
      }));
    }
  };

  const handleCopyUrl = () => {
    if (publicUrl) {
      navigator.clipboard.writeText(publicUrl);
      // Could add a snackbar notification here
    }
  };

  const handleClose = () => {
    setState(resetFlowPublishState());
    onClose();
  };

  return (
    <Dialog open={open} onClose={handleClose} maxWidth="sm" fullWidth>
      <DialogTitle>
        {published ? t('flowPublishDialog.titlePublished') : t('flowPublishDialog.title')}
        <IconButton
          onClick={handleClose}
          aria-label="close"
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
              {t('flowPublishDialog.infoMessage')}
            </Alert>

            <Typography variant="body2" color="text.secondary" gutterBottom>
              <strong>{t('flowPublishDialog.flowNameLabel')}:</strong> {flow?.name || t('flowPublishDialog.unknown')}
            </Typography>
            
            <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
              <strong>{t('flowPublishDialog.typeLabel')}:</strong> {flow?.flow_type || t('flowPublishDialog.unknown')}
            </Typography>

            <TextField
              fullWidth
              multiline
              rows={3}
              label={t('flowPublishDialog.changeDescriptionLabel')}
              placeholder={t('flowPublishDialog.changeDescriptionPlaceholder')}
              value={changeDescription}
              onChange={(e) => setState((currentState) => ({
                ...currentState,
                changeDescription: e.target.value,
              }))}
              sx={{ mb: 2 }}
              slotProps={{
                htmlInput: {
                  'aria-label': t('flowPublishDialog.changeDescriptionLabel'),
                }
              }}
            />
          </>
        ) : (
          <>
            <Alert severity="success" sx={{ mb: 3 }}>
              {t('flowPublishDialog.successMessage')}
            </Alert>

            <Typography variant="subtitle2" gutterBottom>
              {t('flowPublishDialog.publicUrlLabel')}
            </Typography>
            
            <TextField
              fullWidth
              value={publicUrl || ''}
              sx={{ mb: 2 }}
              slotProps={{
                input: {
                  readOnly: true,
                  endAdornment: (
                    <InputAdornment position="end">
                      <IconButton onClick={handleCopyUrl} edge="end" aria-label="copy public url">
                        <ContentCopyIcon />
                      </IconButton>
                    </InputAdornment>
                  ),
                }
              }}
            />

            <Divider sx={{ my: 2 }} />

            <Box sx={{ textAlign: 'center' }}>
              <QrCodeIcon sx={{ fontSize: 120, color: 'primary.main', mb: 1 }} />
              <Typography variant="caption" display="block" color="text.secondary">
                {t('flowPublishDialog.qrCodeComingSoon')}
              </Typography>
            </Box>
          </>
        )}
      </DialogContent>
      <DialogActions>
        <Button onClick={handleClose}>
          {published ? t('flowPublishDialog.close') : t('flowPublishDialog.cancel')}
        </Button>
        {!published && (
          <Button
            variant="contained"
            onClick={handlePublish}
            disabled={publishing}
            startIcon={publishing ? <CircularProgress size={16} /> : <PublishIcon />}
          >
            {publishing ? t('flowPublishDialog.publishing') : t('flowPublishDialog.publishButton')}
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

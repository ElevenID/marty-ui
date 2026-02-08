/**
 * Trust Sources Step - Trust Profile Wizard
 * 
 * Define trusted issuers (DIDs, certificate authorities, etc.)
 * This step is optional and can be skipped.
 */

import { useState } from 'react';
import {
  Box,
  Typography,
  TextField,
  Button,
  List,
  ListItem,
  ListItemText,
  IconButton,
  Chip,
  Alert,
} from '@mui/material';
import AddIcon from '@mui/icons-material/Add';
import DeleteIcon from '@mui/icons-material/Delete';
import InfoIcon from '@mui/icons-material/Info';

const TrustSourcesStep = ({ data, onChange }) => {
  const [newIssuerDid, setNewIssuerDid] = useState('');

  const handleAddIssuer = () => {
    if (!newIssuerDid.trim()) return;

    const trustedIssuers = [...(data.trusted_issuers || [])];
    
    // Check for duplicates
    if (trustedIssuers.some((issuer) => issuer.did === newIssuerDid.trim())) {
      return;
    }

    trustedIssuers.push({
      did: newIssuerDid.trim(),
      name: '',
      added_at: new Date().toISOString(),
    });

    onChange({ trusted_issuers: trustedIssuers });
    setNewIssuerDid('');
  };

  const handleRemoveIssuer = (index) => {
    const trustedIssuers = [...(data.trusted_issuers || [])];
    trustedIssuers.splice(index, 1);
    onChange({ trusted_issuers: trustedIssuers });
  };

  const handleKeyPress = (e) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      handleAddIssuer();
    }
  };

  return (
    <Box>
      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1 }}>
        <Typography variant="h6">
          Trust Sources
        </Typography>
        <Chip label="Optional" size="small" color="default" variant="outlined" />
      </Box>
      <Typography color="text.secondary" paragraph>
        Define which credential issuers your organization trusts. You can skip this step and configure trust sources later.
      </Typography>

      <Alert severity="info" sx={{ mb: 3 }} icon={<InfoIcon />}>
        <Typography variant="body2" gutterBottom>
          Trust sources can include DIDs (Decentralized Identifiers), certificate authorities, or known issuer endpoints.
        </Typography>
        <Typography variant="caption" color="text.secondary">
          <strong>Skipping this step?</strong> Your profile will accept credentials from any issuer. You can add specific trust sources later to restrict which issuers are accepted.
        </Typography>
      </Alert>

      {/* Example DIDs */}
      <Box sx={{ mb: 3, p: 2, bgcolor: 'grey.50', borderRadius: 1, border: 1, borderColor: 'grey.200' }}>
        <Typography variant="caption" color="text.secondary" gutterBottom display="block">
          Example DIDs:
        </Typography>
        <Box sx={{ fontFamily: 'monospace', fontSize: '0.75rem', color: 'text.secondary' }}>
          <Box>• did:web:issuer.example.com</Box>
          <Box>• did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK</Box>
          <Box>• did:ion:EiClkZMDxPKqC9c-umQfTkR8vvZ9JPhl_xLDI9Nfk38w5A</Box>
        </Box>
      </Box>

      {/* Add Issuer DID */}
      <Box sx={{ display: 'flex', gap: 2, mb: 3 }}>
        <TextField
          fullWidth
          label="Issuer DID"
          placeholder="did:web:example.com or did:key:z6Mk..."
          value={newIssuerDid}
          onChange={(e) => setNewIssuerDid(e.target.value)}
          onKeyPress={handleKeyPress}
          helperText="Enter a DID (Decentralized Identifier) for a trusted issuer"
        />
        <Button
          variant="contained"
          startIcon={<AddIcon />}
          onClick={handleAddIssuer}
          disabled={!newIssuerDid.trim()}
          sx={{ minWidth: 120 }}
        >
          Add
        </Button>
      </Box>

      {/* Issuer List */}
      {data.trusted_issuers && data.trusted_issuers.length > 0 ? (
        <Box>
          <Typography variant="subtitle2" gutterBottom>
            Trusted Issuers ({data.trusted_issuers.length})
          </Typography>
          <List>
            {data.trusted_issuers.map((issuer, index) => (
              <ListItem
                key={index}
                secondaryAction={
                  <IconButton
                    edge="end"
                    onClick={() => handleRemoveIssuer(index)}
                    color="error"
                  >
                    <DeleteIcon />
                  </IconButton>
                }
                sx={{ bgcolor: 'background.paper', mb: 1, borderRadius: 1 }}
              >
                <ListItemText
                  primary={
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                      <Typography
                        variant="body2"
                        sx={{
                          fontFamily: 'monospace',
                          wordBreak: 'break-all',
                        }}
                      >
                        {issuer.did}
                      </Typography>
                      {issuer.name && (
                        <Chip label={issuer.name} size="small" />
                      )}
                    </Box>
                  }
                />
              </ListItem>
            ))}
          </List>
        </Box>
      ) : (
        <Box
          sx={{
            p: 4,
            textAlign: 'center',
            border: '2px dashed',
            borderColor: 'divider',
            borderRadius: 1,
          }}
        >
          <Typography color="text.secondary">
            No trusted issuers configured yet. Add DIDs above or skip this step.
          </Typography>
        </Box>
      )}

      {/* Future: Import from registry */}
      <Box sx={{ mt: 3, p: 2, bgcolor: 'action.hover', borderRadius: 1 }}>
        <Typography variant="body2" color="text.secondary">
          <strong>Coming soon:</strong> Import trusted issuers from known registries (ICAO PKD, EU Trust Lists, etc.)
        </Typography>
      </Box>
    </Box>
  );
};

export default TrustSourcesStep;

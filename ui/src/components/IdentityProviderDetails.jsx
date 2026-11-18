import { useEffect, useState } from 'react';
import { Box, Button, ListItem, ListItemIcon, ListItemText, Typography } from '@mui/material';
import SecurityIcon from '@mui/icons-material/Security';
import { getIdentityProvider } from '../services/identityProviderApi';

export default function IdentityProviderDetails() {
  const [provider, setProvider] = useState(null);
  const [failed, setFailed] = useState(false);
  const [loading, setLoading] = useState(true);
  const [attempt, setAttempt] = useState(0);

  useEffect(() => {
    const controller = new AbortController();
    let active = true;
    setLoading(true);
    setFailed(false);
    getIdentityProvider({ signal: controller.signal }).then(result => {
      if (active) setProvider(result);
    }).catch(() => {
      if (active) {
        setProvider(null);
        setFailed(true);
      }
    }).finally(() => {
      if (active) setLoading(false);
    });
    return () => {
      active = false;
      controller.abort();
    };
  }, [attempt]);

  return <>
    <ListItem>
      <ListItemIcon><SecurityIcon /></ListItemIcon>
      <ListItemText
        primary="Sign-in provider"
        secondary={provider?.provider_name || (loading ? 'Loading sign-in details…' : 'Provider details unavailable')}
      />
    </ListItem>
    {failed && <ListItem>
      <Box>
        <Typography variant="body2" color="text.secondary">
          Account settings could not be loaded. Retry to see your sign-in settings.
        </Typography>
        <Button onClick={() => setAttempt(value => value + 1)} disabled={loading}>
          Retry account settings
        </Button>
      </Box>
    </ListItem>}
    {provider && (provider.account_url || provider.recovery_url) && <ListItem>
      <Box>
        <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap', mb: 1 }}>
          {provider.account_url && <Button component="a" href={provider.account_url} rel="noreferrer">
            Manage sign-in account
          </Button>}
          {provider.recovery_url && <Button component="a" href={provider.recovery_url} rel="noreferrer">
            Account recovery
          </Button>}
        </Box>
        <Typography variant="body2" color="text.secondary">
          These settings open at {provider.provider_name}.
        </Typography>
      </Box>
    </ListItem>}
    {provider?.provider_logout_supported === false && <ListItem>
      <Typography variant="body2" color="text.secondary">
        Signing out ends your ElevenID session. Your sign-in provider may keep you signed in.
      </Typography>
    </ListItem>}
  </>;
}

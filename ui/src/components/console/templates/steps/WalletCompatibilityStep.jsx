/**
 * WalletCompatibilityStep
 *
 * Step 4 of the Credential Template Wizard.
 * Lets template authors select which wallets support this credential type,
 * and confirms the issuance protocol.
 *
 * Props:
 *   data      {object}  — wizard state (supported_wallet_ids, issuance_protocol, supported_formats)
 *   onChange  {fn}      — wizard.updateData
 */

import { useState, useEffect } from 'react';
import {
  Box,
  Typography,
  Autocomplete,
  TextField,
  Alert,
  Chip,
  Stack,
  CircularProgress,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Paper,
  Avatar,
} from '@mui/material';
import WalletIcon from '@mui/icons-material/AccountBalanceWallet';
import InfoOutlinedIcon from '@mui/icons-material/InfoOutlined';

import { listWallets } from '../../../../services/walletRegistryApi';

const PROTOCOL_OPTIONS = [
  { value: 'oid4vci', label: 'OID4VCI (OpenID for Verifiable Credential Issuance)' },
];

export default function WalletCompatibilityStep({ data, onChange }) {
  const [wallets, setWallets] = useState([]);
  const [loadingWallets, setLoadingWallets] = useState(false);
  const [walletError, setWalletError] = useState(null);

  // Derive issuance_protocol from supported_formats if not explicitly set
  const effectiveProtocol = data.issuance_protocol || 'oid4vci';

  useEffect(() => {
    let cancelled = false;
    setLoadingWallets(true);
    setWalletError(null);
    listWallets(true)
      .then((list) => {
        if (!cancelled) setWallets(list || []);
      })
      .catch((err) => {
        if (!cancelled) setWalletError('Could not load wallet registry. You can continue without selecting wallets.');
      })
      .finally(() => {
        if (!cancelled) setLoadingWallets(false);
      });
    return () => { cancelled = true; };
  }, []);

  // Selected wallet objects resolved from IDs
  const selectedWallets = wallets.filter((w) =>
    (data.supported_wallet_ids || []).includes(w.id)
  );

  const handleWalletChange = (_, newValue) => {
    onChange({ supported_wallet_ids: newValue.map((w) => w.id) });
  };

  const handleProtocolChange = (e) => {
    onChange({ issuance_protocol: e.target.value });
  };

  return (
    <Box>
      <Typography variant="h6" gutterBottom>
        Wallet Compatibility
      </Typography>
      <Typography variant="body2" color="text.secondary" paragraph>
        Select the wallets that support this credential type.
        This controls which deep-link buttons appear when admins issue to applicants.
      </Typography>

      {/* Protocol selector */}
      <FormControl fullWidth size="small" sx={{ mb: 3 }}>
        <InputLabel id="protocol-label">Issuance Protocol</InputLabel>
        <Select
          labelId="protocol-label"
          value={effectiveProtocol}
          label="Issuance Protocol"
          onChange={handleProtocolChange}
        >
          {PROTOCOL_OPTIONS.map((opt) => (
            <MenuItem key={opt.value} value={opt.value}>
              {opt.label}
            </MenuItem>
          ))}
        </Select>
      </FormControl>

      {/* Wallet multi-select */}
      {loadingWallets ? (
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, py: 2 }}>
          <CircularProgress size={18} />
          <Typography variant="body2" color="text.secondary">Loading wallet registry…</Typography>
        </Box>
      ) : (
        <>
          {walletError && (
            <Alert severity="warning" sx={{ mb: 2 }} icon={<InfoOutlinedIcon />}>
              {walletError}
            </Alert>
          )}

          <Autocomplete
            multiple
            options={wallets}
            getOptionLabel={(w) => w.name}
            isOptionEqualToValue={(a, b) => a.id === b.id}
            value={selectedWallets}
            onChange={handleWalletChange}
            renderTags={(value, getTagProps) =>
              value.map((wallet, index) => (
                <Chip
                  key={wallet.id}
                  label={wallet.name}
                  size="small"
                  avatar={
                    wallet.logo_url ? (
                      <Avatar src={wallet.logo_url} sx={{ width: 18, height: 18 }} />
                    ) : undefined
                  }
                  icon={!wallet.logo_url ? <WalletIcon sx={{ fontSize: 16 }} /> : undefined}
                  {...getTagProps({ index })}
                />
              ))
            }
            renderOption={(props, wallet) => {
              const supportedPlatforms = wallet.supported_platforms || wallet.platforms || [];

              return (
                <Box component="li" {...props} sx={{ display: 'flex', alignItems: 'center', gap: 1.5, py: 1 }}>
                  {wallet.logo_url ? (
                    <Box
                      component="img"
                      src={wallet.logo_url}
                      alt={wallet.name}
                      sx={{ width: 24, height: 24, objectFit: 'contain' }}
                    />
                  ) : (
                    <WalletIcon fontSize="small" color="action" />
                  )}
                  <Box>
                    <Typography variant="body2">{wallet.name}</Typography>
                    {supportedPlatforms.length > 0 && (
                      <Typography variant="caption" color="text.secondary">
                        {supportedPlatforms.join(' · ')}
                      </Typography>
                    )}
                  </Box>
                </Box>
              );
            }}
            renderInput={(params) => (
              <TextField
                {...params}
                label="Supported Wallets"
                placeholder="Search wallet registry…"
                size="small"
                helperText="Select all wallets that are compatible with this credential's format and protocol."
              />
            )}
            sx={{ mb: 2 }}
          />

          {selectedWallets.length === 0 && (
            <Alert severity="warning" icon={<InfoOutlinedIcon />}>
              No wallets selected. The issuance screen will fall back to a generic QR code without
              wallet-specific deep links. It is recommended to select at least one wallet.
            </Alert>
          )}

          {selectedWallets.length > 0 && (
            <Paper variant="outlined" sx={{ p: 2 }}>
              <Typography variant="caption" color="text.secondary" display="block" gutterBottom>
                Preview — Wallet deep-link buttons shown to applicants:
              </Typography>
              <Stack spacing={1}>
                {selectedWallets.map((w) => {
                  const supportedPlatforms = w.supported_platforms || w.platforms || [];

                  return (
                    <Box
                      key={w.id}
                      sx={{ display: 'flex', alignItems: 'center', gap: 1.5 }}
                    >
                      {w.logo_url ? (
                        <Box
                          component="img"
                          src={w.logo_url}
                          alt={w.name}
                          sx={{ width: 20, height: 20, objectFit: 'contain' }}
                        />
                      ) : (
                        <WalletIcon fontSize="small" color="action" />
                      )}
                      <Typography variant="body2">
                        Add to {w.name}
                      </Typography>
                      <Stack direction="row" spacing={0.5} sx={{ ml: 'auto' }}>
                        {supportedPlatforms.map((p) => (
                          <Chip key={p} label={p} size="small" variant="outlined" sx={{ fontSize: '0.65rem', height: 18 }} />
                        ))}
                      </Stack>
                    </Box>
                  );
                })}
              </Stack>
            </Paper>
          )}
        </>
      )}
    </Box>
  );
}

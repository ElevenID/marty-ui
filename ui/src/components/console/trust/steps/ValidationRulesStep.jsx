/**
 * Validation Rules Step - Trust Profile Wizard
 * 
 * Configure cryptographic and validation requirements.
 * This step is optional with sensible defaults.
 */

import { useEffect, useState } from 'react';
import {
  Box,
  Typography,
  FormControl,
  FormGroup,
  FormControlLabel,
  Checkbox,
  InputLabel,
  Select,
  MenuItem,
  FormHelperText,
  Alert,
  Divider,
  Button,
  Chip,
  Collapse,
  Autocomplete,
  Avatar,
  Paper,
  Stack,
  TextField,
} from '@mui/material';
import SecurityIcon from '@mui/icons-material/Security';
import RestartAltIcon from '@mui/icons-material/RestartAlt';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import ExpandLessIcon from '@mui/icons-material/ExpandLess';
import WalletIcon from '@mui/icons-material/AccountBalanceWallet';
import InfoOutlinedIcon from '@mui/icons-material/InfoOutlined';
import { useTranslation } from 'react-i18next';

import { listWallets } from '../../../../services/walletRegistryApi';
import {
  TRUST_PROFILE_ALLOWED_ALGORITHMS as ALGORITHMS,
  getAllowedAlgorithmsForFramework,
  isFrameworkAlgorithmSelectionLocked,
  normalizeTrustProfileAllowedAlgorithms,
} from '../trustProfileFormatCatalog';

const KEY_SIZES = [
  { value: 2048, label: '2048 bits' },
  { value: 3072, label: '3072 bits' },
  { value: 4096, label: '4096 bits' },
];

const REVOCATION_MODES = [
  { value: 'HARD_FAIL', label: 'Hard fail if revocation cannot be checked' },
  { value: 'SOFT_FAIL', label: 'Allow temporary degradation if revocation is unavailable' },
  { value: 'OFF', label: 'Skip revocation checks' },
];

const CLOCK_SKEW_OPTIONS = [
  { value: 60, label: '1 minute' },
  { value: 300, label: '5 minutes' },
  { value: 900, label: '15 minutes' },
];

const FRESHNESS_WINDOW_OPTIONS = [
  { value: 3600, label: '1 hour' },
  { value: 21600, label: '6 hours' },
  { value: 86400, label: '24 hours' },
  { value: 604800, label: '7 days' },
];

function haveSameValues(left = [], right = []) {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

const ValidationRulesStep = ({ data, onChange }) => {
  const { t } = useTranslation('console');
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [wallets, setWallets] = useState([]);
  const [loadingWallets, setLoadingWallets] = useState(false);
  const [walletError, setWalletError] = useState(null);
  const walletLoadErrorMessage = t(
    'wizards.trustProfile.validationRulesStep.walletCompatibility.loadError',
    { defaultValue: 'Could not load the wallet registry. You can keep configuring the trust profile and add wallet targeting later.' },
  );

  const frameworkType = data.framework_type || 'custom';
  const algorithmSelectionLocked = isFrameworkAlgorithmSelectionLocked(frameworkType);
  const defaultRules = {
    allowed_algorithms: getAllowedAlgorithmsForFramework(frameworkType),
    allow_self_signed: false,
    min_key_size: 2048,
    require_key_usage: true,
  };
  const rules = {
    ...defaultRules,
    ...(data.validation_rules || {}),
    allowed_algorithms: getAllowedAlgorithmsForFramework(
      frameworkType,
      data.validation_rules?.allowed_algorithms,
    ),
  };
  const revocationPolicy = data.revocation_policy || { check_mode: 'HARD_FAIL' };
  const timePolicy = {
    clock_skew_seconds: 300,
    require_freshness: false,
    freshness_window_seconds: 86400,
    ...(data.time_policy || {}),
  };
  const selectedWallets = wallets.filter((wallet) =>
    (data.supported_wallet_ids || []).includes(wallet.id)
  );

  useEffect(() => {
    let cancelled = false;
    setLoadingWallets(true);
    setWalletError(null);

    listWallets(true)
      .then((walletList) => {
        if (!cancelled) {
          setWallets(Array.isArray(walletList) ? walletList : []);
        }
      })
      .catch(() => {
        if (!cancelled) {
          setWalletError(walletLoadErrorMessage);
        }
      })
      .finally(() => {
        if (!cancelled) {
          setLoadingWallets(false);
        }
      });

    return () => {
      cancelled = true;
    };
  }, [walletLoadErrorMessage]);

  useEffect(() => {
    if (!algorithmSelectionLocked) {
      return;
    }

    const currentAlgorithms = normalizeTrustProfileAllowedAlgorithms(data.validation_rules?.allowed_algorithms);
    const frameworkAlgorithms = getAllowedAlgorithmsForFramework(frameworkType);

    if (haveSameValues(currentAlgorithms, frameworkAlgorithms)) {
      return;
    }

    onChange({
      validation_rules: {
        ...defaultRules,
        ...(data.validation_rules || {}),
        allowed_algorithms: frameworkAlgorithms,
      },
    });
  }, [algorithmSelectionLocked, data.validation_rules, defaultRules, frameworkType, onChange]);

  const handleAlgorithmToggle = (algorithm) => {
    if (algorithmSelectionLocked) {
      return;
    }

    const current = rules.allowed_algorithms || [];
    const updated = current.includes(algorithm)
      ? current.filter((a) => a !== algorithm)
      : [...current, algorithm];
    onChange({ validation_rules: { ...rules, allowed_algorithms: updated } });
  };

  const handleRuleChange = (key, value) => {
    onChange({ validation_rules: { ...rules, [key]: value } });
  };

  const handleResetDefaults = () => {
    onChange({ validation_rules: defaultRules });
  };

  const handleWalletChange = (_, newValue) => {
    onChange({ supported_wallet_ids: newValue.map((wallet) => wallet.id) });
  };

  const handleIssuanceProtocolChange = (event) => {
    onChange({ issuance_protocol: event.target.value });
  };

  const handleRevocationChange = (event) => {
    onChange({
      revocation_policy: {
        ...revocationPolicy,
        check_mode: event.target.value,
      },
    });
  };

  const handleTimePolicyChange = (updates) => {
    onChange({
      time_policy: {
        ...timePolicy,
        ...updates,
      },
    });
  };

  return (
    <Box>
      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1 }}>
        <SecurityIcon />
        <Typography variant="h6">
          {t('wizards.trustProfile.validationRulesStep.title')}
        </Typography>
        <Chip
          label={t('wizards.trustProfile.validationRulesStep.optionalChip')}
          size="small"
          color="default"
          variant="outlined"
        />
      </Box>
      <Typography color="text.secondary" paragraph>
        {t('wizards.trustProfile.validationRulesStep.description')}
      </Typography>

      {algorithmSelectionLocked ? (
        <Alert severity="info" sx={{ mb: 3 }}>
          <Typography variant="body2" gutterBottom>
            <strong>
              {t('wizards.trustProfile.validationRulesStep.frameworkLockedAlert.title', {
                framework: t(`wizards.trustProfile.frameworkLabels.${frameworkType}`),
              })}
            </strong>
          </Typography>
          <Typography variant="caption" color="text.secondary">
            {t('wizards.trustProfile.validationRulesStep.frameworkLockedAlert.description')}
          </Typography>
        </Alert>
      ) : (
        <Alert severity="success" sx={{ mb: 3 }}>
          <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <Box>
              <Typography variant="body2" gutterBottom>
                <strong>{t('wizards.trustProfile.validationRulesStep.defaultsAlert.title')}</strong>
              </Typography>
              <Typography variant="caption" color="text.secondary">
                {t('wizards.trustProfile.validationRulesStep.defaultsAlert.description')}
              </Typography>
            </Box>
            <Button
              size="small"
              startIcon={<RestartAltIcon />}
              onClick={handleResetDefaults}
            >
              {t('wizards.trustProfile.validationRulesStep.resetDefaults')}
            </Button>
          </Box>
        </Alert>
      )}

      {/* Allowed Algorithms */}
      <FormControl component="fieldset" fullWidth sx={{ mb: 3 }}>
        <Typography variant="subtitle2" gutterBottom>
          {t('wizards.trustProfile.validationRulesStep.allowedAlgorithms.title')}
        </Typography>
        <FormHelperText sx={{ mt: 0, mb: 1 }}>
          {algorithmSelectionLocked
            ? t('wizards.trustProfile.validationRulesStep.allowedAlgorithms.helperLocked', {
                defaultValue: 'This framework restricts signing algorithms. Choose Custom to edit them.',
              })
            : t('wizards.trustProfile.validationRulesStep.allowedAlgorithms.helper')}
        </FormHelperText>
        <FormGroup>
          <Box sx={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 1 }}>
            {ALGORITHMS.map((alg) => (
              <FormControlLabel
                key={alg.value}
                control={
                  <Checkbox
                    checked={(rules.allowed_algorithms || []).includes(alg.value)}
                    onChange={() => handleAlgorithmToggle(alg.value)}
                    disabled={algorithmSelectionLocked}
                    slotProps={{ input: { 'data-testid': `wizard.trustProfile.algorithm.${alg.value}` } }}
                  />
                }
                label={alg.label}
              />
            ))}
          </Box>
        </FormGroup>
      </FormControl>

      <Divider sx={{ my: 3 }} />

      <Box sx={{ mb: 3 }}>
        <Typography variant="subtitle2" gutterBottom>
          {t(
            'wizards.trustProfile.validationRulesStep.walletCompatibility.title',
            { defaultValue: 'Wallet compatibility' },
          )}
        </Typography>
        <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
          {t(
            'wizards.trustProfile.validationRulesStep.walletCompatibility.description',
            { defaultValue: 'Select the wallets this trust profile is intended to support so downstream flows can surface the right handoff options.' },
          )}
        </Typography>

        <FormControl fullWidth size="small" sx={{ mb: 2 }}>
          <InputLabel id="trust-profile-issuance-protocol-label">
            {t(
              'wizards.trustProfile.validationRulesStep.walletCompatibility.protocolLabel',
              { defaultValue: 'Issuance protocol' },
            )}
          </InputLabel>
          <Select
            labelId="trust-profile-issuance-protocol-label"
            value={data.issuance_protocol || 'oid4vci'}
            onChange={handleIssuanceProtocolChange}
            label={t(
              'wizards.trustProfile.validationRulesStep.walletCompatibility.protocolLabel',
              { defaultValue: 'Issuance protocol' },
            )}
            data-testid="wizard.trustProfile.issuanceProtocol"
          >
            <MenuItem value="oid4vci">OID4VCI</MenuItem>
          </Select>
          <FormHelperText>
            {t(
              'wizards.trustProfile.validationRulesStep.walletCompatibility.protocolHelper',
              { defaultValue: 'The protocol used when this trust profile participates in wallet handoff flows.' },
            )}
          </FormHelperText>
        </FormControl>

        {loadingWallets ? (
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, py: 1 }}>
            <SecurityIcon fontSize="small" color="action" />
            <Typography variant="body2" color="text.secondary">
              {t(
                'wizards.trustProfile.validationRulesStep.walletCompatibility.loading',
                { defaultValue: 'Loading wallet registry…' },
              )}
            </Typography>
          </Box>
        ) : (
          <>
            {walletError && (
              <Alert severity="warning" icon={<InfoOutlinedIcon />} sx={{ mb: 2 }}>
                {walletError}
              </Alert>
            )}

            <Autocomplete
              multiple
              options={wallets}
              getOptionLabel={(wallet) => wallet.name}
              isOptionEqualToValue={(left, right) => left.id === right.id}
              value={selectedWallets}
              onChange={handleWalletChange}
              renderValue={(value, getItemProps) =>
                value.map((wallet, index) => {
                  const { key, ...itemProps } = getItemProps({ index });

                  return (
                    <Chip
                      key={key}
                      label={wallet.name}
                      size="small"
                      avatar={wallet.logo_url ? <Avatar src={wallet.logo_url} sx={{ width: 18, height: 18 }} /> : undefined}
                      icon={!wallet.logo_url ? <WalletIcon sx={{ fontSize: 16 }} /> : undefined}
                      {...itemProps}
                    />
                  );
                })
              }
              renderOption={(props, wallet) => {
                const { key, ...optionProps } = props;
                const platforms = wallet.supported_platforms || wallet.platforms || [];

                return (
                  <Box key={key} component="li" {...optionProps} sx={{ display: 'flex', alignItems: 'center', gap: 1.5, py: 1 }}>
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
                      {platforms.length > 0 && (
                        <Typography variant="caption" color="text.secondary">
                          {platforms.join(' · ')}
                        </Typography>
                      )}
                    </Box>
                  </Box>
                );
              }}
              renderInput={(params) => (
                <TextField
                  {...params}
                  label={t(
                    'wizards.trustProfile.validationRulesStep.walletCompatibility.walletsLabel',
                    { defaultValue: 'Supported wallets' },
                  )}
                  placeholder={t(
                    'wizards.trustProfile.validationRulesStep.walletCompatibility.walletsPlaceholder',
                    { defaultValue: 'Search wallet registry…' },
                  )}
                  helperText={t(
                    'wizards.trustProfile.validationRulesStep.walletCompatibility.walletsHelper',
                    { defaultValue: 'Selecting wallets lets issuance and handoff experiences prioritize the right apps.' },
                  )}
                  size="small"
                />
              )}
              sx={{ mb: 2 }}
            />

            {selectedWallets.length === 0 && (
              <Alert severity="info" icon={<InfoOutlinedIcon />}>
                {t(
                  'wizards.trustProfile.validationRulesStep.walletCompatibility.noWalletsSelected',
                  { defaultValue: 'No specific wallets selected. Compatible flows will fall back to generic wallet handoff behavior.' },
                )}
              </Alert>
            )}

            {selectedWallets.length > 0 && (
              <Paper variant="outlined" sx={{ p: 2, mt: 2 }}>
                <Typography variant="caption" color="text.secondary" display="block" gutterBottom>
                  {t(
                    'wizards.trustProfile.validationRulesStep.walletCompatibility.previewLabel',
                    { defaultValue: 'Selected wallet targets' },
                  )}
                </Typography>
                <Stack spacing={1}>
                  {selectedWallets.map((wallet) => {
                    const platforms = wallet.supported_platforms || wallet.platforms || [];

                    return (
                      <Box key={wallet.id} sx={{ display: 'flex', alignItems: 'center', gap: 1.5 }}>
                        {wallet.logo_url ? (
                          <Box
                            component="img"
                            src={wallet.logo_url}
                            alt={wallet.name}
                            sx={{ width: 20, height: 20, objectFit: 'contain' }}
                          />
                        ) : (
                          <WalletIcon fontSize="small" color="action" />
                        )}
                        <Typography variant="body2">{wallet.name}</Typography>
                        <Stack direction="row" spacing={0.5} sx={{ ml: 'auto' }}>
                          {platforms.map((platform) => (
                            <Chip key={platform} label={platform} size="small" variant="outlined" sx={{ fontSize: '0.65rem', height: 18 }} />
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

      {/* Advanced Options Toggle */}
      <Box sx={{ mt: 3 }}>
        <Button
          fullWidth
          variant="outlined"
          onClick={() => setShowAdvanced(!showAdvanced)}
          endIcon={showAdvanced ? <ExpandLessIcon /> : <ExpandMoreIcon />}
        >
          {t('wizards.trustProfile.validationRulesStep.advanced.toggle', {
            action: showAdvanced
              ? t('wizards.trustProfile.validationRulesStep.advanced.hide')
              : t('wizards.trustProfile.validationRulesStep.advanced.show'),
          })}
        </Button>

        <Collapse in={showAdvanced}>
          <Box sx={{ mt: 2 }}>
            <Divider sx={{ my: 3 }} />

            {/* Key Size Constraints */}
            <FormControl fullWidth sx={{ mb: 3 }}>
              <InputLabel>{t('wizards.trustProfile.validationRulesStep.keySize.label')}</InputLabel>
              <Select
                value={rules.min_key_size || 2048}
                onChange={(e) => handleRuleChange('min_key_size', e.target.value)}
                label={t('wizards.trustProfile.validationRulesStep.keySize.label')}
              >
                {KEY_SIZES.map((size) => (
                  <MenuItem key={size.value} value={size.value}>
                    {size.label}
                  </MenuItem>
                ))}
              </Select>
              <FormHelperText>
                {t('wizards.trustProfile.validationRulesStep.keySize.helper')}
              </FormHelperText>
            </FormControl>

            <Divider sx={{ my: 3 }} />

            <FormControl fullWidth sx={{ mb: 3 }}>
              <InputLabel>{t(
                'wizards.trustProfile.validationRulesStep.revocation.label',
                { defaultValue: 'Revocation strategy' },
              )}</InputLabel>
              <Select
                value={revocationPolicy.check_mode || 'HARD_FAIL'}
                onChange={handleRevocationChange}
                label={t(
                  'wizards.trustProfile.validationRulesStep.revocation.label',
                  { defaultValue: 'Revocation strategy' },
                )}
                data-testid="wizard.trustProfile.revocationStrategy"
              >
                {REVOCATION_MODES.map((mode) => (
                  <MenuItem key={mode.value} value={mode.value}>
                    {mode.label}
                  </MenuItem>
                ))}
              </Select>
              <FormHelperText>
                {t(
                  'wizards.trustProfile.validationRulesStep.revocation.helper',
                  { defaultValue: 'Define how strictly verification should react when revocation information is missing or stale.' },
                )}
              </FormHelperText>
            </FormControl>

            <FormControl fullWidth sx={{ mb: 3 }}>
              <InputLabel>{t(
                'wizards.trustProfile.validationRulesStep.timePolicy.clockSkewLabel',
                { defaultValue: 'Clock skew tolerance' },
              )}</InputLabel>
              <Select
                value={timePolicy.clock_skew_seconds ?? 300}
                onChange={(event) => handleTimePolicyChange({ clock_skew_seconds: Number(event.target.value) })}
                label={t(
                  'wizards.trustProfile.validationRulesStep.timePolicy.clockSkewLabel',
                  { defaultValue: 'Clock skew tolerance' },
                )}
                data-testid="wizard.trustProfile.clockSkew"
              >
                {CLOCK_SKEW_OPTIONS.map((option) => (
                  <MenuItem key={option.value} value={option.value}>
                    {option.label}
                  </MenuItem>
                ))}
              </Select>
              <FormHelperText>
                {t(
                  'wizards.trustProfile.validationRulesStep.timePolicy.clockSkewHelper',
                  { defaultValue: 'Allow bounded time drift between issuers, wallets, and verifier systems.' },
                )}
              </FormHelperText>
            </FormControl>

            {/* Additional Options */}
            <Typography variant="subtitle2" gutterBottom>
              {t('wizards.trustProfile.validationRulesStep.additionalSecurity.title')}
            </Typography>
            
            <FormGroup>
              <FormControlLabel
                control={
                  <Checkbox
                    checked={rules.allow_self_signed || false}
                    onChange={(e) => handleRuleChange('allow_self_signed', e.target.checked)}
                  />
                }
                label={t('wizards.trustProfile.validationRulesStep.additionalSecurity.allowSelfSigned.label')}
              />
              <FormHelperText sx={{ ml: 4, mt: -1, mb: 2 }}>
                {t('wizards.trustProfile.validationRulesStep.additionalSecurity.allowSelfSigned.helper')}
              </FormHelperText>

              <FormControlLabel
                control={
                  <Checkbox
                    checked={rules.require_key_usage !== false}
                    onChange={(e) => handleRuleChange('require_key_usage', e.target.checked)}
                  />
                }
                label={t('wizards.trustProfile.validationRulesStep.additionalSecurity.requireKeyUsage.label')}
              />
              <FormHelperText sx={{ ml: 4, mt: -1 }}>
                {t('wizards.trustProfile.validationRulesStep.additionalSecurity.requireKeyUsage.helper')}
              </FormHelperText>

              <FormControlLabel
                control={
                  <Checkbox
                    checked={timePolicy.require_freshness || false}
                    onChange={(event) => handleTimePolicyChange({ require_freshness: event.target.checked })}
                    data-testid="wizard.trustProfile.requireFreshness"
                  />
                }
                label={t(
                  'wizards.trustProfile.validationRulesStep.timePolicy.requireFreshnessLabel',
                  { defaultValue: 'Require credential freshness' },
                )}
              />
              <FormHelperText sx={{ ml: 4, mt: -1, mb: 2 }}>
                {t(
                  'wizards.trustProfile.validationRulesStep.timePolicy.requireFreshnessHelper',
                  { defaultValue: 'Reject credentials that are valid but older than your freshness window.' },
                )}
              </FormHelperText>

              <FormControl fullWidth sx={{ ml: 4 }} disabled={!timePolicy.require_freshness}>
                <InputLabel>{t(
                  'wizards.trustProfile.validationRulesStep.timePolicy.freshnessWindowLabel',
                  { defaultValue: 'Freshness window' },
                )}</InputLabel>
                <Select
                  value={timePolicy.freshness_window_seconds ?? 86400}
                  onChange={(event) => handleTimePolicyChange({ freshness_window_seconds: Number(event.target.value) })}
                  label={t(
                    'wizards.trustProfile.validationRulesStep.timePolicy.freshnessWindowLabel',
                    { defaultValue: 'Freshness window' },
                  )}
                  data-testid="wizard.trustProfile.freshnessWindow"
                >
                  {FRESHNESS_WINDOW_OPTIONS.map((option) => (
                    <MenuItem key={option.value} value={option.value}>
                      {option.label}
                    </MenuItem>
                  ))}
                </Select>
                <FormHelperText>
                  {t(
                    'wizards.trustProfile.validationRulesStep.timePolicy.freshnessWindowHelper',
                    { defaultValue: 'How recent a credential must be when freshness is enforced.' },
                  )}
                </FormHelperText>
              </FormControl>
            </FormGroup>
          </Box>
        </Collapse>
      </Box>
    </Box>
  );
};

export default ValidationRulesStep;

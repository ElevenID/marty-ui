/**
 * IssuingSection
 *
 * Inline section rendered on the ApplicationReviewPage for approved
 * applications.  Lets the reviewer pick an issuance protocol, generate
 * an invite, and display the resulting QR code (or whatever the
 * protocol's InviteDisplay component renders) — all without opening a
 * modal.
 *
 * Protocol flexibility:
 *   The section reads from the issuance-protocol registry
 *   (config/issuanceProtocols.js).  When only one protocol is
 *   registered the selector is hidden and the single protocol is
 *   auto-selected.  Adding a new protocol requires zero changes here.
 *
 * Props:
 *   applicationId      {string}  — ID of the application
 *   applicationStatus  {string}  — current status ('approved', etc.)
 */

import { useState, useCallback } from 'react';
import {
  Box,
  Button,
  Collapse,
  FormControl,
  InputLabel,
  MenuItem,
  Paper,
  Select,
  Stack,
  Typography,
  CircularProgress,
  Alert,
} from '@mui/material';
import SendIcon from '@mui/icons-material/Send';
import QrCode2Icon from '@mui/icons-material/QrCode2';

import { getAvailableProtocols } from '../../../config/issuanceProtocols';

// ── Section chrome (matches SectionCard pattern from ApplicationReviewPage) ─

function SectionCard({ title, icon, children }) {
  return (
    <Paper variant="outlined" sx={{ mb: 3 }}>
      <Box
        sx={{
          display: 'flex',
          alignItems: 'center',
          gap: 1,
          px: 2.5,
          py: 1.5,
          borderBottom: '1px solid',
          borderColor: 'divider',
        }}
      >
        {icon}
        <Typography variant="subtitle1" fontWeight="medium">
          {title}
        </Typography>
      </Box>
      <Box sx={{ p: 2.5 }}>{children}</Box>
    </Paper>
  );
}

// ── Main component ──────────────────────────────────────────────────────────

export default function IssuingSection({ applicationId, applicationStatus }) {
  const protocols = getAvailableProtocols();
  const singleProtocol = protocols.length === 1;

  const [selectedProtocolId, setSelectedProtocolId] = useState(
    singleProtocol ? protocols[0].id : '',
  );
  const [offerData, setOfferData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [expanded, setExpanded] = useState(false);

  const selectedProtocol = protocols.find((p) => p.id === selectedProtocolId);

  // ── Generate offer ──────────────────────────────────────────────────────

  const handleGenerateOffer = useCallback(async () => {
    if (!selectedProtocol) return;
    setLoading(true);
    setError(null);
    try {
      const data = await selectedProtocol.generateOffer(applicationId);
      if (!data?.offer_url) {
        setError('Credential offer URI was not returned. The issuance service may be unavailable. Please try again.');
        return;
      }
      setOfferData(data);
      setExpanded(true);
    } catch (err) {
      setError(err.message || 'Failed to generate issuance invite');
    } finally {
      setLoading(false);
    }
  }, [selectedProtocol, applicationId]);

  // ── Regenerate (e.g. after expiry) ──────────────────────────────────────

  const handleRegenerate = useCallback(async () => {
    if (!selectedProtocol) return;
    setLoading(true);
    setError(null);
    try {
      const data = await selectedProtocol.generateOffer(applicationId);
      setOfferData(data);
    } catch (err) {
      setError(err.message || 'Failed to regenerate issuance invite');
    } finally {
      setLoading(false);
    }
  }, [selectedProtocol, applicationId]);

  // Only render for approved or issued applications
  if (applicationStatus !== 'approved' && applicationStatus !== 'issued') return null;

  // ── Render ─────────────────────────────────────────────────────────────

  const InviteDisplay = selectedProtocol?.InviteDisplay;

  return (
    <SectionCard title="Credential Issuance" icon={<SendIcon color="action" />}>
      <Stack spacing={2}>
        {/* Protocol selector — hidden when there is only one protocol */}
        {!singleProtocol && (
          <FormControl size="small" sx={{ maxWidth: 320 }}>
            <InputLabel id="issuance-protocol-label">Issuance Protocol</InputLabel>
            <Select
              labelId="issuance-protocol-label"
              value={selectedProtocolId}
              label="Issuance Protocol"
              onChange={(e) => {
                setSelectedProtocolId(e.target.value);
                // Reset invite when switching protocols
                setOfferData(null);
                setExpanded(false);
                setError(null);
              }}
            >
              {protocols.map((p) => (
                <MenuItem key={p.id} value={p.id}>
                  <Stack>
                    <Typography variant="body2">{p.label}</Typography>
                    {p.description && (
                      <Typography variant="caption" color="text.secondary">
                        {p.description}
                      </Typography>
                    )}
                  </Stack>
                </MenuItem>
              ))}
            </Select>
          </FormControl>
        )}

        {/* Description line (shown when a protocol is selected) */}
        {selectedProtocol && !expanded && (
          <Typography variant="body2" color="text.secondary">
            Generate a {selectedProtocol.label} credential invite for the applicant.
          </Typography>
        )}

        {/* Action button */}
        {selectedProtocol && !expanded && (
          <Box>
            <Button
              variant="contained"
              startIcon={
                loading ? (
                  <CircularProgress size={16} color="inherit" />
                ) : (
                  <QrCode2Icon />
                )
              }
              onClick={handleGenerateOffer}
              disabled={loading}
            >
              {loading ? 'Generating…' : `Display ${selectedProtocol.label} Invite`}
            </Button>
          </Box>
        )}

        {/* Error feedback */}
        {error && (
          <Alert severity="error" onClose={() => setError(null)}>
            {error}
          </Alert>
        )}

        {/* Inline invite display (QR code, etc.) — revealed after generation */}
        <Collapse in={expanded} unmountOnExit>
          {InviteDisplay && (
            <InviteDisplay
              offerData={offerData}
              onRegenerate={handleRegenerate}
              loading={loading}
            />
          )}
        </Collapse>
      </Stack>
    </SectionCard>
  );
}

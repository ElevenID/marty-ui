import {
  Alert,
  Avatar,
  Box,
  Chip,
  Divider,
  Paper,
  Stack,
  Typography,
} from '@mui/material';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import ErrorIcon from '@mui/icons-material/Error';
import HelpOutlineIcon from '@mui/icons-material/HelpOutlined';
import LinkIcon from '@mui/icons-material/Link';
import WorkspacePremiumIcon from '@mui/icons-material/WorkspacePremium';

function firstPresent(...values) {
  return values.find((value) => {
    if (value === undefined || value === null) return false;
    if (typeof value === 'string') return value.trim() !== '';
    return true;
  });
}

function asObject(value) {
  return value && typeof value === 'object' && !Array.isArray(value) ? value : {};
}

function asArray(value) {
  return Array.isArray(value) ? value : [];
}

function getPath(source, path) {
  return path.split('.').reduce((current, key) => {
    if (current === undefined || current === null) return undefined;
    return current[key];
  }, source);
}

function firstPath(source, paths) {
  return firstPresent(...paths.map((path) => getPath(source, path)));
}

function toDisplayValue(value) {
  if (value === true) return 'Yes';
  if (value === false) return 'No';
  if (value === undefined || value === null || value === '') return 'Not disclosed';
  if (typeof value === 'object') return JSON.stringify(value);
  return String(value);
}

function titleize(value) {
  if (!value) return '';
  return String(value)
    .replace(/[_-]/g, ' ')
    .replace(/\b\w/g, (char) => char.toUpperCase());
}

function statusValue(value) {
  return String(value || '').toLowerCase();
}

function nestedClaims(claims = {}) {
  const safeClaims = asObject(claims);
  const subject = asObject(safeClaims.credentialSubject);
  const vcSubject = asObject(safeClaims.vc?.credentialSubject);
  return {
    ...safeClaims,
    ...subject,
    ...vcSubject,
  };
}

function credentialResultValue(credentialResults, key) {
  for (const result of credentialResults) {
    if (result && result[key] !== undefined && result[key] !== null) return result[key];
  }
  return undefined;
}

function claimResultsFromMipMessage(session = {}) {
  const payload = session.context_data?.mip_messages?.verification_result?.payload
    || session.mip_messages?.verification_result?.payload
    || {};
  return asArray(payload.claim_results).reduce((acc, claim) => {
    if (claim.claim_name) {
      acc[claim.claim_name] = claim.present ? 'Presented' : 'Not presented';
    }
    return acc;
  }, {});
}

export function extractVerificationSummary(session = {}) {
  const rawResult = asObject(session.result);
  const nestedResult = asObject(rawResult.result);
  const result = Object.keys(nestedResult).length ? nestedResult : rawResult;
  const contextResult = asObject(session.context_data?.result);
  const contextClaims = asObject(session.context_data?.verified_claims);
  const claims = nestedClaims({
    ...claimResultsFromMipMessage(session),
    ...contextClaims,
    ...asObject(result.verified_claims),
    ...asObject(session.verified_claims),
  });
  const credentialResults = [
    ...asArray(session.credential_results),
    ...asArray(result.credential_results),
    ...asArray(contextResult.credential_results),
    ...asArray(session.context_data?.credential_results),
  ];
  const firstCredential = credentialResults[0] || {};
  const achievement = asObject(firstPresent(claims.achievement, claims.badge, claims.open_badge));
  const issuer = asObject(firstPresent(claims.issuer, claims.issuerProfile));
  const image = firstPresent(
    firstPath(achievement, ['image.id', 'image.uri']),
    achievement.image,
    firstPath(claims, ['image.id', 'image.uri', 'logo.uri', 'display.logo.uri']),
    claims.badge_image_url,
    claims.badge_image,
    claims.logo_url,
  );
  const canvasProvenance = asObject(firstPresent(
    claims.canvas_provenance,
    claims.canvas_mirror,
    firstPath(claims, ['provenance.canvas', 'provenance.canvas_credentials']),
    firstPath(result, ['canvas_provenance', 'canvas_mirror']),
  ));
  const canvasCredentialId = firstPresent(
    canvasProvenance.external_credential_id,
    canvasProvenance.canvas_credential_id,
    claims.canvas_credential_id,
    claims.canvasCredentialsId,
  );

  const passed = firstPresent(
    result.passed,
    rawResult.passed,
    ['passed', 'completed'].includes(statusValue(session.status)) ? true : undefined,
    session.result_code ? statusValue(session.result_code) === 'passed' : undefined,
    rawResult.evaluation_result ? statusValue(rawResult.evaluation_result) === 'passed' : undefined,
    rawResult.result ? statusValue(rawResult.result) === 'passed' : undefined,
  );
  const trustValidated = firstPresent(
    result.trust_validated,
    rawResult.trust_validated,
    rawResult.decision ? rawResult.decision === 'allow' : undefined,
    session.decision ? session.decision === 'allow' : undefined,
    credentialResultValue(credentialResults, 'trust_check_passed'),
  );
  const revocationChecked = firstPresent(
    result.revocation_checked,
    rawResult.revocation_checked,
    credentialResultValue(credentialResults, 'revocation_checked'),
    credentialResultValue(credentialResults, 'revocation_validated'),
    credentialResultValue(credentialResults, 'revocation_status_checked'),
  );
  const signatureValid = firstPresent(
    credentialResultValue(credentialResults, 'signature_valid'),
    rawResult.signature_valid,
  );

  return {
    passed: Boolean(passed),
    badgeName: firstPresent(
      achievement.name,
      claims.achievement_name,
      claims.badge_name,
      claims.name,
      firstCredential.credential_name,
      firstCredential.credential_template_name,
      'Presented Credential',
    ),
    description: firstPresent(achievement.description, claims.description, firstCredential.description),
    image,
    issuerDid: firstPresent(issuer.id, claims.issuer_did, firstCredential.issuer_did, rawResult.issuer_did),
    issuerName: firstPresent(issuer.name, claims.issuer_name, firstCredential.issuer_name),
    trustValidated,
    revocationChecked,
    signatureValid,
    canvasCredentialId,
    canvasAccount: firstPresent(canvasProvenance.canvas_account_id, claims.canvas_account_id),
    canvasDeliveryId: firstPresent(canvasProvenance.delivery_record_id, claims.canvas_delivery_id),
    claims,
    claimsSatisfied: asArray(result.claims_satisfied || rawResult.claims_satisfied),
    claimsMissing: asArray(result.claims_missing || rawResult.claims_missing),
    failureReason: firstPresent(result.failure_reason, rawResult.failure_reason, rawResult.decision_reason, session.error),
  };
}

function CheckLine({ label, value }) {
  const known = value !== undefined && value !== null;
  const ok = Boolean(value);
  return (
    <Stack direction="row" spacing={1} alignItems="center">
      {known ? (
        ok ? <CheckCircleIcon color="success" fontSize="small" /> : <ErrorIcon color="error" fontSize="small" />
      ) : (
        <HelpOutlineIcon color="disabled" fontSize="small" />
      )}
      <Typography variant="body2">{label}</Typography>
      <Chip
        size="small"
        label={known ? (ok ? 'Passed' : 'Failed') : 'Not reported'}
        color={known ? (ok ? 'success' : 'error') : 'default'}
        variant="outlined"
        sx={{ ml: 'auto' }}
      />
    </Stack>
  );
}

function ClaimList({ claims, claimsSatisfied, claimsMissing }) {
  const entries = Object.entries(claims || {})
    .filter(([key, value]) => (
      value !== undefined
      && value !== null
      && !['achievement', 'badge', 'open_badge', 'issuer', 'vc', 'credentialSubject'].includes(key)
      && typeof value !== 'object'
    ))
    .slice(0, 8);

  const names = entries.length
    ? entries
    : claimsSatisfied.map((name) => [name, 'Satisfied']);

  if (!names.length && !claimsMissing.length) return null;

  return (
    <Box>
      <Typography variant="subtitle2" sx={{ fontWeight: 800, mb: 1 }}>
        Presented claims
      </Typography>
      <Box sx={{ display: 'grid', gap: 1, gridTemplateColumns: { xs: '1fr', md: 'repeat(2, minmax(0, 1fr))' } }}>
        {names.map(([key, value]) => (
          <Box key={key}>
            <Typography variant="caption" color="text.secondary">
              {titleize(key)}
            </Typography>
            <Typography variant="body2" sx={{ overflowWrap: 'anywhere' }}>
              {toDisplayValue(value)}
            </Typography>
          </Box>
        ))}
      </Box>
      {claimsMissing.length > 0 ? (
        <Alert severity="warning" sx={{ mt: 1 }}>
          Missing claims: {claimsMissing.join(', ')}
        </Alert>
      ) : null}
    </Box>
  );
}

function VerificationResultSummary({ session }) {
  const summary = extractVerificationSummary(session);
  const hasCanvasMirror = Boolean(summary.canvasCredentialId || summary.canvasAccount || summary.canvasDeliveryId);

  return (
    <Paper variant="outlined" sx={{ p: 2, borderRadius: 1 }} data-testid="verification-result-summary">
      <Stack spacing={2}>
        <Stack direction={{ xs: 'column', sm: 'row' }} spacing={2} alignItems={{ xs: 'flex-start', sm: 'center' }}>
          <Avatar
            src={typeof summary.image === 'string' ? summary.image : undefined}
            alt={summary.badgeName}
            variant="rounded"
            sx={{ width: 64, height: 64, bgcolor: 'action.hover', color: 'primary.main' }}
          >
            <WorkspacePremiumIcon />
          </Avatar>
          <Box sx={{ flex: 1, minWidth: 0 }}>
            <Stack direction="row" spacing={1} alignItems="center" flexWrap="wrap" useFlexGap>
              <Typography variant="h6" sx={{ fontWeight: 800, overflowWrap: 'anywhere' }}>
                {summary.badgeName}
              </Typography>
              <Chip size="small" label="Open Badge" variant="outlined" />
              <Chip
                size="small"
                label={summary.passed ? 'Verified' : 'Not verified'}
                color={summary.passed ? 'success' : 'error'}
              />
            </Stack>
            {summary.description ? (
              <Typography variant="body2" color="text.secondary">
                {summary.description}
              </Typography>
            ) : null}
            <Typography variant="caption" color="text.secondary" sx={{ overflowWrap: 'anywhere', display: 'block', mt: 0.5 }}>
              {summary.issuerName ? `${summary.issuerName} - ` : ''}{summary.issuerDid || 'Issuer not disclosed'}
            </Typography>
          </Box>
        </Stack>

        {summary.failureReason && !summary.passed ? (
          <Alert severity="error">{summary.failureReason}</Alert>
        ) : null}

        <Divider />

        <Stack spacing={1}>
          <Typography variant="subtitle2" sx={{ fontWeight: 800 }}>
            Verification checks
          </Typography>
          <CheckLine label="Trust profile accepted the issuer" value={summary.trustValidated} />
          <CheckLine label="Revocation/status was checked" value={summary.revocationChecked} />
          <CheckLine label="Credential signature was valid" value={summary.signatureValid} />
        </Stack>

        <ClaimList
          claims={summary.claims}
          claimsSatisfied={summary.claimsSatisfied}
          claimsMissing={summary.claimsMissing}
        />

        {hasCanvasMirror ? (
          <>
            <Divider />
            <Box data-testid="verification-canvas-mirror-result">
              <Stack direction="row" spacing={1} alignItems="center" sx={{ mb: 1 }}>
                <LinkIcon color="primary" fontSize="small" />
                <Typography variant="subtitle2" sx={{ fontWeight: 800 }}>
                  Canvas Credentials mirror
                </Typography>
              </Stack>
              <Box sx={{ display: 'grid', gap: 1, gridTemplateColumns: { xs: '1fr', md: 'repeat(3, minmax(0, 1fr))' } }}>
                <Box>
                  <Typography variant="caption" color="text.secondary">Canvas credential</Typography>
                  <Typography variant="body2" sx={{ overflowWrap: 'anywhere' }}>
                    {summary.canvasCredentialId || 'Not referenced'}
                  </Typography>
                </Box>
                <Box>
                  <Typography variant="caption" color="text.secondary">Canvas account</Typography>
                  <Typography variant="body2" sx={{ overflowWrap: 'anywhere' }}>
                    {summary.canvasAccount || 'Not referenced'}
                  </Typography>
                </Box>
                <Box>
                  <Typography variant="caption" color="text.secondary">Delivery record</Typography>
                  <Typography variant="body2" sx={{ overflowWrap: 'anywhere' }}>
                    {summary.canvasDeliveryId || 'Not referenced'}
                  </Typography>
                </Box>
              </Box>
            </Box>
          </>
        ) : null}
      </Stack>
    </Paper>
  );
}

export default VerificationResultSummary;

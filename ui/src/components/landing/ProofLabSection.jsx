import {
  Box,
  Button,
  Chip,
  Grid,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  Paper,
  Typography,
} from '@mui/material';
import ArrowForwardIcon from '@mui/icons-material/ArrowForward';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import CancelIcon from '@mui/icons-material/Cancel';

import { INTERACTIVE_PROOF_LAB } from '../../data/marketingContent';
import { Section, SectionHeading } from './LandingSection';

export default function ProofLabSection({
  t,
  isMobile,
  activeScenario,
  onScenarioChange,
  onRun,
  status,
  result,
  requestPreview,
  presentationData,
}) {
  const proofTimeline = result?.checks?.length ? result.checks : activeScenario.eventLog;

  return (
    <Section>
      <SectionHeading
        subtitle={t('landingPage.proofLab.subtitle', INTERACTIVE_PROOF_LAB.subtitle)}
        divider
      >
        {t('landingPage.proofLab.title', INTERACTIVE_PROOF_LAB.title)}
      </SectionHeading>

      <Paper
        elevation={0}
        sx={{
          p: { xs: 2.5, md: 4 },
          borderRadius: 3,
          background: 'linear-gradient(135deg, #071427 0%, #10233d 100%)',
          color: 'common.white',
        }}
      >
        <Grid container spacing={3} alignItems="stretch">
          <Grid item xs={12} md={4}>
            <Chip
              label={t('landingPage.proofLab.eyebrow', INTERACTIVE_PROOF_LAB.eyebrow)}
              color="info"
              variant="outlined"
              sx={{ mb: 2, fontWeight: 700, borderColor: 'rgba(255,255,255,0.22)', color: 'common.white' }}
            />
            <Typography variant="h5" fontWeight={800} sx={{ mb: 1 }}>
              {activeScenario.title}
            </Typography>
            <Typography variant="body2" sx={{ color: 'rgba(255,255,255,0.78)', mb: 2.5 }}>
              {activeScenario.summary}
            </Typography>
            <Typography variant="caption" sx={{ color: 'rgba(255,255,255,0.62)', textTransform: 'uppercase', letterSpacing: 1.1 }}>
              Active verifier channel
            </Typography>
            <Typography variant="body1" fontWeight={700} sx={{ mt: 0.75, mb: 2.5 }}>
              {activeScenario.channel}
            </Typography>

            <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1, mb: 2.5 }}>
              {INTERACTIVE_PROOF_LAB.scenarios.map((scenario) => (
                <Button
                  key={scenario.id}
                  size="small"
                  fullWidth={isMobile}
                  variant={activeScenario.id === scenario.id ? 'contained' : 'outlined'}
                  onClick={() => onScenarioChange(scenario.id)}
                  sx={{
                    justifyContent: 'flex-start',
                    borderColor: 'rgba(255,255,255,0.2)',
                    color: 'common.white',
                    bgcolor: activeScenario.id === scenario.id ? 'rgba(255,255,255,0.16)' : 'transparent',
                    '&:hover': {
                      borderColor: 'rgba(255,255,255,0.32)',
                      bgcolor: 'rgba(255,255,255,0.12)',
                    },
                  }}
                >
                  {scenario.label}
                </Button>
              ))}
            </Box>

            <Paper
              elevation={0}
              sx={{
                p: 2.5,
                bgcolor: 'rgba(255,255,255,0.06)',
                borderRadius: 3,
                border: '1px solid rgba(255,255,255,0.1)',
              }}
            >
              <Typography variant="caption" sx={{ color: 'rgba(255,255,255,0.62)', textTransform: 'uppercase', letterSpacing: 1.1 }}>
                Verifier request
              </Typography>
              <Chip
                label={activeScenario.requestPath}
                size="small"
                sx={{ mt: 1.25, mb: 1.5, bgcolor: 'rgba(255,255,255,0.1)', color: 'common.white' }}
              />
              <Typography variant="body2" sx={{ color: 'rgba(255,255,255,0.82)' }}>
                {activeScenario.requestSummary}
              </Typography>
            </Paper>

            <Box sx={{ display: 'flex', gap: 1.5, flexWrap: 'wrap', mt: 2.5 }}>
              <Button
                variant="contained"
                onClick={onRun}
                disabled={status === 'running'}
                data-testid="proof-lab-run-button"
              >
                {status === 'running' ? 'Running verification...' : 'Run scenario verification'}
              </Button>

              <Button
                variant="outlined"
                component="a"
                href={`/blog/${activeScenario.slug}`}
                endIcon={<ArrowForwardIcon />}
                sx={{ borderColor: 'rgba(255,255,255,0.3)', color: 'common.white' }}
              >
                {activeScenario.cta}
              </Button>
            </Box>
          </Grid>

          <Grid item xs={12} md={8}>
            <Grid container spacing={2}>
              <Grid item xs={12} sm={6}>
                <Paper elevation={0} sx={{ p: 2.5, height: '100%', bgcolor: 'rgba(255,255,255,0.06)', borderRadius: 3, border: '1px solid rgba(255,255,255,0.1)' }}>
                  <Typography variant="overline" sx={{ color: 'rgba(255,255,255,0.62)', letterSpacing: 1.1 }}>
                    Holder sees
                  </Typography>
                  <Typography variant="body1" fontWeight={700} sx={{ mt: 0.75, mb: 1.5 }}>
                    {activeScenario.holderSummary}
                  </Typography>
                  <Typography variant="caption" sx={{ color: 'rgba(255,255,255,0.62)', textTransform: 'uppercase', letterSpacing: 1.1 }}>
                    Proof disclosed
                  </Typography>
                  <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1, mt: 1.25 }}>
                    {activeScenario.disclosed.map((item) => (
                      <Chip key={item} label={item} size="small" sx={{ bgcolor: 'rgba(255,255,255,0.1)', color: 'common.white' }} />
                    ))}
                  </Box>
                </Paper>
              </Grid>

              <Grid item xs={12} sm={6}>
                <Paper elevation={0} sx={{ p: 2.5, height: '100%', bgcolor: 'rgba(255,255,255,0.06)', borderRadius: 3, border: '1px solid rgba(255,255,255,0.1)' }}>
                  <Typography variant="overline" sx={{ color: 'rgba(255,255,255,0.62)', letterSpacing: 1.1 }}>
                    Verifier evaluates
                  </Typography>
                  <List disablePadding dense sx={{ mt: 1 }}>
                    {activeScenario.verifierChecks.map((check) => (
                      <ListItem key={check.label} sx={{ px: 0, py: 0.75, alignItems: 'flex-start' }}>
                        <ListItemIcon sx={{ minWidth: 30, mt: 0.2 }}>
                          {check.status === 'pass' ? (
                            <CheckCircleIcon fontSize="small" sx={{ color: 'success.light' }} />
                          ) : (
                            <CancelIcon fontSize="small" sx={{ color: 'error.light' }} />
                          )}
                        </ListItemIcon>
                        <ListItemText
                          primary={check.label}
                          secondary={check.detail}
                          primaryTypographyProps={{ fontWeight: 700, color: 'common.white' }}
                          secondaryTypographyProps={{ color: 'rgba(255,255,255,0.72)' }}
                        />
                      </ListItem>
                    ))}
                  </List>
                </Paper>
              </Grid>

              <Grid item xs={12} sm={6}>
                <Paper elevation={0} sx={{ p: 2.5, height: '100%', bgcolor: 'rgba(255,255,255,0.06)', borderRadius: 3, border: '1px solid rgba(255,255,255,0.1)' }}>
                  <Typography variant="overline" sx={{ color: 'rgba(255,255,255,0.62)', letterSpacing: 1.1 }}>
                    Request preview
                  </Typography>
                  <Box
                    component="pre"
                    data-testid="proof-lab-request-preview"
                    sx={{
                      m: 0,
                      mt: 1.25,
                      overflowX: 'auto',
                      whiteSpace: 'pre-wrap',
                      wordBreak: 'break-word',
                      fontFamily: 'Consolas, Menlo, Monaco, monospace',
                      fontSize: '0.78rem',
                      lineHeight: 1.55,
                      color: 'common.white',
                    }}
                  >
                    {JSON.stringify(requestPreview, null, 2)}
                  </Box>
                </Paper>
              </Grid>

              <Grid item xs={12} sm={6}>
                <Paper elevation={0} sx={{ p: 2.5, height: '100%', bgcolor: 'rgba(255,255,255,0.06)', borderRadius: 3, border: '1px solid rgba(255,255,255,0.1)' }}>
                  <Typography variant="overline" sx={{ color: 'rgba(255,255,255,0.62)', letterSpacing: 1.1 }}>
                    Proof preview
                  </Typography>
                  <Box
                    component="pre"
                    data-testid="proof-lab-presentation-preview"
                    sx={{
                      m: 0,
                      mt: 1.25,
                      overflowX: 'auto',
                      maxHeight: 220,
                      whiteSpace: 'pre-wrap',
                      wordBreak: 'break-word',
                      fontFamily: 'Consolas, Menlo, Monaco, monospace',
                      fontSize: '0.78rem',
                      lineHeight: 1.55,
                      color: 'common.white',
                    }}
                  >
                    {presentationData}
                  </Box>
                </Paper>
              </Grid>

              <Grid item xs={12}>
                <Paper
                  elevation={0}
                  sx={{
                    p: 2.5,
                    borderRadius: 3,
                    bgcolor: 'rgba(255,255,255,0.06)',
                    border: '1px solid rgba(255,255,255,0.1)',
                  }}
                >
                  <Box sx={{ display: 'flex', justifyContent: 'space-between', gap: 2, flexWrap: 'wrap', mb: 2 }}>
                    <Box>
                      <Typography variant="overline" sx={{ color: 'rgba(255,255,255,0.62)', letterSpacing: 1.1 }}>
                        Decision log
                      </Typography>
                      <Typography variant="body1" fontWeight={700} sx={{ mt: 0.75 }}>
                        {activeScenario.outcome}
                      </Typography>
                    </Box>
                    {result ? (
                      <Chip
                        label={result.verified ? 'VERIFIED' : 'FAILED'}
                        color={result.verified ? 'success' : 'error'}
                        variant="filled"
                        data-testid="proof-lab-result-chip"
                      />
                    ) : (
                      <Chip label={activeScenario.proof} color="success" variant="outlined" />
                    )}
                  </Box>
                  {result && (
                    <Box
                      sx={{
                        mb: 2,
                        p: 2,
                        borderRadius: 2,
                        bgcolor: 'rgba(255,255,255,0.05)',
                        border: '1px solid rgba(255,255,255,0.1)',
                      }}
                    >
                      <Typography variant="caption" sx={{ color: 'rgba(255,255,255,0.62)', textTransform: 'uppercase', letterSpacing: 1.1 }}>
                        Verification response
                      </Typography>
                      <Typography variant="body2" sx={{ mt: 1, color: 'rgba(255,255,255,0.82)' }}>
                        {result.presentation_summary || activeScenario.outcome}
                      </Typography>
                      <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1, mt: 1.5 }}>
                        {result.issuer && <Chip label={`Issuer: ${result.issuer}`} size="small" />}
                        <Chip label={`Checks: ${result.checks?.length || 0}`} size="small" />
                        <Chip label={`Claims: ${Object.keys(result.claims || {}).length}`} size="small" />
                      </Box>
                    </Box>
                  )}
                  <Grid container spacing={1.5}>
                    {proofTimeline.map((item, index) => {
                      const itemKey = typeof item === 'string' ? item : `${item.check_name}-${index}`;

                      return (
                        <Grid item xs={12} md={4} key={itemKey}>
                          <Box sx={{ p: 2, height: '100%', borderRadius: 2, bgcolor: 'rgba(255,255,255,0.05)' }}>
                            <Chip label={index + 1} size="small" color="info" sx={{ mb: 1 }} />
                            <Typography variant="body2" sx={{ color: 'rgba(255,255,255,0.82)' }}>
                              {typeof item === 'string' ? item : `${item.check_name}: ${item.details}`}
                            </Typography>
                          </Box>
                        </Grid>
                      );
                    })}
                  </Grid>
                </Paper>
              </Grid>
            </Grid>
          </Grid>
        </Grid>
      </Paper>
    </Section>
  );
}
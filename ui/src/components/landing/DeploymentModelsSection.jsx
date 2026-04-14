import { Link } from 'react-router-dom';
import {
  Box,
  Button,
  Card,
  CardActionArea,
  CardContent,
  Chip,
  Grid,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  Paper,
  Typography,
} from '@mui/material';
import ApiIcon from '@mui/icons-material/Api';
import BusinessIcon from '@mui/icons-material/Business';
import SettingsInputAntennaIcon from '@mui/icons-material/SettingsInputAntenna';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import ArrowForwardIcon from '@mui/icons-material/ArrowForward';

import { DEPLOYMENT_MODELS } from '../../data/marketingContent';
import { DeploymentModelDiagram } from '../diagrams';
import { Section, SectionHeading } from './LandingSection';

const DEPLOYMENT_MODE_META = {
  'saas-verification': {
    icon: <ApiIcon sx={{ fontSize: 34, color: 'primary.main' }} />,
    color: 'primary',
  },
  'self-hosted-infrastructure': {
    icon: <BusinessIcon sx={{ fontSize: 34, color: 'secondary.main' }} />,
    color: 'secondary',
  },
  'offline-checkpoint-runtime': {
    icon: <SettingsInputAntennaIcon sx={{ fontSize: 34, color: 'warning.main' }} />,
    color: 'warning',
  },
};

export default function DeploymentModelsSection({ t, onSelectMode }) {
  return (
    <Section>
      <SectionHeading
        subtitle={t('landingPage.deploymentModels.subtitle', DEPLOYMENT_MODELS.subtitle)}
        divider
      >
        {t('landingPage.deploymentModels.title', DEPLOYMENT_MODELS.title)}
      </SectionHeading>

      <Grid container spacing={3} alignItems="stretch" sx={{ mb: 4 }}>
        <Grid item xs={12} lg={7}>
          <Paper
            elevation={0}
            sx={{
              p: { xs: 2.5, md: 3.5 },
              height: '100%',
              borderRadius: 4,
              background: 'linear-gradient(180deg, #071427 0%, #10233d 100%)',
              color: 'common.white',
            }}
          >
            <DeploymentModelDiagram />
          </Paper>
        </Grid>

        <Grid item xs={12} lg={5}>
          <Paper
            elevation={0}
            sx={{
              p: { xs: 2.5, md: 3 },
              height: '100%',
              borderRadius: 4,
              bgcolor: 'grey.50',
              border: '1px solid',
              borderColor: 'grey.200',
            }}
          >
            <Chip label="Architecture fit" color="info" variant="outlined" sx={{ fontWeight: 700, mb: 2 }} />
            <Typography variant="h5" fontWeight={800} sx={{ mb: 1.5 }}>
              {t('landingPage.deploymentModels.panelTitle', 'Where the platform sits in production.')}
            </Typography>
            <Typography variant="body2" color="text.secondary" sx={{ mb: 2.5 }}>
              {t(
                'landingPage.deploymentModels.panelSubtitle',
                'Show buyers the runtime choices early so deployment and integration questions are answered before they need a sales call.'
              )}
            </Typography>

            <Box sx={{ display: 'grid', gap: 1.5 }}>
              {DEPLOYMENT_MODELS.questions.map((item) => (
                <Box
                  key={item.question}
                  sx={{
                    p: 2,
                    borderRadius: 3,
                    bgcolor: 'common.white',
                    border: '1px solid',
                    borderColor: 'grey.200',
                  }}
                >
                  <Typography variant="subtitle2" fontWeight={800} sx={{ mb: 0.5 }}>
                    {item.question}
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    {item.answer}
                  </Typography>
                </Box>
              ))}
            </Box>

            <Box
              sx={{
                mt: 2.5,
                p: 2.25,
                borderRadius: 3,
                bgcolor: '#0f2038',
                color: 'common.white',
              }}
            >
              <Typography variant="overline" sx={{ color: 'rgba(255,255,255,0.66)', letterSpacing: 1.2 }}>
                {DEPLOYMENT_MODELS.example.title}
              </Typography>
              <Typography
                variant="body2"
                sx={{
                  mt: 1,
                  fontFamily: 'Consolas, Menlo, Monaco, monospace',
                  color: 'rgba(255,255,255,0.9)',
                }}
              >
                {DEPLOYMENT_MODELS.example.flow.join(' -> ')}
              </Typography>
              <Typography variant="body2" sx={{ mt: 1.25, color: 'rgba(255,255,255,0.82)' }}>
                {DEPLOYMENT_MODELS.example.summary}
              </Typography>
            </Box>
          </Paper>
        </Grid>
      </Grid>

      <Grid container spacing={3}>
        {DEPLOYMENT_MODELS.modes.map((mode) => {
          const meta = DEPLOYMENT_MODE_META[mode.id] || DEPLOYMENT_MODE_META['saas-verification'];

          return (
            <Grid item xs={12} md={4} key={mode.id}>
              <Card
                elevation={2}
                sx={{
                  height: '100%',
                  display: 'flex',
                  flexDirection: 'column',
                  transition: 'all 0.2s ease',
                  '&:hover': { transform: 'translateY(-4px)', boxShadow: 6 },
                }}
              >
                <CardActionArea component={Link} to={mode.path} onClick={() => onSelectMode(mode)} sx={{ height: '100%' }}>
                  <CardContent sx={{ p: 3, height: '100%', display: 'flex', flexDirection: 'column' }}>
                    <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: 1.5, mb: 2 }}>
                      <Box
                        sx={{
                          width: 50,
                          height: 50,
                          borderRadius: 2,
                          display: 'flex',
                          alignItems: 'center',
                          justifyContent: 'center',
                          bgcolor: `${meta.color}.50`,
                        }}
                      >
                        {meta.icon}
                      </Box>
                      <Chip label={mode.badge} size="small" color={meta.color} variant="outlined" sx={{ fontWeight: 700 }} />
                    </Box>
                    <Typography variant="h6" fontWeight={800} gutterBottom>
                      {mode.title}
                    </Typography>
                    <Typography variant="body2" color="text.secondary" sx={{ mb: 2.5 }}>
                      {mode.summary}
                    </Typography>
                    <Typography variant="caption" sx={{ color: 'text.secondary', textTransform: 'uppercase', letterSpacing: 1.1 }}>
                      Features
                    </Typography>
                    <List dense sx={{ mb: 2 }}>
                      {mode.features.map((feature) => (
                        <ListItem key={feature} sx={{ px: 0, py: 0.35, alignItems: 'flex-start' }}>
                          <ListItemIcon sx={{ minWidth: 28, mt: 0.15 }}>
                            <CheckCircleIcon fontSize="small" color={meta.color} />
                          </ListItemIcon>
                          <ListItemText primary={feature} primaryTypographyProps={{ variant: 'body2' }} />
                        </ListItem>
                      ))}
                    </List>
                    <Typography variant="caption" sx={{ color: 'text.secondary', textTransform: 'uppercase', letterSpacing: 1.1 }}>
                      Best for
                    </Typography>
                    <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1, mt: 1.25, mb: 2.5 }}>
                      {mode.bestFor.map((audience) => (
                        <Chip key={audience} label={audience} size="small" />
                      ))}
                    </Box>
                    <Button
                      variant="text"
                      component="span"
                      endIcon={<ArrowForwardIcon />}
                      sx={{ mt: 'auto', alignSelf: 'flex-start', px: 0, fontWeight: 700 }}
                    >
                      {mode.cta}
                    </Button>
                  </CardContent>
                </CardActionArea>
              </Card>
            </Grid>
          );
        })}
      </Grid>
    </Section>
  );
}
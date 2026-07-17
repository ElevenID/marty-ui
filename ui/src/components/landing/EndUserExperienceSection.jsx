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

import { END_USER_EXPERIENCES } from '../../data/marketingContent';
import { Section, SectionHeading } from './LandingSection';

export default function EndUserExperienceSection({ t, activeExperience, onSelectExperience }) {
  return (
    <Section bgcolor="grey.50">
      <SectionHeading
        subtitle={t('landingPage.endUserExperience.subtitle', END_USER_EXPERIENCES.subtitle)}
        divider
      >
        {t('landingPage.endUserExperience.title', END_USER_EXPERIENCES.title)}
      </SectionHeading>
      <Box sx={{ display: 'flex', justifyContent: 'center', flexWrap: 'wrap', gap: 1, mb: 4 }}>
        {END_USER_EXPERIENCES.journeys.map((journey) => (
          <Button
            key={journey.id}
            size="small"
            variant={activeExperience.id === journey.id ? 'contained' : 'outlined'}
            onClick={() => onSelectExperience(journey.id)}
          >
            {journey.label}
          </Button>
        ))}
      </Box>
      <Grid container spacing={4} alignItems="stretch">
        <Grid item xs={12} md={5}>
          <Paper elevation={2} sx={{ p: 3, height: '100%', borderRadius: 3 }}>
            <Chip
              label={`${activeExperience.persona} - ${activeExperience.environment}`}
              color="primary"
              variant="outlined"
              sx={{ mb: 2, fontWeight: 600 }}
            />
            <Typography variant="h5" fontWeight={800} sx={{ mb: 1.5 }}>
              {activeExperience.title}
            </Typography>
            <Typography variant="body2" color="text.secondary" sx={{ mb: 2.5 }}>
              {activeExperience.summary}
            </Typography>
            <List disablePadding>
              {activeExperience.steps.map((step, index) => (
                <ListItem key={step.label} sx={{ px: 0, alignItems: 'flex-start', py: 1 }}>
                  <ListItemIcon sx={{ minWidth: 42, mt: 0.25 }}>
                    <Chip label={index + 1} size="small" color="primary" />
                  </ListItemIcon>
                  <ListItemText
                    primary={step.label}
                    secondary={step.description}
                    slotProps={{
                      primary: { fontWeight: 700 },
                      secondary: { color: 'text.secondary' }
                    }} />
                </ListItem>
              ))}
            </List>
          </Paper>
        </Grid>

        <Grid item xs={12} md={7}>
          <Grid container spacing={2}>
            <Grid item xs={12} sm={6}>
              <Paper elevation={1} sx={{ p: 2.5, height: '100%', borderRadius: 3 }}>
                <Typography variant="overline" sx={{ color: 'text.secondary', letterSpacing: 1.1 }}>
                  Holder experience
                </Typography>
                <Typography variant="body1" fontWeight={700} sx={{ mt: 0.75, mb: 1.5 }}>
                  {activeExperience.holderView}
                </Typography>
                <Typography variant="caption" sx={{ color: 'text.secondary', textTransform: 'uppercase', letterSpacing: 1.1 }}>
                  Shared proof
                </Typography>
                <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1, mt: 1.25 }}>
                  {activeExperience.disclosed.map((item) => (
                    <Chip key={item} label={item} size="small" />
                  ))}
                </Box>
              </Paper>
            </Grid>

            <Grid item xs={12} sm={6}>
              <Paper elevation={1} sx={{ p: 2.5, height: '100%', borderRadius: 3 }}>
                <Typography variant="overline" sx={{ color: 'text.secondary', letterSpacing: 1.1 }}>
                  Verifier experience
                </Typography>
                <Typography variant="body1" fontWeight={700} sx={{ mt: 0.75, mb: 1.5 }}>
                  {activeExperience.verifierView}
                </Typography>
                <Typography variant="caption" sx={{ color: 'text.secondary', textTransform: 'uppercase', letterSpacing: 1.1 }}>
                  Governed checks
                </Typography>
                <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1, mt: 1.25 }}>
                  {activeExperience.verifierChecks.map((item) => (
                    <Chip key={item} label={item} size="small" variant="outlined" />
                  ))}
                </Box>
              </Paper>
            </Grid>

            <Grid item xs={12}>
              <Paper
                elevation={1}
                sx={{
                  p: 2.5,
                  borderRadius: 3,
                  background: 'linear-gradient(135deg, rgba(25,118,210,0.08) 0%, rgba(25,118,210,0.02) 100%)',
                }}
              >
                <Typography variant="overline" sx={{ color: 'text.secondary', letterSpacing: 1.1 }}>
                  Outcome
                </Typography>
                <Typography variant="body1" fontWeight={700} sx={{ mt: 0.75, mb: 1.5 }}>
                  {activeExperience.outcome}
                </Typography>
                <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1 }}>
                  {activeExperience.benefits.map((item) => (
                    <Chip key={item} label={item} size="small" color="success" variant="outlined" />
                  ))}
                </Box>
              </Paper>
            </Grid>
          </Grid>
        </Grid>
      </Grid>
    </Section>
  );
}
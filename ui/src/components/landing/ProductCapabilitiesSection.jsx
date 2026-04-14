import { Box, Button, Card, CardContent, Chip, Grid, Typography } from '@mui/material';
import FlightTakeoffIcon from '@mui/icons-material/FlightTakeoff';
import ArrowForwardIcon from '@mui/icons-material/ArrowForward';
import ApiIcon from '@mui/icons-material/Api';
import PhoneIphoneIcon from '@mui/icons-material/PhoneIphone';
import SettingsInputAntennaIcon from '@mui/icons-material/SettingsInputAntenna';

import { PRODUCTS } from '../../data/marketingContent';
import { Section, SectionHeading } from './LandingSection';

const PRODUCT_ICONS = {
  'verification-api': <ApiIcon sx={{ fontSize: 36, color: 'primary.main' }} />,
  'issuance-api': <FlightTakeoffIcon sx={{ fontSize: 36, color: 'secondary.main' }} />,
  kiosk: <SettingsInputAntennaIcon sx={{ fontSize: 36, color: 'warning.main' }} />,
  authenticator: <PhoneIphoneIcon sx={{ fontSize: 36, color: 'info.main' }} />,
};

export default function ProductCapabilitiesSection({ t }) {
  return (
    <Section>
      <SectionHeading
        subtitle={t('landingPage.products.description', 'A complete platform-from issuance to verification and governance.')}
        divider
      >
        {t('landingPage.products.title', 'Products & Capabilities')}
      </SectionHeading>

      <Grid container spacing={3}>
        {PRODUCTS.slice(0, 4).map((product) => (
          <Grid item xs={12} sm={6} md={3} key={product.id}>
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
              <CardContent sx={{ flexGrow: 1, textAlign: 'center' }}>
                <Box sx={{ mb: 1 }}>{PRODUCT_ICONS[product.id]}</Box>
                <Typography variant="h6" fontWeight={700} gutterBottom>
                  {product.name}
                </Typography>
                <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                  {product.tagline}
                </Typography>
                <Box sx={{ mt: 1 }}>
                  {product.deployment.slice(0, 2).map((deploy) => (
                    <Chip
                      key={deploy}
                      label={deploy}
                      size="small"
                      variant="outlined"
                      sx={{ mr: 0.5, mb: 0.5 }}
                    />
                  ))}
                </Box>
              </CardContent>
              <Box sx={{ p: 2, pt: 0, textAlign: 'center' }}>
                <Button
                  size="small"
                  fullWidth
                  variant="text"
                  component="a"
                  href="/product"
                  endIcon={<ArrowForwardIcon fontSize="small" />}
                  sx={{ '&:hover': { bgcolor: 'primary.50' } }}
                >
                  {t('landingPage.products.viewDetails', 'View Details')}
                </Button>
              </Box>
            </Card>
          </Grid>
        ))}
      </Grid>

      <Box sx={{ textAlign: 'center', mt: 4 }}>
        <Button
          variant="outlined"
          size="large"
          component="a"
          href="/product"
          endIcon={<ArrowForwardIcon />}
          sx={{ transition: 'all 0.2s ease', '&:hover': { transform: 'translateY(-2px)' } }}
        >
          {t('landingPage.products.viewAll', 'View All Products')}
        </Button>
      </Box>
    </Section>
  );
}
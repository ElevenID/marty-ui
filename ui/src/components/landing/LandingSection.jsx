import { Box, Divider, Typography } from '@mui/material';

export function Section({ children, bgcolor, sx, ...rest }) {
  return (
    <Box
      sx={{
        py: { xs: 6, md: 10 },
        px: { xs: 2, md: 0 },
        bgcolor: bgcolor || 'transparent',
        ...sx,
      }}
      {...rest}
    >
      {children}
    </Box>
  );
}

export function SectionHeading({ children, subtitle, divider, sx }) {
  return (
    <Box sx={{ textAlign: 'center', mb: 5, ...sx }}>
      {divider && <Divider sx={{ mb: 3, maxWidth: 80, mx: 'auto', borderWidth: 2, borderColor: 'primary.main' }} />}
      <Typography variant="h4" component="h2" fontWeight={800} gutterBottom sx={{ fontSize: { xs: '1.75rem', md: '2.25rem' } }}>
        {children}
      </Typography>
      {subtitle && (
        <Typography variant="body1" color="text.secondary" sx={{ maxWidth: 700, mx: 'auto' }}>
          {subtitle}
        </Typography>
      )}
    </Box>
  );
}
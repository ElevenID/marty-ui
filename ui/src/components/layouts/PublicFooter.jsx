import { publicEntryHref } from '../../application/routing/publicEntry';
import { Box, Divider, Link as MuiLink, Stack, Typography } from '@mui/material';
import { Link as RouterLink } from 'react-router';
import { IS_SELFHOST_UI, SHOW_PUBLIC_DEMOS } from '@ui-public-config';
import { isWebSectionEnabled } from '../../utils/runtimeConfig';

const footerLinks = [
  { label: 'Privacy Policy', to: '/privacy-policy', testId: 'public-footer-privacy-link' },
  { label: 'Terms of Service', to: '/terms-of-service', testId: 'public-footer-terms-link' },
  { label: 'Security', to: '/security', testId: 'public-footer-security-link' },
  { label: 'Demos', to: '/demos', testId: 'public-footer-demos-link' },
  { label: 'Resources', to: '/resources', testId: 'public-footer-resources-link' },
];

function PublicFooter() {
  if (IS_SELFHOST_UI || !isWebSectionEnabled('public')) return null;

  return (
    <Box component="footer" data-testid="public-footer" sx={{ mt: 6, pb: 4 }}>
      <Divider sx={{ mb: 3 }} />
      <Stack
        direction={{ xs: 'column', md: 'row' }}
        spacing={2}
        sx={{
          alignItems: { xs: 'flex-start', md: 'center' },
          justifyContent: 'space-between',
        }}
      >
        <Box>
          <Typography variant="subtitle2" fontWeight={700} color="text.primary">
            ElevenID LLC
          </Typography>
          <Typography variant="body2" color="text.secondary">
            Public site information, legal terms, and support contacts for identity-provider sign-in.
          </Typography>
        </Box>

        <Stack
          component="nav"
          aria-label="Public site footer links"
          direction="row"
          spacing={2}
          useFlexGap
          sx={{
            width: '100%',
            minWidth: 0,
            flexWrap: 'wrap',
            justifyContent: { xs: 'flex-start', md: 'flex-end' },
          }}
        >
          {footerLinks.filter((link) => SHOW_PUBLIC_DEMOS || link.to !== '/demos').map((link) => (
            <MuiLink
              key={link.to}
              component={RouterLink}
              to={publicEntryHref(link.to)}
              underline="hover"
              color="text.secondary"
              data-testid={link.testId}
              sx={{ fontWeight: 600 }}
            >
              {link.label}
            </MuiLink>
          ))}
          <MuiLink
            href="mailto:sales@elevenidllc.com"
            underline="hover"
            color="text.secondary"
            data-testid="public-footer-contact-link"
            sx={{ fontWeight: 600 }}
          >
            Contact
          </MuiLink>
        </Stack>
      </Stack>
    </Box>
  );
}

export default PublicFooter;

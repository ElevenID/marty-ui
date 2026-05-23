import PropTypes from 'prop-types';
import {
  Box,
  Breadcrumbs,
  Button,
  Divider,
  Link as MuiLink,
  Paper,
  Stack,
  Typography,
} from '@mui/material';
import { Link as RouterLink } from 'react-router-dom';
import { SEOHead } from '../seo';
import { breadcrumbListSchema } from '../seo/structuredData';

const SITE_URL = 'https://elevenidllc.com';
const EFFECTIVE_DATE = 'May 13, 2026';

function LegalPageLayout({ title, description, canonicalPath, eyebrow, children }) {
  const canonicalUrl = `${SITE_URL}${canonicalPath}`;

  return (
    <Box>
      <SEOHead
        title={title}
        description={description}
        canonicalPath={canonicalPath}
        keywords={[
          'elevenid legal',
          'elevenid privacy',
          'elevenid terms',
          'self-hosted identity infrastructure',
          'verifiable identity compliance',
        ]}
        structuredData={[
          {
            '@context': 'https://schema.org',
            '@type': 'WebPage',
            name: title,
            description,
            url: canonicalUrl,
            publisher: {
              '@type': 'Organization',
              name: 'ElevenID LLC',
              url: SITE_URL,
            },
          },
          breadcrumbListSchema([
            { name: 'Home', url: SITE_URL },
            { name: title, url: canonicalUrl },
          ]),
        ]}
      />

      <Box
        sx={{
          background: 'linear-gradient(135deg, rgba(25,118,210,0.10) 0%, rgba(21,101,192,0.18) 100%)',
          border: '1px solid',
          borderColor: 'divider',
          borderRadius: 3,
          px: { xs: 3, md: 5 },
          py: { xs: 4, md: 6 },
          mb: 4,
        }}
      >
        <Breadcrumbs sx={{ mb: 2 }} aria-label="breadcrumb">
          <MuiLink component={RouterLink} underline="hover" color="inherit" to="/">
            Home
          </MuiLink>
          <Typography color="text.primary">{title}</Typography>
        </Breadcrumbs>

        <Typography variant="overline" color="primary.main" sx={{ letterSpacing: 1.2, fontWeight: 700 }}>
          {eyebrow}
        </Typography>
        <Typography variant="h3" component="h1" sx={{ mt: 1, mb: 2, fontWeight: 700 }}>
          {title}
        </Typography>
        <Typography variant="h6" color="text.secondary" sx={{ maxWidth: 860 }}>
          {description}
        </Typography>
        <Typography variant="body2" color="text.secondary" sx={{ mt: 2 }}>
          Effective date: {EFFECTIVE_DATE}
        </Typography>
      </Box>

      <Stack spacing={3}>{children}</Stack>
    </Box>
  );
}

LegalPageLayout.propTypes = {
  title: PropTypes.string.isRequired,
  description: PropTypes.string.isRequired,
  canonicalPath: PropTypes.string.isRequired,
  eyebrow: PropTypes.string.isRequired,
  children: PropTypes.node.isRequired,
};

function SectionCard({ title, children }) {
  return (
    <Paper elevation={0} sx={{ p: { xs: 3, md: 4 }, border: '1px solid', borderColor: 'divider', borderRadius: 3 }}>
      <Typography variant="h5" component="h2" sx={{ mb: 2, fontWeight: 700 }}>
        {title}
      </Typography>
      <Box sx={{ '& p:last-child': { mb: 0 } }}>{children}</Box>
    </Paper>
  );
}

SectionCard.propTypes = {
  title: PropTypes.string.isRequired,
  children: PropTypes.node.isRequired,
};

function BulletList({ items }) {
  return (
    <Box component="ul" sx={{ pl: 3, my: 0, '& li': { mb: 1 } }}>
      {items.map((item) => (
        <li key={item}>
          <Typography variant="body1" color="text.secondary">
            {item}
          </Typography>
        </li>
      ))}
    </Box>
  );
}

BulletList.propTypes = {
  items: PropTypes.arrayOf(PropTypes.string).isRequired,
};

export function PrivacyPolicyPage() {
  return (
    <LegalPageLayout
      title="Privacy Policy"
      description="How ElevenID LLC handles information on the public demonstration environment and how our self-hosted model is designed to minimize custody of customer keys and identity data."
      canonicalPath="/privacy-policy"
      eyebrow="Legal"
    >
      <SectionCard title="Overview">
        <Typography variant="body1" paragraph color="text.secondary">
          ElevenID LLC builds verifiable identity infrastructure. Our preferred production model is self-hosted deployment so customers can operate identity,
          credential, and trust services inside environments they control. We strive to be infrastructure rather than a long-term custodian of customer keys,
          wallets, or sensitive business records.
        </Typography>
        <Typography variant="body1" paragraph color="text.secondary">
          This policy applies to the public ElevenID website and demonstration environment at elevenidllc.com, including educational flows, product previews,
          documentation, and login experiences used to demonstrate how the platform works. Customer-specific self-hosted deployments may operate under separate
          agreements, customer instructions, and infrastructure controls.
        </Typography>
      </SectionCard>

      <SectionCard title="What the public site is for">
        <Typography variant="body1" paragraph color="text.secondary">
          The public production environment is intended for demonstration, education, evaluation, and adoption support. It helps technical buyers, operators,
          and partners understand how the platform behaves before choosing a self-hosted deployment or a separately governed production arrangement.
        </Typography>
        <Typography variant="body1" color="text.secondary">
          Because this site is a shared demonstration environment, you should not use it as the sole repository for regulated data, signing secrets, or other
          information that requires dedicated production handling guarantees.
        </Typography>
      </SectionCard>

      <SectionCard title="Information we may collect on the public site">
        <Typography variant="body1" paragraph color="text.secondary">
          Depending on how you interact with the site, we may process a limited set of information needed to operate the public service and support evaluation.
        </Typography>
        <BulletList
          items={[
            'Basic account and login information, such as email address, display name, or identity-provider subject identifiers used to complete sign-in.',
            'Operational metadata such as timestamps, request identifiers, IP addresses, browser details, and service logs required for security, abuse prevention, troubleshooting, and reliability.',
            'Information you choose to submit in forms, demos, onboarding flows, or support requests.',
            'Configuration and usage information needed to show product behavior, preserve session state, and improve documentation or demonstration journeys.',
          ]}
        />
      </SectionCard>

      <SectionCard title="Google and other identity providers">
        <Typography variant="body1" paragraph color="text.secondary">
          If you choose to authenticate with Google or another external identity provider, that provider will process your login according to its own terms and
          privacy practices. We typically receive only the information necessary to complete authentication and create or link an account on the demonstration site,
          such as your name, email address, and provider identifier.
        </Typography>
        <Typography variant="body1" color="text.secondary">
          We do not control the policies or security practices of third-party identity providers. You should review their policies directly before using those services.
        </Typography>
      </SectionCard>

      <SectionCard title="How we use information">
        <BulletList
          items={[
            'To authenticate users and secure access to demonstration features.',
            'To operate, maintain, monitor, and improve the public demonstration environment.',
            'To respond to requests, troubleshoot problems, and support adoption or educational conversations.',
            'To detect fraud, misuse, or attempts to compromise the service.',
            'To comply with legal obligations and enforce our policies or agreements.',
          ]}
        />
      </SectionCard>

      <SectionCard title="Self-hosted deployments and data custody">
        <Typography variant="body1" paragraph color="text.secondary">
          Our product direction emphasizes self-hosted deployments where the customer controls infrastructure, keys, storage, access policy, and retention.
          In those deployments, ElevenID LLC generally aims to provide software, integration guidance, and infrastructure patterns rather than ongoing custody of
          customer signing keys, credential stores, or sensitive operational data.
        </Typography>
        <Typography variant="body1" color="text.secondary">
          Actual data handling depends on how a customer configures the platform. If a customer chooses a separate managed arrangement, shared support workflow,
          or third-party integration, additional processing may occur under the applicable contract or deployment documentation.
        </Typography>
      </SectionCard>

      <SectionCard title="Retention, security, and disclosure">
        <Typography variant="body1" paragraph color="text.secondary">
          We retain information from the public site only for as long as reasonably necessary to operate the service, protect the environment, investigate issues,
          support evaluation activity, and satisfy legal obligations. We apply practical administrative, technical, and organizational safeguards appropriate to the
          demonstration nature of the service, but no internet-connected system can be guaranteed perfectly secure.
        </Typography>
        <Typography variant="body1" paragraph color="text.secondary">
          We may disclose information to service providers, infrastructure operators, advisors, or authorities when needed to run the site, protect users,
          investigate abuse, comply with law, or complete a business transaction. We do not sell personal information from the public demonstration site.
        </Typography>
        <Typography variant="body1" color="text.secondary">
          If you need stronger assurances regarding location, retention, deletion, breach handling, or security controls, we recommend a self-hosted deployment or
          a separately negotiated production agreement.
        </Typography>
      </SectionCard>

      <SectionCard title="Your choices and contact information">
        <Typography variant="body1" paragraph color="text.secondary">
          You may choose not to use the public demonstration environment, not to sign in with a third-party provider, or not to submit optional information.
          You may also contact us to request account assistance, ask questions about this policy, or discuss a self-hosted deployment model better aligned with
          your compliance needs.
        </Typography>
        <Typography variant="body1" color="text.secondary">
          Contact ElevenID LLC using the contact information published on the site, including{' '}
          <MuiLink href="mailto:sales@elevenidllc.com">sales@elevenidllc.com</MuiLink>.
        </Typography>
      </SectionCard>

      <Paper elevation={0} sx={{ p: { xs: 3, md: 4 }, borderRadius: 3, bgcolor: 'grey.50', border: '1px solid', borderColor: 'divider' }}>
        <Typography variant="h5" component="h2" sx={{ mb: 2, fontWeight: 700 }}>
          Looking for a lower-custody production model?
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
          ElevenID is designed to support self-hosted credential and identity infrastructure so organizations can keep operational control closer to their own
          systems, policies, and keys.
        </Typography>
        <Stack direction={{ xs: 'column', sm: 'row' }} spacing={2}>
          <Button component={RouterLink} to="/architecture" variant="contained">
            Explore architecture
          </Button>
          <Button component={RouterLink} to="/security" variant="outlined">
            Review security approach
          </Button>
        </Stack>
      </Paper>
    </LegalPageLayout>
  );
}

export function TermsOfServicePage() {
  return (
    <LegalPageLayout
      title="Terms of Service"
      description="Terms governing use of the public ElevenID LLC website and demonstration environment, with a strong preference for self-hosted deployments for production use."
      canonicalPath="/terms-of-service"
      eyebrow="Legal"
    >
      <SectionCard title="Scope and acceptance">
        <Typography variant="body1" paragraph color="text.secondary">
          These Terms of Service govern your access to and use of the public ElevenID website, demonstration environment, educational materials, and related public
          services made available at elevenidllc.com by ElevenID LLC. By accessing or using the public site, you agree to these terms.
        </Typography>
        <Typography variant="body1" color="text.secondary">
          If you use ElevenID under a separate written agreement, proof of concept statement, partner contract, or self-hosted license arrangement, that separate
          agreement may supplement or supersede these public-site terms for the covered services.
        </Typography>
      </SectionCard>

      <SectionCard title="Demonstration and education first">
        <Typography variant="body1" paragraph color="text.secondary">
          The public production environment is primarily intended to demonstrate platform capabilities, support education, and help organizations evaluate adoption.
          It is not presented as a substitute for a dedicated production deployment tailored to your compliance, availability, data residency, or operational needs.
        </Typography>
        <Typography variant="body1" color="text.secondary">
          If you need production assurances, dedicated support obligations, or stronger control over keys and data, ElevenID recommends a self-hosted deployment or
          another separately governed production arrangement.
        </Typography>
      </SectionCard>

      <SectionCard title="Acceptable use">
        <Typography variant="body1" paragraph color="text.secondary">
          You agree not to misuse the public site or attempt to interfere with its operation. This includes, without limitation:
        </Typography>
        <BulletList
          items={[
            'Attempting to gain unauthorized access to accounts, credentials, systems, or networks.',
            'Uploading malicious code, conducting denial-of-service activity, or probing the service in a way that degrades availability for others.',
            'Using the demonstration environment for unlawful activity, deceptive identity claims, or content that violates applicable law or the rights of others.',
            'Relying on the public site as the sole production environment for high-risk, regulated, or mission-critical workloads without a separate agreement.',
          ]}
        />
      </SectionCard>

      <SectionCard title="Accounts and authentication">
        <Typography variant="body1" paragraph color="text.secondary">
          You are responsible for the accuracy of information you provide and for activity occurring through your account or login method. If you authenticate using
          Google or another third-party provider, your use of that provider remains subject to the provider&apos;s own terms and policies.
        </Typography>
        <Typography variant="body1" color="text.secondary">
          We may suspend, restrict, or terminate access to the public site if we reasonably believe an account is compromised, being misused, or creating risk to the
          service or other users.
        </Typography>
      </SectionCard>

      <SectionCard title="Self-hosted deployments and customer responsibility">
        <Typography variant="body1" paragraph color="text.secondary">
          ElevenID&apos;s preferred production model is self-hosted infrastructure. In that model, customers are generally responsible for their hosting environment,
          identity provider connections, security posture, key custody, data retention, backup practices, and compliance decisions unless a separate agreement says otherwise.
        </Typography>
        <Typography variant="body1" color="text.secondary">
          We design the software to support low-custody operating models where customers can keep sensitive data and cryptographic material closer to their own control.
          Actual responsibility boundaries depend on the chosen deployment architecture and written commercial terms.
        </Typography>
      </SectionCard>

      <SectionCard title="Intellectual property and open materials">
        <Typography variant="body1" paragraph color="text.secondary">
          The public site, branding, documentation, demos, and software-related materials are owned by ElevenID LLC or its licensors except where open-source or
          third-party components are identified separately. Use of the public site does not transfer ownership of intellectual property.
        </Typography>
        <Typography variant="body1" color="text.secondary">
          ElevenID may describe or implement open standards and interoperable protocols. Your use of standards-based outputs remains subject to applicable law,
          third-party rights, and any licenses identified in the relevant software or documentation.
        </Typography>
      </SectionCard>

      <SectionCard title="Disclaimers and limits">
        <Typography variant="body1" paragraph color="text.secondary">
          The public site is provided on an “as is” and “as available” basis to the maximum extent permitted by law. We do not guarantee that the demonstration
          environment will be uninterrupted, error-free, suitable for every purpose, or appropriate as a substitute for a dedicated production deployment.
        </Typography>
        <Typography variant="body1" color="text.secondary">
          To the maximum extent permitted by law, ElevenID LLC will not be liable for indirect, incidental, special, consequential, exemplary, or punitive damages,
          or for loss of profits, data, goodwill, or business opportunity arising from use of the public site. Nothing in these terms excludes liability that cannot
          legally be excluded.
        </Typography>
      </SectionCard>

      <SectionCard title="Changes, suspension, and contact">
        <Typography variant="body1" paragraph color="text.secondary">
          We may update the public site, these terms, or the availability of demonstration features from time to time. Updated terms become effective when posted here.
          Continued use of the public site after updates are posted means you accept the revised terms.
        </Typography>
        <Typography variant="body1" color="text.secondary">
          Questions about these terms or requests for a self-hosted production discussion can be directed to{' '}
          <MuiLink href="mailto:sales@elevenidllc.com">sales@elevenidllc.com</MuiLink>.
        </Typography>
      </SectionCard>

      <Paper elevation={0} sx={{ p: { xs: 3, md: 4 }, borderRadius: 3, bgcolor: 'grey.50', border: '1px solid', borderColor: 'divider' }}>
        <Typography variant="h5" component="h2" sx={{ mb: 2, fontWeight: 700 }}>
          For production use, start with the self-hosted model
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
          The public environment helps teams evaluate ElevenID. Production responsibility, control, and data minimization are best achieved through a deployment
          you operate or contractually govern directly.
        </Typography>
        <Stack direction={{ xs: 'column', sm: 'row' }} spacing={2}>
          <Button component={RouterLink} to="/developers" variant="contained">
            Review developer resources
          </Button>
          <Button component={RouterLink} to="/resources" variant="outlined">
            Explore adoption resources
          </Button>
        </Stack>
      </Paper>

      <Divider />

      <Typography variant="body2" color="text.secondary">
        These public-site terms are general information and are not legal advice. Deployment-specific obligations, support terms, data processing commitments,
        or security requirements should be handled in a separate written agreement when needed.
      </Typography>
    </LegalPageLayout>
  );
}
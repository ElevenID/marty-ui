import { lazy } from 'react';
import { Route } from 'react-router-dom';
import { DISABLE_PUBLIC_GET_STARTED_BUTTONS } from '@ui-public-config';
import { useAuth } from '../hooks/useAuth';

const lazyNamedExport = (loader, exportName) => lazy(() => loader().then((module) => ({ default: module[exportName] })));

const LandingPage = lazy(() => import('../components/LandingPage'));
const ProductPage = lazy(() => import('../components/ProductPage'));
const StandardsPage = lazy(() => import('../components/StandardsPage'));
const ProtocolPage = lazy(() => import('../components/ProtocolPage'));
const IdentityGuidePage = lazy(() => import('../components/IdentityGuidePage'));
const FromIDVPage = lazy(() => import('../components/FromIDVPage'));
const BlogPage = lazy(() => import('@marty/blog/blog-page'));
const BlogPostPage = lazy(() => import('@marty/blog/blog-post-page'));
const AuthorsPage = lazy(() => import('@marty/blog/authors-page'));
const AuthorPage = lazy(() => import('@marty/blog/author-page'));
const FoundationsPage = lazy(() => import('@marty/blog/foundations-page'));
const PricingPage = lazyNamedExport(() => import('@marty/subscriptions'), 'PricingPage');
const SubscriptionCheckout = lazyNamedExport(() => import('@marty/subscriptions'), 'SubscriptionCheckout');
const SolutionsPage = lazyNamedExport(() => import('../components/pages/PublicIAPages'), 'SolutionsPage');
const DevelopersPage = lazyNamedExport(() => import('../components/pages/PublicIAPages'), 'DevelopersPage');
const ArchitecturePage = lazyNamedExport(() => import('../components/pages/PublicIAPages'), 'ArchitecturePage');
const SecurityPage = lazyNamedExport(() => import('../components/pages/PublicIAPages'), 'SecurityPage');
const ResourcesPage = lazyNamedExport(() => import('../components/pages/PublicIAPages'), 'ResourcesPage');
const VerifiableCredentialApiPage = lazy(() => import('../components/pages/VerifiableCredentialApiPage'));
const EudiWalletVerificationPage = lazy(() => import('../components/pages/EudiWalletVerificationPage'));
const IsoMdocVerificationPage = lazy(() => import('../components/pages/IsoMdocVerificationPage'));
const SdJwtVerificationPage = lazy(() => import('../components/pages/SdJwtVerificationPage'));
const OpenBadgesVerificationPage = lazy(() => import('../components/pages/OpenBadgesVerificationPage'));
const OpenBadgesIssuancePage = lazy(() => import('../components/pages/OpenBadgesIssuancePage'));
const TrustRegistryPage = lazy(() => import('../components/pages/TrustRegistryPage'));
const AiCapabilityPage = lazy(() => import('../components/pages/AiCapabilityPage'));
const WhatIsCredentialVerificationPage = lazy(() => import('../components/pages/WhatIsCredentialVerificationPage'));
const WhatIsOpenBadgePage = lazy(() => import('../components/pages/WhatIsOpenBadgePage'));
const WhatIsDigitalCredentialPage = lazy(() => import('../components/pages/WhatIsDigitalCredentialPage'));
const WhatIsMartyProtocolPage = lazy(() => import('../components/pages/WhatIsMartyProtocolPage'));

export function renderPublicRoot() {
  return <LandingPage />;
}

export function renderMarketingRoutes({ login }) {
  return (
    <>
      <Route path="/product" element={<ProductPage />} />
      <Route path="/solutions" element={<SolutionsPage />} />
      <Route path="/developers" element={<DevelopersPage />} />
      <Route path="/architecture" element={<ArchitecturePage />} />
      <Route path="/security" element={<SecurityPage />} />
      <Route path="/resources" element={<ResourcesPage />} />
      <Route path="/verifiable-credential-api" element={<VerifiableCredentialApiPage />} />
      <Route path="/eudi-wallet-verification" element={<EudiWalletVerificationPage />} />
      <Route path="/iso-18013-5-mdoc-verification" element={<IsoMdocVerificationPage />} />
      <Route path="/sd-jwt-verification" element={<SdJwtVerificationPage />} />
      <Route path="/open-badges-verification" element={<OpenBadgesVerificationPage />} />
      <Route path="/open-badges-issuance" element={<OpenBadgesIssuancePage />} />
      <Route path="/trust-registry-infrastructure" element={<TrustRegistryPage />} />
      <Route path="/identity" element={<IdentityGuidePage />} />
      <Route path="/why-verifiable-identity" element={<FromIDVPage />} />
      <Route path="/from-idv-to-verifiable-identity" element={<FromIDVPage />} />
      <Route path="/standards" element={<StandardsPage />} />
      <Route path="/protocol" element={<ProtocolPage />} />
      <Route path="/ai" element={<AiCapabilityPage />} />
      <Route path="/what-is-verifiable-identity" element={<FromIDVPage />} />
      <Route path="/what-is-credential-verification" element={<WhatIsCredentialVerificationPage />} />
      <Route path="/what-is-open-badge" element={<WhatIsOpenBadgePage />} />
      <Route path="/what-is-digital-credential" element={<WhatIsDigitalCredentialPage />} />
      <Route path="/what-is-marty-protocol" element={<WhatIsMartyProtocolPage />} />
      <Route path="/blog" element={<BlogPage />} />
      <Route path="/blog/tag/:tag" element={<BlogPage />} />
      <Route path="/blog/foundations" element={<FoundationsPage />} />
      <Route path="/blog/:slug" element={<BlogPostPage />} />
      <Route path="/authors" element={<AuthorsPage />} />
      <Route path="/authors/:authorId" element={<AuthorPage />} />
      <Route
        path="/pricing"
        element={
          <PricingPage
            login={login}
            disableSandboxSignup={DISABLE_PUBLIC_GET_STARTED_BUTTONS}
            checkoutBasePath="/pricing/checkout"
          />
        }
      />
      <Route
        path="/pricing/checkout"
        element={
          <SubscriptionCheckout
            useAuth={useAuth}
            login={login}
            setupPath="/console-handoff/org/setup"
            billingPath="/console-handoff/org/billing"
          />
        }
      />
    </>
  );
}
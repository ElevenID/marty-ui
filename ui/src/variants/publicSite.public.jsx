import { lazy } from 'react';
import { Navigate, Route } from 'react-router-dom';
import { DISABLE_PUBLIC_GET_STARTED_BUTTONS } from '@ui-public-config';
import { useAuth } from '../hooks/useAuth';
import { renderCommercePublicRoutes } from '../extensions/commerce';

const lazyNamedExport = (loader, exportName) => lazy(() => loader().then((module) => ({ default: module[exportName] })));

const LandingPage = lazy(() => import('../components/LandingPage'));
const ProductPage = lazy(() => import('../components/ProductPage'));
const StandardsPage = lazy(() => import('../components/StandardsPage'));
const ProtocolPage = lazy(() => import('../components/ProtocolPage'));
const IdentityGuidePage = lazy(() => import('../components/IdentityGuidePage'));
const FromIDVPage = lazy(() => import('../components/FromIDVPage'));
const BlogPage = lazy(() => import('@elevenid/marty-blog/blog-page'));
const BlogPostPage = lazy(() => import('@elevenid/marty-blog/blog-post-page'));
const AuthorsPage = lazy(() => import('@elevenid/marty-blog/authors-page'));
const AuthorPage = lazy(() => import('@elevenid/marty-blog/author-page'));
const FoundationsPage = lazy(() => import('@elevenid/marty-blog/foundations-page'));
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
const PrivacyPolicyPage = lazyNamedExport(() => import('../components/pages/LegalPages'), 'PrivacyPolicyPage');
const TermsOfServicePage = lazyNamedExport(() => import('../components/pages/LegalPages'), 'TermsOfServicePage');
const DemoCatalogPage = lazyNamedExport(() => import('../components/pages/DemoPages'), 'DemoCatalogPage');
const DemoReleasePage = lazyNamedExport(() => import('../components/pages/DemoPages'), 'DemoReleasePage');
const DemoScenarioPage = lazyNamedExport(() => import('../components/pages/DemoPages'), 'DemoScenarioPage');
const DemoLatestScenarioRedirect = lazyNamedExport(() => import('../components/pages/DemoPages'), 'DemoLatestScenarioRedirect');

export function renderPublicRoot() {
  return <LandingPage />;
}

export function getPublicLoginFallback() {
  return '/';
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
      <Route path="/demos" element={<DemoCatalogPage />} />
      <Route path="/demos/latest/:scenario" element={<DemoLatestScenarioRedirect />} />
      <Route path="/demos/:stackVersion/:scenario" element={<DemoScenarioPage />} />
      <Route path="/demos/:stackVersion" element={<DemoReleasePage />} />
      <Route path="/verification" element={<Navigate to="/verifiable-credential-api" replace />} />
      <Route path="/verifiable-credential-api" element={<VerifiableCredentialApiPage />} />
      <Route path="/eudi-wallet-verification" element={<EudiWalletVerificationPage />} />
      <Route path="/iso-18013-5-mdoc-verification" element={<IsoMdocVerificationPage />} />
      <Route path="/sd-jwt-verification" element={<SdJwtVerificationPage />} />
      <Route path="/open-badges-verification" element={<OpenBadgesVerificationPage />} />
      <Route path="/issuance" element={<Navigate to="/open-badges-issuance" replace />} />
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
      <Route path="/privacy-policy" element={<PrivacyPolicyPage />} />
      <Route path="/privacy" element={<PrivacyPolicyPage />} />
      <Route path="/terms-of-service" element={<TermsOfServicePage />} />
      <Route path="/terms" element={<TermsOfServicePage />} />
      <Route path="/blog" element={<BlogPage />} />
      <Route path="/blog/tag/:tag" element={<BlogPage />} />
      <Route path="/blog/foundations" element={<FoundationsPage />} />
      <Route path="/blog/:slug" element={<BlogPostPage />} />
      <Route path="/authors" element={<AuthorsPage />} />
      <Route path="/authors/:authorId" element={<AuthorPage />} />
      {renderCommercePublicRoutes({
        login,
        useAuth,
        disableSandboxSignup: DISABLE_PUBLIC_GET_STARTED_BUTTONS,
      })}
    </>
  );
}

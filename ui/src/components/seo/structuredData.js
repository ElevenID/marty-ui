/**
 * Structured data (JSON-LD) generators for SEO
 * Based on schema.org standards
 */

/**
 * Organization schema for homepage and site-wide use
 */
export const organizationSchema = () => ({
  '@context': 'https://schema.org',
  '@type': 'Organization',
  name: 'ElevenID LLC',
  url: 'https://elevenidllc.com',
  logo: 'https://elevenidllc.com/logo512.png',
  description: 'Verifiable identity infrastructure for EUDI Wallets, Open Badges, and W3C Verifiable Credentials',
  foundingDate: '2023',
  sameAs: [
    // Add social media profiles when available
  ],
  contactPoint: {
    '@type': 'ContactPoint',
    contactType: 'Sales',
    email: 'sales@elevenidllc.com',
  },
});

/**
 * SoftwareApplication schema for product pages
 * @param {object} params - Product parameters
 */
export const softwareApplicationSchema = ({
  name,
  description,
  applicationCategory = 'SecurityApplication',
  operatingSystem = 'Cross-platform',
  offers = null,
}) => {
  const schema = {
    '@context': 'https://schema.org',
    '@type': 'SoftwareApplication',
    name,
    description,
    applicationCategory,
    operatingSystem,
    provider: {
      '@type': 'Organization',
      name: 'ElevenID LLC',
      url: 'https://elevenidllc.com',
    },
  };

  if (offers) {
    schema.offers = {
      '@type': 'Offer',
      ...offers,
    };
  }

  return schema;
};

/**
 * Article schema for learn/blog content
 * @param {object} params - Article parameters
 */
export const articleSchema = ({
  headline,
  description,
  datePublished,
  dateModified = null,
  authorName = 'ElevenID LLC',
  url,
}) => ({
  '@context': 'https://schema.org',
  '@type': 'Article',
  headline,
  description,
  datePublished,
  dateModified: dateModified || datePublished,
  author: {
    '@type': 'Organization',
    name: authorName,
  },
  publisher: {
    '@type': 'Organization',
    name: 'ElevenID LLC',
    logo: {
      '@type': 'ImageObject',
      url: 'https://elevenidllc.com/logo512.png',
    },
  },
  url,
  mainEntityOfPage: {
    '@type': 'WebPage',
    '@id': url,
  },
});

/**
 * BreadcrumbList schema for navigation hierarchy
 * @param {array} items - Array of {name, url} objects representing breadcrumb hierarchy
 * @example breadcrumbListSchema([
 *   { name: 'Home', url: 'https://elevenidllc.com' },
 *   { name: 'Products', url: 'https://elevenidllc.com/product' },
 *   { name: 'API Verification', url: 'https://elevenidllc.com/verifiable-credential-api' }
 * ])
 */
export const breadcrumbListSchema = (items) => ({
  '@context': 'https://schema.org',
  '@type': 'BreadcrumbList',
  itemListElement: items.map((item, index) => ({
    '@type': 'ListItem',
    position: index + 1,
    name: item.name,
    item: item.url,
  })),
});

/**
 * TechArticle schema for the protocol/specification page
 */
export const protocolSchema = () => ({
  '@context': 'https://schema.org',
  '@type': 'TechArticle',
  name: 'Marty Identity Protocol (MIP)',
  headline: 'An open standard for cryptographically verifiable digital identity management',
  description: 'MIP defines the minimum automatable set of primitives required for issuing, holding, presenting, and verifying digital credentials under explicit rules of trust and disclosure.',
  url: 'https://elevenidllc.com/protocol',
  datePublished: '2026-03-11',
  license: 'https://www.apache.org/licenses/LICENSE-2.0',
  version: '0.1.0',
  author: {
    '@type': 'Organization',
    name: 'The MIP Authors',
  },
  publisher: {
    '@type': 'Organization',
    name: 'ElevenID LLC',
    url: 'https://elevenidllc.com',
  },
  about: {
    '@type': 'Thing',
    name: 'Digital Identity Management',
  },
});

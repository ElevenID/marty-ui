import { useEffect } from 'react';
import PropTypes from 'prop-types';

/**
 * SEOHead component - Manages page metadata for SEO
 * 
 * @param {string} title - Page title (max 60 chars, will be suffixed with " | ElevenID LLC")
 * @param {string} description - Meta description (140-160 chars recommended)
 * @param {string} canonicalPath - Path for canonical URL (e.g., "/product")
 * @param {string} ogImage - Open Graph image URL (absolute URL)
 * @param {string} ogType - Open Graph type (default: "website")
 * @param {object} structuredData - JSON-LD structured data object
 * @param {string[]} keywords - Array of keywords for meta keywords tag
 */
const SEOHead = ({
  title,
  description,
  canonicalPath,
  ogImage = 'https://elevenidllc.com/logo512.png',
  ogType = 'website',
  structuredData = null,
  keywords = [],
}) => {
  const siteUrl = 'https://elevenidllc.com';
  const fullTitle = title.includes('ElevenID LLC') ? title : `${title} | ElevenID LLC`;
  const canonicalUrl = `${siteUrl}${canonicalPath}`;

  useEffect(() => {
    document.title = fullTitle;

    const upsertMeta = (selector, attrs = {}, content = null) => {
      let el = document.head.querySelector(selector);
      if (!el) {
        el = document.createElement('meta');
        Object.entries(attrs).forEach(([k, v]) => el.setAttribute(k, v));
        document.head.appendChild(el);
      }
      if (content !== null) {
        el.setAttribute('content', content);
      }
      return el;
    };

    const upsertLink = (selector, rel, href) => {
      let el = document.head.querySelector(selector);
      if (!el) {
        el = document.createElement('link');
        el.setAttribute('rel', rel);
        document.head.appendChild(el);
      }
      el.setAttribute('href', href);
      return el;
    };

    upsertMeta('meta[name="description"]', { name: 'description' }, description);
    if (keywords.length > 0) {
      upsertMeta('meta[name="keywords"]', { name: 'keywords' }, keywords.join(', '));
    }

    upsertLink('link[rel="canonical"]', 'canonical', canonicalUrl);

    upsertMeta('meta[property="og:site_name"]', { property: 'og:site_name' }, 'ElevenID LLC');
    upsertMeta('meta[property="og:type"]', { property: 'og:type' }, ogType);
    upsertMeta('meta[property="og:title"]', { property: 'og:title' }, fullTitle);
    upsertMeta('meta[property="og:description"]', { property: 'og:description' }, description);
    upsertMeta('meta[property="og:url"]', { property: 'og:url' }, canonicalUrl);
    upsertMeta('meta[property="og:image"]', { property: 'og:image' }, ogImage);
    upsertMeta('meta[property="og:image:alt"]', { property: 'og:image:alt' }, title);

    upsertMeta('meta[name="twitter:card"]', { name: 'twitter:card' }, 'summary_large_image');
    upsertMeta('meta[name="twitter:title"]', { name: 'twitter:title' }, fullTitle);
    upsertMeta('meta[name="twitter:description"]', { name: 'twitter:description' }, description);
    upsertMeta('meta[name="twitter:image"]', { name: 'twitter:image' }, ogImage);

    let scriptEl = document.head.querySelector('script[data-seo-jsonld="true"]');
    if (structuredData) {
      if (!scriptEl) {
        scriptEl = document.createElement('script');
        scriptEl.type = 'application/ld+json';
        scriptEl.setAttribute('data-seo-jsonld', 'true');
        document.head.appendChild(scriptEl);
      }
      scriptEl.textContent = JSON.stringify(structuredData);
    } else if (scriptEl) {
      scriptEl.remove();
    }
  }, [fullTitle, description, canonicalUrl, ogType, ogImage, title, structuredData, keywords]);

  return null;
};

SEOHead.propTypes = {
  title: PropTypes.string.isRequired,
  description: PropTypes.string.isRequired,
  canonicalPath: PropTypes.string.isRequired,
  ogImage: PropTypes.string,
  ogType: PropTypes.string,
  structuredData: PropTypes.object,
  keywords: PropTypes.arrayOf(PropTypes.string),
};

export default SEOHead;

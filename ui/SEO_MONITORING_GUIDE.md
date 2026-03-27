# SEO & Monitoring Setup Guide

## ✅ Production Build Test Results

**Status**: PASSED ✅

### Build Output
- ✅ 14 routes prerendered successfully
- ✅ Meta tags injected (title, description, keywords)
- ✅ Open Graph tags present
- ✅ Twitter Card tags present
- ✅ JSON-LD structured data embedded
- ✅ Canonical URLs set
- ✅ robots.txt generated (298 bytes)
- ✅ sitemap.xml generated (4.9 KB, 15 URLs)

### Prerendered Pages
```
/ (75.66 KB)
/product (56.39 KB)
/verifiable-credential-api (32.30 KB)
/eudi-wallet-verification (13.86 KB)
/iso-18013-5-mdoc-verification (10.54 KB)
/sd-jwt-verification (9.52 KB)
/open-badges-verification (11.14 KB)
/open-badges-issuance (9.63 KB)
/trust-registry-infrastructure (10.66 KB)
/identity (34.94 KB)
/from-idv-to-verifiable-identity (29.79 KB)
/standards (27.10 KB)
/pricing (40.16 KB)
/docs (23.14 KB)
```

### robots.txt
```
User-agent: *
Allow: /
Disallow: /console
Disallow: /applicant
Disallow: /admin
Disallow: /vendor
Disallow: /dashboard
Disallow: /auth/*
Disallow: /api/*
Disallow: /v1/*

Sitemap: https://elevenidllc.com/sitemap.xml
```

---

## 🔍 Google Search Console Setup

### 1. Add Site to Search Console

1. Go to [Google Search Console](https://search.google.com/search-console)
2. Click "Add Property"
3. Choose "URL prefix" and enter: `https://elevenidllc.com`

### 2. Verify Ownership

**Option A: HTML Meta Tag** (Recommended)

1. Search Console will provide a verification meta tag like:
   ```html
   <meta name="google-site-verification" content="YOUR_VERIFICATION_CODE" />
   ```

2. Add it to `ui/index.html` in the `<head>` section:
   ```html
   <!-- Google Search Console Verification -->
   <meta name="google-site-verification" content="YOUR_CODE_HERE" />
   ```

3. Deploy and click "Verify" in Search Console

**Option B: Upload HTML File**

1. Download the verification HTML file from Search Console
2. Place it in `ui/public/` directory
3. Deploy and click "Verify"

### 3. Submit Sitemap

1. In Search Console, go to Sitemaps (left sidebar)
2. Enter `https://elevenidllc.com/sitemap.xml`
3. Click "Submit"

### 4. Monitor Coverage

- **Index Coverage**: Check which pages are indexed
- **URL Inspection**: Test individual URLs
- **Performance**: View clicks, impressions, CTR
- **Core Web Vitals**: Monitor page experience metrics

---

## 📊 Google Analytics Setup

### 1. Create GA4 Property

1. Go to [Google Analytics](https://analytics.google.com/)
2. Create new GA4 property for `elevenidllc.com`
3. Copy your Measurement ID (format: `G-XXXXXXXXXX`)

### 2. Configure Environment Variable

Add to `ui/.env.production` for production builds, or to the repo root `.env` when testing through the local tunnel stack:
```bash
VITE_GA_MEASUREMENT_ID=G-XXXXXXXXXX
```

### 3. Initialize Analytics

In `ui/src/App.jsx`, add:
```javascript
import { useEffect } from 'react';
import { useLocation } from 'react-router-dom';
import { initAnalytics, trackPageView, trackWebVitals } from './utils/analytics';

function App() {
  const location = useLocation();

  // Initialize once
  useEffect(() => {
    initAnalytics();
    trackWebVitals();
  }, []);

  // Track route changes
  useEffect(() => {
    trackPageView(location.pathname, document.title);
  }, [location]);

  // ... rest of App
}
```

### 4. Install web-vitals (Optional)

For Core Web Vitals tracking:
```bash
cd ui
bun add web-vitals
```

### 5. Track Custom Events

```javascript
import { trackEvent, trackConversion } from './utils/analytics';

// Example: Track button clicks
trackEvent('cta_clicked', { button_name: 'start_free' });

// Example: Track conversions
trackConversion('signup', { plan: 'FREE' });
```

---

## 📈 Monitoring Checklist

### Weekly Tasks
- [ ] Check Search Console for crawl errors
- [ ] Review index coverage (target: 14/14 pages)
- [ ] Monitor Core Web Vitals scores:
  - **LCP**: < 2.5s (good)
  - **FID**: < 100ms (good)
  - **CLS**: < 0.1 (good)

### Monthly Tasks
- [ ] Analyze top queries in Search Console
- [ ] Review organic traffic in Google Analytics
- [ ] Check for broken backlinks
- [ ] Update sitemap if new pages added
- [ ] Review page speed insights

### Quarterly Tasks
- [ ] Audit meta descriptions for CTR optimization
- [ ] Update structured data if product changes
- [ ] Review and refresh content on low-performing pages
- [ ] Check competitors' SEO strategies

---

## 🎯 SEO Performance Targets

### First 30 Days
- ✅ All 14 pages indexed
- ✅ No crawl errors
- ✅ Sitemap submitted
- ✅ Core Web Vitals passing

### 90 Days
- 🎯 10+ branded keyword rankings
- 🎯 5+ non-branded keyword rankings (position < 50)
- 🎯 100+ organic sessions/month

### 6 Months
- 🎯 20+ top 10 rankings
- 🎯 500+ organic sessions/month
- 🎯 Domain Authority > 20

---

## 🔧 Troubleshooting

### Pages Not Indexed

1. Check robots.txt isn't blocking: `curl https://elevenidllc.com/robots.txt`
2. Verify canonical URLs match domain
3. Use URL Inspection tool in Search Console
4. Check for noindex tags (there shouldn't be any)

### Low Core Web Vitals

1. **LCP Issues**: Optimize images, reduce server response time
2. **FID Issues**: Minimize JavaScript, use code splitting
3. **CLS Issues**: Set image dimensions, avoid layout shifts

### Analytics Not Tracking

1. Check `VITE_GA_MEASUREMENT_ID` is set
2. Verify gtag.js loads: Check Network tab in DevTools
3. Test in incognito mode (browser extensions can block tracking)
4. Use [Google Tag Assistant](https://tagassistant.google.com/)

---

## 📚 Resources

- [Google Search Console Help](https://support.google.com/webmasters)
- [GA4 Documentation](https://support.google.com/analytics/answer/9304153)
- [Core Web Vitals Guide](https://web.dev/vitals/)
- [Schema.org Documentation](https://schema.org/)
- [Open Graph Protocol](https://ogp.me/)

---

## 🚀 Next Steps

1. **Add verification meta tag** to `ui/index.html`
2. **Set up GA4 property** and add measurement ID to `.env`
3. **Integrate analytics** in `App.jsx`
4. **Deploy production build** to elevenidllc.com
5. **Verify in Search Console** and submit sitemap
6. **Monitor for 7 days** and review initial metrics

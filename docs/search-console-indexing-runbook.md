# Search Console indexing correction and verification

Tracking: #830. These changes are proposals for human review, not deployments.

## Condition and evidence

The reviewed notifications report HTTP 401, HTTP 5xx, pages with redirects,
duplicates without a selected canonical, and alternate pages with a proper
canonical. The onboarding email contains no additional website defect.
The emails do not provide affected URLs or prove the entire site is unindexed.

The public UI Dockerfile disables prerendering. The original Vite configuration
also disabled sitemap/robots generation under that flag. Both UI Nginx configs
returned the SPA shell for missing crawler files. Browser navigation to the live
crawler-file URLs ended at the homepage; that observation is not, by itself,
evidence of a server-side HTTP redirect or of the deployed image revision.

## Corrections

1. Generate sitemap/robots in public builds independently of browser prerendering
   (#831), while leaving self-host/development behavior unchanged.
2. Serve robots and root/index/numbered XML sitemap files as files in both UI
   Nginx configurations. Missing files return 404, not a successful HTML shell.
   This second change detects a missing artifact; it does not generate one.

No authentication, gateway failure handling, beta canonical policy, or deliberate
redirect is changed. Robots rules are crawl guidance, not access control.

## Local confirmation

With the repository's supported Node toolchain and locked dependencies:

```sh
cd ui
node --experimental-vm-modules --test scripts/seo-config.test.mjs
cd ..
python3 ui/scripts/test_nginx_crawler_routes.py
```

The first command is provided by #831. It executes the real Vite configuration
with explicit plugin/content fixtures, not a full build. The second requires a
local `nginx` binary and uses disposable fixtures, loopback servers, the actual
repository configs, `nginx -t`, and real GET/HEAD requests. It fails rather than
skipping if Nginx is unavailable. No external network or real credentials are
needed by either test.

Also run the repository's frozen install, public build and existing SEO tests.
Repeat the public build with `DISABLE_PRERENDER=1`; inspect the final image for
nonempty crawler files in both cases. These full-build/image checks are separate
from fixture-based local regression results. Check the actual deployment target:
external reverse proxies or Cloudflare rules can still override UI behavior.

## After a separately authorized deployment

Check raw HTTP responses before using a browser (which may execute SPA redirects):

```sh
curl -sS --max-time 20 -D - https://elevenidllc.com/robots.txt
curl -sS --max-time 20 -D - https://elevenidllc.com/sitemap.xml
curl -sS --max-time 20 -D - https://elevenidllc.com/product
```

Expect robots to be text and the sitemap to be valid XML, not HTML, login pages,
or challenges. A missing sitemap now correctly returns 404 but still needs the
build/deployment repaired. Follow any sitemap-index entries and verify the
actual generated filenames. Inspect public-page canonical and robots metadata,
redirect chains, response codes, and headers; compare the main and beta hosts.
Do not expose private URLs or secrets in public issues or test fixtures.

## Resolve the remaining reports using actual URL examples

Use authenticated Search Console Page indexing and URL inspection to record each
reported example's hostname, path, last crawl, current response, and canonical.
An email reporting a new reason can reflect an earlier crawl.

- **401:** A private API or account page may correctly require authentication.
  Do not remove authentication to make it indexable. For an intended public page,
  locate the specific application/edge rule responsible and fix only that route.
- **5xx:** Reproduce the specific URL and check application, proxy, tunnel and
  origin logs around its crawl date. Never convert genuine failures to fake 200s.
- **Duplicate without selected canonical:** Inspect initial and rendered HTML,
  sitemap membership, and both selected canonicals. Correct inconsistent signals
  only after establishing the intended canonical page.
- **Page with redirect:** Preserve intentional redirects. Prefer final canonical
  URLs in sitemap entries and internal links. Check for loops or wrong targets.
- **Alternate with proper canonical:** Normally expected for a deliberate
  alternate; verify that its intended canonical is eligible and indexed.

After the deployed fix is verified, use Validate fix for actionable groups and
inspect/request indexing for representative public canonical pages. This is a
separate authorized operation; do not promise indexing or a completion date.
Keep #830 open until affected-URL and deployed evidence supports closure.

## References

- https://support.google.com/webmasters/answer/7440203
- https://developers.google.com/search/docs/crawling-indexing/consolidate-duplicate-urls
- https://developers.google.com/crawling/docs/robots-txt/robots-txt-spec

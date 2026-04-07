// vite.config.ts
import { defineConfig, loadEnv } from "file:///Volumes/Heart%20of%20Gold/Github/work/marty-ui/ui/node_modules/vite/dist/node/index.js";
import react from "file:///Volumes/Heart%20of%20Gold/Github/work/marty-ui/ui/node_modules/@vitejs/plugin-react/dist/index.js";
import prerender from "file:///Volumes/Heart%20of%20Gold/Github/work/marty-ui/ui/node_modules/@prerenderer/rollup-plugin/index.mjs";
import PuppeteerRenderer from "file:///Volumes/Heart%20of%20Gold/Github/work/marty-ui/ui/node_modules/@prerenderer/renderer-puppeteer/index.mjs";
import Sitemap from "file:///Volumes/Heart%20of%20Gold/Github/work/marty-ui/ui/node_modules/vite-plugin-sitemap/dist/index.js";
var vite_config_default = defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), "");
  const isDev = mode === "development";
  const disablePrerender = isDev || process.env.DISABLE_PRERENDER === "1";
  const port = Number(env.VITE_PORT || env.PORT || env.UI_DEV_PORT || 3e3);
  return {
    resolve: {
      dedupe: ["react", "react-dom", "react/jsx-runtime", "react/jsx-dev-runtime"]
    },
    optimizeDeps: {
      include: ["react", "react-dom", "react/jsx-runtime", "react/jsx-dev-runtime", "react-router-dom", "@marty/blog"]
    },
    plugins: [
      react(),
      // Checker temporarily disabled for debugging
      /*
      ...(isDev ? [checker({
        typescript: true,
        eslint: {
          lintCommand: 'eslint . --ext .js,.jsx,.ts,.tsx',
        },
        overlay: {
          initialIsOpen: false,
          position: 'br',
        },
      })] : []),
      */
      // Prerendering for SEO - only in production builds
      ...!disablePrerender ? [
        prerender({
          routes: [
            "/",
            "/product",
            "/verifiable-credential-api",
            "/eudi-wallet-verification",
            "/iso-18013-5-mdoc-verification",
            "/sd-jwt-verification",
            "/open-badges-verification",
            "/open-badges-issuance",
            "/trust-registry-infrastructure",
            "/identity",
            "/from-idv-to-verifiable-identity",
            "/standards",
            "/protocol",
            "/blog",
            "/blog/why-identity-needs-a-protocol",
            "/blog/trust-profiles-explained",
            "/blog/business-case-for-credential-portability",
            "/blog/cryptographic-trust-anchors-primer",
            "/blog/credential-templates-designing-what-gets-issued",
            "/blog/presentation-policies-minimum-disclosure",
            "/blog/eudi-wallet-readiness",
            "/blog/deployment-profiles-from-design-to-production",
            "/blog/zero-knowledge-predicates-identity",
            "/blog/flows-orchestrating-identity-lifecycle",
            "/blog/compliance-profiles-bridging-regulation",
            "/blog/sd-jwt-selective-disclosure-deep-dive",
            "/blog/cedar-policies-for-identity-governance",
            "/blog/introducing-mip",
            "/blog/mip-json-schemas-walkthrough",
            "/blog/post-quantum-readiness-in-identity",
            "/blog/building-trust-registries-at-scale",
            "/blog/offline-verification-design-patterns",
            "/blog/holder-binding-beyond-biometrics",
            "/blog/mip-and-open-badges-education-credentials",
            "/blog/conformance-testing-for-implementers",
            "/blog/revocation-strategies-compared",
            "/pricing",
            "/docs"
          ],
          renderer: new PuppeteerRenderer({
            renderAfterTime: 3e3,
            // Wait for MUI CSS-in-JS hydration
            headless: true
          }),
          postProcess(route) {
            route.html = route.html.replace(
              "</head>",
              '<meta name="prerender-status-code" content="200" /></head>'
            );
          }
        }),
        // Sitemap generation
        Sitemap({
          hostname: "https://elevenidllc.com",
          dynamicRoutes: [
            "/",
            "/product",
            "/verifiable-credential-api",
            "/eudi-wallet-verification",
            "/iso-18013-5-mdoc-verification",
            "/sd-jwt-verification",
            "/open-badges-verification",
            "/open-badges-issuance",
            "/trust-registry-infrastructure",
            "/identity",
            "/from-idv-to-verifiable-identity",
            "/standards",
            "/protocol",
            "/blog",
            "/blog/why-identity-needs-a-protocol",
            "/blog/trust-profiles-explained",
            "/blog/business-case-for-credential-portability",
            "/blog/cryptographic-trust-anchors-primer",
            "/blog/credential-templates-designing-what-gets-issued",
            "/blog/presentation-policies-minimum-disclosure",
            "/blog/eudi-wallet-readiness",
            "/blog/deployment-profiles-from-design-to-production",
            "/blog/zero-knowledge-predicates-identity",
            "/blog/flows-orchestrating-identity-lifecycle",
            "/blog/compliance-profiles-bridging-regulation",
            "/blog/sd-jwt-selective-disclosure-deep-dive",
            "/blog/cedar-policies-for-identity-governance",
            "/blog/introducing-mip",
            "/blog/mip-json-schemas-walkthrough",
            "/blog/post-quantum-readiness-in-identity",
            "/blog/building-trust-registries-at-scale",
            "/blog/offline-verification-design-patterns",
            "/blog/holder-binding-beyond-biometrics",
            "/blog/mip-and-open-badges-education-credentials",
            "/blog/conformance-testing-for-implementers",
            "/blog/revocation-strategies-compared",
            "/pricing",
            "/docs"
          ],
          exclude: [
            "/console",
            "/console/*",
            "/applicant",
            "/applicant/*",
            "/admin",
            "/admin/*",
            "/vendor",
            "/vendor/*",
            "/dashboard",
            "/login",
            "/auth/*"
          ],
          changefreq: "weekly",
          priority: {
            "/": 1,
            "/product": 0.9,
            "/pricing": 0.9,
            "/standards": 0.8,
            "/docs": 0.8,
            "*": 0.7
          },
          generateRobotsTxt: true,
          robots: [
            {
              userAgent: "*",
              allow: "/",
              disallow: [
                "/console",
                "/console/*",
                "/applicant",
                "/applicant/*",
                "/admin",
                "/admin/*",
                "/vendor",
                "/vendor/*",
                "/dashboard",
                "/auth/*",
                "/api/*",
                "/v1/*"
              ]
            }
          ]
        })
      ] : []
    ],
    server: {
      port,
      host: "0.0.0.0",
      // Listen on all network interfaces
      strictPort: false,
      cors: true,
      allowedHosts: env.PUBLIC_DOMAIN ? [env.PUBLIC_DOMAIN, "localhost"] : "all",
      headers: {
        "Cache-Control": "no-store"
      },
      // When accessed via a public tunnel domain, the browser must connect
      // the HMR WebSocket to the public host via wss:// on port 443.
      // Without this, Vite tries ws://localhost:3000 which fails cross-origin.
      ...env.PUBLIC_DOMAIN ? {
        hmr: {
          protocol: "wss",
          host: env.PUBLIC_DOMAIN,
          clientPort: 443
        }
      } : {},
      proxy: {
        // Proxy /v1/* API requests to microservices gateway
        "/v1": {
          target: env.VITE_API_URL || "http://127.0.0.1:8000",
          changeOrigin: true,
          secure: false,
          ws: true
        },
        // Proxy /auth/* requests to the backend (OIDC flows)
        "/auth": {
          target: env.VITE_API_URL || "http://127.0.0.1:8000",
          changeOrigin: true,
          secure: false,
          ws: true
        },
        // Legacy /api/* proxy (for backwards compatibility during transition)
        "/api": {
          target: env.VITE_API_URL || "http://127.0.0.1:8000",
          changeOrigin: true,
          secure: false,
          ws: true
        },
        // Proxy health check
        "/health": {
          target: env.VITE_API_URL || "http://127.0.0.1:8000",
          changeOrigin: true,
          secure: false
        },
        // Proxy OpenAPI schema for API documentation
        "/openapi.json": {
          target: env.VITE_API_URL || "http://127.0.0.1:8000",
          changeOrigin: true,
          secure: false
        }
      }
    },
    build: {
      outDir: "dist",
      sourcemap: true,
      chunkSizeWarningLimit: 1e3,
      // Increase from default 500kB to 1000kB
      rollupOptions: {
        output: {
          manualChunks: {
            "react-vendor": ["react", "react-dom", "react-router-dom"],
            "mui-vendor": ["@mui/material", "@mui/icons-material", "@mui/x-date-pickers"],
            "chart-vendor": ["recharts"]
          }
        }
      }
    }
  };
});
export {
  vite_config_default as default
};
//# sourceMappingURL=data:application/json;base64,ewogICJ2ZXJzaW9uIjogMywKICAic291cmNlcyI6IFsidml0ZS5jb25maWcudHMiXSwKICAic291cmNlc0NvbnRlbnQiOiBbImNvbnN0IF9fdml0ZV9pbmplY3RlZF9vcmlnaW5hbF9kaXJuYW1lID0gXCIvVm9sdW1lcy9IZWFydCBvZiBHb2xkL0dpdGh1Yi93b3JrL21hcnR5LXVpL3VpXCI7Y29uc3QgX192aXRlX2luamVjdGVkX29yaWdpbmFsX2ZpbGVuYW1lID0gXCIvVm9sdW1lcy9IZWFydCBvZiBHb2xkL0dpdGh1Yi93b3JrL21hcnR5LXVpL3VpL3ZpdGUuY29uZmlnLnRzXCI7Y29uc3QgX192aXRlX2luamVjdGVkX29yaWdpbmFsX2ltcG9ydF9tZXRhX3VybCA9IFwiZmlsZTovLy9Wb2x1bWVzL0hlYXJ0JTIwb2YlMjBHb2xkL0dpdGh1Yi93b3JrL21hcnR5LXVpL3VpL3ZpdGUuY29uZmlnLnRzXCI7aW1wb3J0IHsgZGVmaW5lQ29uZmlnLCBsb2FkRW52IH0gZnJvbSAndml0ZSdcbmltcG9ydCByZWFjdCBmcm9tICdAdml0ZWpzL3BsdWdpbi1yZWFjdCdcbmltcG9ydCBjaGVja2VyIGZyb20gJ3ZpdGUtcGx1Z2luLWNoZWNrZXInXG5pbXBvcnQgcHJlcmVuZGVyIGZyb20gJ0BwcmVyZW5kZXJlci9yb2xsdXAtcGx1Z2luJ1xuaW1wb3J0IFB1cHBldGVlclJlbmRlcmVyIGZyb20gJ0BwcmVyZW5kZXJlci9yZW5kZXJlci1wdXBwZXRlZXInXG5pbXBvcnQgU2l0ZW1hcCBmcm9tICd2aXRlLXBsdWdpbi1zaXRlbWFwJ1xuXG4vLyBodHRwczovL3ZpdGVqcy5kZXYvY29uZmlnL1xuZXhwb3J0IGRlZmF1bHQgZGVmaW5lQ29uZmlnKCh7IG1vZGUgfSkgPT4ge1xuICAvLyBMb2FkIGVudiBmaWxlIGJhc2VkIG9uIGBtb2RlYCBpbiB0aGUgY3VycmVudCB3b3JraW5nIGRpcmVjdG9yeS5cbiAgY29uc3QgZW52ID0gbG9hZEVudihtb2RlLCBwcm9jZXNzLmN3ZCgpLCAnJylcbiAgY29uc3QgaXNEZXYgPSBtb2RlID09PSAnZGV2ZWxvcG1lbnQnXG4gIGNvbnN0IGRpc2FibGVQcmVyZW5kZXIgPSBpc0RldiB8fCBwcm9jZXNzLmVudi5ESVNBQkxFX1BSRVJFTkRFUiA9PT0gJzEnXG4gIGNvbnN0IHBvcnQgPSBOdW1iZXIoZW52LlZJVEVfUE9SVCB8fCBlbnYuUE9SVCB8fCBlbnYuVUlfREVWX1BPUlQgfHwgMzAwMClcbiAgXG4gIHJldHVybiB7XG4gICAgcmVzb2x2ZToge1xuICAgICAgZGVkdXBlOiBbJ3JlYWN0JywgJ3JlYWN0LWRvbScsICdyZWFjdC9qc3gtcnVudGltZScsICdyZWFjdC9qc3gtZGV2LXJ1bnRpbWUnXSxcbiAgICB9LFxuICAgIG9wdGltaXplRGVwczoge1xuICAgICAgaW5jbHVkZTogWydyZWFjdCcsICdyZWFjdC1kb20nLCAncmVhY3QvanN4LXJ1bnRpbWUnLCAncmVhY3QvanN4LWRldi1ydW50aW1lJywgJ3JlYWN0LXJvdXRlci1kb20nLCAnQG1hcnR5L2Jsb2cnXSxcbiAgICB9LFxuICAgIHBsdWdpbnM6IFtcbiAgICAgIHJlYWN0KCksXG4gICAgICAvLyBDaGVja2VyIHRlbXBvcmFyaWx5IGRpc2FibGVkIGZvciBkZWJ1Z2dpbmdcbiAgICAgIC8qXG4gICAgICAuLi4oaXNEZXYgPyBbY2hlY2tlcih7XG4gICAgICAgIHR5cGVzY3JpcHQ6IHRydWUsXG4gICAgICAgIGVzbGludDoge1xuICAgICAgICAgIGxpbnRDb21tYW5kOiAnZXNsaW50IC4gLS1leHQgLmpzLC5qc3gsLnRzLC50c3gnLFxuICAgICAgICB9LFxuICAgICAgICBvdmVybGF5OiB7XG4gICAgICAgICAgaW5pdGlhbElzT3BlbjogZmFsc2UsXG4gICAgICAgICAgcG9zaXRpb246ICdicicsXG4gICAgICAgIH0sXG4gICAgICB9KV0gOiBbXSksXG4gICAgICAqL1xuICAgICAgXG4gICAgICAvLyBQcmVyZW5kZXJpbmcgZm9yIFNFTyAtIG9ubHkgaW4gcHJvZHVjdGlvbiBidWlsZHNcbiAgICAgIC4uLighZGlzYWJsZVByZXJlbmRlciA/IFtcbiAgICAgICAgcHJlcmVuZGVyKHtcbiAgICAgICAgICByb3V0ZXM6IFtcbiAgICAgICAgICAgICcvJyxcbiAgICAgICAgICAgICcvcHJvZHVjdCcsXG4gICAgICAgICAgICAnL3ZlcmlmaWFibGUtY3JlZGVudGlhbC1hcGknLFxuICAgICAgICAgICAgJy9ldWRpLXdhbGxldC12ZXJpZmljYXRpb24nLFxuICAgICAgICAgICAgJy9pc28tMTgwMTMtNS1tZG9jLXZlcmlmaWNhdGlvbicsXG4gICAgICAgICAgICAnL3NkLWp3dC12ZXJpZmljYXRpb24nLFxuICAgICAgICAgICAgJy9vcGVuLWJhZGdlcy12ZXJpZmljYXRpb24nLFxuICAgICAgICAgICAgJy9vcGVuLWJhZGdlcy1pc3N1YW5jZScsXG4gICAgICAgICAgICAnL3RydXN0LXJlZ2lzdHJ5LWluZnJhc3RydWN0dXJlJyxcbiAgICAgICAgICAgICcvaWRlbnRpdHknLFxuICAgICAgICAgICAgJy9mcm9tLWlkdi10by12ZXJpZmlhYmxlLWlkZW50aXR5JyxcbiAgICAgICAgICAgICcvc3RhbmRhcmRzJyxcbiAgICAgICAgICAgICcvcHJvdG9jb2wnLFxuICAgICAgICAgICAgJy9ibG9nJyxcbiAgICAgICAgICAgICcvYmxvZy93aHktaWRlbnRpdHktbmVlZHMtYS1wcm90b2NvbCcsXG4gICAgICAgICAgICAnL2Jsb2cvdHJ1c3QtcHJvZmlsZXMtZXhwbGFpbmVkJyxcbiAgICAgICAgICAgICcvYmxvZy9idXNpbmVzcy1jYXNlLWZvci1jcmVkZW50aWFsLXBvcnRhYmlsaXR5JyxcbiAgICAgICAgICAgICcvYmxvZy9jcnlwdG9ncmFwaGljLXRydXN0LWFuY2hvcnMtcHJpbWVyJyxcbiAgICAgICAgICAgICcvYmxvZy9jcmVkZW50aWFsLXRlbXBsYXRlcy1kZXNpZ25pbmctd2hhdC1nZXRzLWlzc3VlZCcsXG4gICAgICAgICAgICAnL2Jsb2cvcHJlc2VudGF0aW9uLXBvbGljaWVzLW1pbmltdW0tZGlzY2xvc3VyZScsXG4gICAgICAgICAgICAnL2Jsb2cvZXVkaS13YWxsZXQtcmVhZGluZXNzJyxcbiAgICAgICAgICAgICcvYmxvZy9kZXBsb3ltZW50LXByb2ZpbGVzLWZyb20tZGVzaWduLXRvLXByb2R1Y3Rpb24nLFxuICAgICAgICAgICAgJy9ibG9nL3plcm8ta25vd2xlZGdlLXByZWRpY2F0ZXMtaWRlbnRpdHknLFxuICAgICAgICAgICAgJy9ibG9nL2Zsb3dzLW9yY2hlc3RyYXRpbmctaWRlbnRpdHktbGlmZWN5Y2xlJyxcbiAgICAgICAgICAgICcvYmxvZy9jb21wbGlhbmNlLXByb2ZpbGVzLWJyaWRnaW5nLXJlZ3VsYXRpb24nLFxuICAgICAgICAgICAgJy9ibG9nL3NkLWp3dC1zZWxlY3RpdmUtZGlzY2xvc3VyZS1kZWVwLWRpdmUnLFxuICAgICAgICAgICAgJy9ibG9nL2NlZGFyLXBvbGljaWVzLWZvci1pZGVudGl0eS1nb3Zlcm5hbmNlJyxcbiAgICAgICAgICAgICcvYmxvZy9pbnRyb2R1Y2luZy1taXAnLFxuICAgICAgICAgICAgJy9ibG9nL21pcC1qc29uLXNjaGVtYXMtd2Fsa3Rocm91Z2gnLFxuICAgICAgICAgICAgJy9ibG9nL3Bvc3QtcXVhbnR1bS1yZWFkaW5lc3MtaW4taWRlbnRpdHknLFxuICAgICAgICAgICAgJy9ibG9nL2J1aWxkaW5nLXRydXN0LXJlZ2lzdHJpZXMtYXQtc2NhbGUnLFxuICAgICAgICAgICAgJy9ibG9nL29mZmxpbmUtdmVyaWZpY2F0aW9uLWRlc2lnbi1wYXR0ZXJucycsXG4gICAgICAgICAgICAnL2Jsb2cvaG9sZGVyLWJpbmRpbmctYmV5b25kLWJpb21ldHJpY3MnLFxuICAgICAgICAgICAgJy9ibG9nL21pcC1hbmQtb3Blbi1iYWRnZXMtZWR1Y2F0aW9uLWNyZWRlbnRpYWxzJyxcbiAgICAgICAgICAgICcvYmxvZy9jb25mb3JtYW5jZS10ZXN0aW5nLWZvci1pbXBsZW1lbnRlcnMnLFxuICAgICAgICAgICAgJy9ibG9nL3Jldm9jYXRpb24tc3RyYXRlZ2llcy1jb21wYXJlZCcsXG4gICAgICAgICAgICAnL3ByaWNpbmcnLFxuICAgICAgICAgICAgJy9kb2NzJyxcbiAgICAgICAgICBdLFxuICAgICAgICAgIHJlbmRlcmVyOiBuZXcgUHVwcGV0ZWVyUmVuZGVyZXIoe1xuICAgICAgICAgICAgcmVuZGVyQWZ0ZXJUaW1lOiAzMDAwLCAvLyBXYWl0IGZvciBNVUkgQ1NTLWluLUpTIGh5ZHJhdGlvblxuICAgICAgICAgICAgaGVhZGxlc3M6IHRydWUsXG4gICAgICAgICAgfSksXG4gICAgICAgICAgcG9zdFByb2Nlc3Mocm91dGUpIHtcbiAgICAgICAgICAgIC8vIEFkZCBwcmVyZW5kZXIgc3RhdHVzIG1ldGEgdGFnXG4gICAgICAgICAgICByb3V0ZS5odG1sID0gcm91dGUuaHRtbC5yZXBsYWNlKFxuICAgICAgICAgICAgICAnPC9oZWFkPicsXG4gICAgICAgICAgICAgICc8bWV0YSBuYW1lPVwicHJlcmVuZGVyLXN0YXR1cy1jb2RlXCIgY29udGVudD1cIjIwMFwiIC8+PC9oZWFkPidcbiAgICAgICAgICAgICk7XG4gICAgICAgICAgfSxcbiAgICAgICAgfSksXG4gICAgICAgIFxuICAgICAgICAvLyBTaXRlbWFwIGdlbmVyYXRpb25cbiAgICAgICAgU2l0ZW1hcCh7XG4gICAgICAgICAgaG9zdG5hbWU6ICdodHRwczovL2VsZXZlbmlkbGxjLmNvbScsXG4gICAgICAgICAgZHluYW1pY1JvdXRlczogW1xuICAgICAgICAgICAgJy8nLFxuICAgICAgICAgICAgJy9wcm9kdWN0JyxcbiAgICAgICAgICAgICcvdmVyaWZpYWJsZS1jcmVkZW50aWFsLWFwaScsXG4gICAgICAgICAgICAnL2V1ZGktd2FsbGV0LXZlcmlmaWNhdGlvbicsXG4gICAgICAgICAgICAnL2lzby0xODAxMy01LW1kb2MtdmVyaWZpY2F0aW9uJyxcbiAgICAgICAgICAgICcvc2Qtand0LXZlcmlmaWNhdGlvbicsXG4gICAgICAgICAgICAnL29wZW4tYmFkZ2VzLXZlcmlmaWNhdGlvbicsXG4gICAgICAgICAgICAnL29wZW4tYmFkZ2VzLWlzc3VhbmNlJyxcbiAgICAgICAgICAgICcvdHJ1c3QtcmVnaXN0cnktaW5mcmFzdHJ1Y3R1cmUnLFxuICAgICAgICAgICAgJy9pZGVudGl0eScsXG4gICAgICAgICAgICAnL2Zyb20taWR2LXRvLXZlcmlmaWFibGUtaWRlbnRpdHknLFxuICAgICAgICAgICAgJy9zdGFuZGFyZHMnLFxuICAgICAgICAgICAgJy9wcm90b2NvbCcsXG4gICAgICAgICAgICAnL2Jsb2cnLFxuICAgICAgICAgICAgJy9ibG9nL3doeS1pZGVudGl0eS1uZWVkcy1hLXByb3RvY29sJyxcbiAgICAgICAgICAgICcvYmxvZy90cnVzdC1wcm9maWxlcy1leHBsYWluZWQnLFxuICAgICAgICAgICAgJy9ibG9nL2J1c2luZXNzLWNhc2UtZm9yLWNyZWRlbnRpYWwtcG9ydGFiaWxpdHknLFxuICAgICAgICAgICAgJy9ibG9nL2NyeXB0b2dyYXBoaWMtdHJ1c3QtYW5jaG9ycy1wcmltZXInLFxuICAgICAgICAgICAgJy9ibG9nL2NyZWRlbnRpYWwtdGVtcGxhdGVzLWRlc2lnbmluZy13aGF0LWdldHMtaXNzdWVkJyxcbiAgICAgICAgICAgICcvYmxvZy9wcmVzZW50YXRpb24tcG9saWNpZXMtbWluaW11bS1kaXNjbG9zdXJlJyxcbiAgICAgICAgICAgICcvYmxvZy9ldWRpLXdhbGxldC1yZWFkaW5lc3MnLFxuICAgICAgICAgICAgJy9ibG9nL2RlcGxveW1lbnQtcHJvZmlsZXMtZnJvbS1kZXNpZ24tdG8tcHJvZHVjdGlvbicsXG4gICAgICAgICAgICAnL2Jsb2cvemVyby1rbm93bGVkZ2UtcHJlZGljYXRlcy1pZGVudGl0eScsXG4gICAgICAgICAgICAnL2Jsb2cvZmxvd3Mtb3JjaGVzdHJhdGluZy1pZGVudGl0eS1saWZlY3ljbGUnLFxuICAgICAgICAgICAgJy9ibG9nL2NvbXBsaWFuY2UtcHJvZmlsZXMtYnJpZGdpbmctcmVndWxhdGlvbicsXG4gICAgICAgICAgICAnL2Jsb2cvc2Qtand0LXNlbGVjdGl2ZS1kaXNjbG9zdXJlLWRlZXAtZGl2ZScsXG4gICAgICAgICAgICAnL2Jsb2cvY2VkYXItcG9saWNpZXMtZm9yLWlkZW50aXR5LWdvdmVybmFuY2UnLFxuICAgICAgICAgICAgJy9ibG9nL2ludHJvZHVjaW5nLW1pcCcsXG4gICAgICAgICAgICAnL2Jsb2cvbWlwLWpzb24tc2NoZW1hcy13YWxrdGhyb3VnaCcsXG4gICAgICAgICAgICAnL2Jsb2cvcG9zdC1xdWFudHVtLXJlYWRpbmVzcy1pbi1pZGVudGl0eScsXG4gICAgICAgICAgICAnL2Jsb2cvYnVpbGRpbmctdHJ1c3QtcmVnaXN0cmllcy1hdC1zY2FsZScsXG4gICAgICAgICAgICAnL2Jsb2cvb2ZmbGluZS12ZXJpZmljYXRpb24tZGVzaWduLXBhdHRlcm5zJyxcbiAgICAgICAgICAgICcvYmxvZy9ob2xkZXItYmluZGluZy1iZXlvbmQtYmlvbWV0cmljcycsXG4gICAgICAgICAgICAnL2Jsb2cvbWlwLWFuZC1vcGVuLWJhZGdlcy1lZHVjYXRpb24tY3JlZGVudGlhbHMnLFxuICAgICAgICAgICAgJy9ibG9nL2NvbmZvcm1hbmNlLXRlc3RpbmctZm9yLWltcGxlbWVudGVycycsXG4gICAgICAgICAgICAnL2Jsb2cvcmV2b2NhdGlvbi1zdHJhdGVnaWVzLWNvbXBhcmVkJyxcbiAgICAgICAgICAgICcvcHJpY2luZycsXG4gICAgICAgICAgICAnL2RvY3MnLFxuICAgICAgICAgIF0sXG4gICAgICAgICAgZXhjbHVkZTogW1xuICAgICAgICAgICAgJy9jb25zb2xlJyxcbiAgICAgICAgICAgICcvY29uc29sZS8qJyxcbiAgICAgICAgICAgICcvYXBwbGljYW50JyxcbiAgICAgICAgICAgICcvYXBwbGljYW50LyonLFxuICAgICAgICAgICAgJy9hZG1pbicsXG4gICAgICAgICAgICAnL2FkbWluLyonLFxuICAgICAgICAgICAgJy92ZW5kb3InLFxuICAgICAgICAgICAgJy92ZW5kb3IvKicsXG4gICAgICAgICAgICAnL2Rhc2hib2FyZCcsXG4gICAgICAgICAgICAnL2xvZ2luJyxcbiAgICAgICAgICAgICcvYXV0aC8qJyxcbiAgICAgICAgICBdLFxuICAgICAgICAgIGNoYW5nZWZyZXE6ICd3ZWVrbHknLFxuICAgICAgICAgIHByaW9yaXR5OiB7XG4gICAgICAgICAgICAnLyc6IDEuMCxcbiAgICAgICAgICAgICcvcHJvZHVjdCc6IDAuOSxcbiAgICAgICAgICAgICcvcHJpY2luZyc6IDAuOSxcbiAgICAgICAgICAgICcvc3RhbmRhcmRzJzogMC44LFxuICAgICAgICAgICAgJy9kb2NzJzogMC44LFxuICAgICAgICAgICAgJyonOiAwLjcsXG4gICAgICAgICAgfSxcbiAgICAgICAgICBnZW5lcmF0ZVJvYm90c1R4dDogdHJ1ZSxcbiAgICAgICAgICByb2JvdHM6IFtcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgdXNlckFnZW50OiAnKicsXG4gICAgICAgICAgICAgIGFsbG93OiAnLycsXG4gICAgICAgICAgICAgIGRpc2FsbG93OiBbXG4gICAgICAgICAgICAgICAgJy9jb25zb2xlJyxcbiAgICAgICAgICAgICAgICAnL2NvbnNvbGUvKicsXG4gICAgICAgICAgICAgICAgJy9hcHBsaWNhbnQnLFxuICAgICAgICAgICAgICAgICcvYXBwbGljYW50LyonLFxuICAgICAgICAgICAgICAgICcvYWRtaW4nLFxuICAgICAgICAgICAgICAgICcvYWRtaW4vKicsXG4gICAgICAgICAgICAgICAgJy92ZW5kb3InLFxuICAgICAgICAgICAgICAgICcvdmVuZG9yLyonLFxuICAgICAgICAgICAgICAgICcvZGFzaGJvYXJkJyxcbiAgICAgICAgICAgICAgICAnL2F1dGgvKicsXG4gICAgICAgICAgICAgICAgJy9hcGkvKicsXG4gICAgICAgICAgICAgICAgJy92MS8qJyxcbiAgICAgICAgICAgICAgXSxcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgXSxcbiAgICAgICAgfSksXG4gICAgICBdIDogW10pLFxuICAgIF0sXG4gICAgc2VydmVyOiB7XG4gICAgICBwb3J0OiBwb3J0LFxuICAgICAgaG9zdDogJzAuMC4wLjAnLCAvLyBMaXN0ZW4gb24gYWxsIG5ldHdvcmsgaW50ZXJmYWNlc1xuICAgICAgc3RyaWN0UG9ydDogZmFsc2UsXG4gICAgICBjb3JzOiB0cnVlLFxuICAgICAgYWxsb3dlZEhvc3RzOiBlbnYuUFVCTElDX0RPTUFJTiA/IFtlbnYuUFVCTElDX0RPTUFJTiwgJ2xvY2FsaG9zdCddIDogJ2FsbCcsXG4gICAgICBoZWFkZXJzOiB7XG4gICAgICAgICdDYWNoZS1Db250cm9sJzogJ25vLXN0b3JlJyxcbiAgICAgIH0sXG4gICAgICAvLyBXaGVuIGFjY2Vzc2VkIHZpYSBhIHB1YmxpYyB0dW5uZWwgZG9tYWluLCB0aGUgYnJvd3NlciBtdXN0IGNvbm5lY3RcbiAgICAgIC8vIHRoZSBITVIgV2ViU29ja2V0IHRvIHRoZSBwdWJsaWMgaG9zdCB2aWEgd3NzOi8vIG9uIHBvcnQgNDQzLlxuICAgICAgLy8gV2l0aG91dCB0aGlzLCBWaXRlIHRyaWVzIHdzOi8vbG9jYWxob3N0OjMwMDAgd2hpY2ggZmFpbHMgY3Jvc3Mtb3JpZ2luLlxuICAgICAgLi4uKGVudi5QVUJMSUNfRE9NQUlOID8ge1xuICAgICAgICBobXI6IHtcbiAgICAgICAgICBwcm90b2NvbDogJ3dzcycsXG4gICAgICAgICAgaG9zdDogZW52LlBVQkxJQ19ET01BSU4sXG4gICAgICAgICAgY2xpZW50UG9ydDogNDQzLFxuICAgICAgICB9LFxuICAgICAgfSA6IHt9KSxcbiAgICAgIHByb3h5OiB7XG4gICAgICAgIC8vIFByb3h5IC92MS8qIEFQSSByZXF1ZXN0cyB0byBtaWNyb3NlcnZpY2VzIGdhdGV3YXlcbiAgICAgICAgJy92MSc6IHtcbiAgICAgICAgICB0YXJnZXQ6IGVudi5WSVRFX0FQSV9VUkwgfHwgJ2h0dHA6Ly8xMjcuMC4wLjE6ODAwMCcsXG4gICAgICAgICAgY2hhbmdlT3JpZ2luOiB0cnVlLFxuICAgICAgICAgIHNlY3VyZTogZmFsc2UsXG4gICAgICAgICAgd3M6IHRydWUsXG4gICAgICAgIH0sXG4gICAgICAgIC8vIFByb3h5IC9hdXRoLyogcmVxdWVzdHMgdG8gdGhlIGJhY2tlbmQgKE9JREMgZmxvd3MpXG4gICAgICAgICcvYXV0aCc6IHtcbiAgICAgICAgICB0YXJnZXQ6IGVudi5WSVRFX0FQSV9VUkwgfHwgJ2h0dHA6Ly8xMjcuMC4wLjE6ODAwMCcsXG4gICAgICAgICAgY2hhbmdlT3JpZ2luOiB0cnVlLFxuICAgICAgICAgIHNlY3VyZTogZmFsc2UsXG4gICAgICAgICAgd3M6IHRydWUsXG4gICAgICAgIH0sXG4gICAgICAgIC8vIExlZ2FjeSAvYXBpLyogcHJveHkgKGZvciBiYWNrd2FyZHMgY29tcGF0aWJpbGl0eSBkdXJpbmcgdHJhbnNpdGlvbilcbiAgICAgICAgJy9hcGknOiB7XG4gICAgICAgICAgdGFyZ2V0OiBlbnYuVklURV9BUElfVVJMIHx8ICdodHRwOi8vMTI3LjAuMC4xOjgwMDAnLFxuICAgICAgICAgIGNoYW5nZU9yaWdpbjogdHJ1ZSxcbiAgICAgICAgICBzZWN1cmU6IGZhbHNlLFxuICAgICAgICAgIHdzOiB0cnVlLFxuICAgICAgICB9LFxuICAgICAgICAvLyBQcm94eSBoZWFsdGggY2hlY2tcbiAgICAgICAgJy9oZWFsdGgnOiB7XG4gICAgICAgICAgdGFyZ2V0OiBlbnYuVklURV9BUElfVVJMIHx8ICdodHRwOi8vMTI3LjAuMC4xOjgwMDAnLFxuICAgICAgICAgIGNoYW5nZU9yaWdpbjogdHJ1ZSxcbiAgICAgICAgICBzZWN1cmU6IGZhbHNlLFxuICAgICAgICB9LFxuICAgICAgICAvLyBQcm94eSBPcGVuQVBJIHNjaGVtYSBmb3IgQVBJIGRvY3VtZW50YXRpb25cbiAgICAgICAgJy9vcGVuYXBpLmpzb24nOiB7XG4gICAgICAgICAgdGFyZ2V0OiBlbnYuVklURV9BUElfVVJMIHx8ICdodHRwOi8vMTI3LjAuMC4xOjgwMDAnLFxuICAgICAgICAgIGNoYW5nZU9yaWdpbjogdHJ1ZSxcbiAgICAgICAgICBzZWN1cmU6IGZhbHNlLFxuICAgICAgICB9LFxuICAgICAgfSxcbiAgICB9LFxuICAgIGJ1aWxkOiB7XG4gICAgICBvdXREaXI6ICdkaXN0JyxcbiAgICAgIHNvdXJjZW1hcDogdHJ1ZSxcbiAgICAgIGNodW5rU2l6ZVdhcm5pbmdMaW1pdDogMTAwMCwgLy8gSW5jcmVhc2UgZnJvbSBkZWZhdWx0IDUwMGtCIHRvIDEwMDBrQlxuICAgICAgcm9sbHVwT3B0aW9uczoge1xuICAgICAgICBvdXRwdXQ6IHtcbiAgICAgICAgICBtYW51YWxDaHVua3M6IHtcbiAgICAgICAgICAgICdyZWFjdC12ZW5kb3InOiBbJ3JlYWN0JywgJ3JlYWN0LWRvbScsICdyZWFjdC1yb3V0ZXItZG9tJ10sXG4gICAgICAgICAgICAnbXVpLXZlbmRvcic6IFsnQG11aS9tYXRlcmlhbCcsICdAbXVpL2ljb25zLW1hdGVyaWFsJywgJ0BtdWkveC1kYXRlLXBpY2tlcnMnXSxcbiAgICAgICAgICAgICdjaGFydC12ZW5kb3InOiBbJ3JlY2hhcnRzJ10sXG4gICAgICAgICAgfSxcbiAgICAgICAgfSxcbiAgICAgIH0sXG4gICAgfSxcbiAgfVxufSlcbiJdLAogICJtYXBwaW5ncyI6ICI7QUFBZ1UsU0FBUyxjQUFjLGVBQWU7QUFDdFcsT0FBTyxXQUFXO0FBRWxCLE9BQU8sZUFBZTtBQUN0QixPQUFPLHVCQUF1QjtBQUM5QixPQUFPLGFBQWE7QUFHcEIsSUFBTyxzQkFBUSxhQUFhLENBQUMsRUFBRSxLQUFLLE1BQU07QUFFeEMsUUFBTSxNQUFNLFFBQVEsTUFBTSxRQUFRLElBQUksR0FBRyxFQUFFO0FBQzNDLFFBQU0sUUFBUSxTQUFTO0FBQ3ZCLFFBQU0sbUJBQW1CLFNBQVMsUUFBUSxJQUFJLHNCQUFzQjtBQUNwRSxRQUFNLE9BQU8sT0FBTyxJQUFJLGFBQWEsSUFBSSxRQUFRLElBQUksZUFBZSxHQUFJO0FBRXhFLFNBQU87QUFBQSxJQUNMLFNBQVM7QUFBQSxNQUNQLFFBQVEsQ0FBQyxTQUFTLGFBQWEscUJBQXFCLHVCQUF1QjtBQUFBLElBQzdFO0FBQUEs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

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
      include: ["react", "react-dom", "react/jsx-runtime", "react/jsx-dev-runtime", "react-router-dom"]
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
//# sourceMappingURL=data:application/json;base64,ewogICJ2ZXJzaW9uIjogMywKICAic291cmNlcyI6IFsidml0ZS5jb25maWcudHMiXSwKICAic291cmNlc0NvbnRlbnQiOiBbImNvbnN0IF9fdml0ZV9pbmplY3RlZF9vcmlnaW5hbF9kaXJuYW1lID0gXCIvVm9sdW1lcy9IZWFydCBvZiBHb2xkL0dpdGh1Yi93b3JrL21hcnR5LXVpL3VpXCI7Y29uc3QgX192aXRlX2luamVjdGVkX29yaWdpbmFsX2ZpbGVuYW1lID0gXCIvVm9sdW1lcy9IZWFydCBvZiBHb2xkL0dpdGh1Yi93b3JrL21hcnR5LXVpL3VpL3ZpdGUuY29uZmlnLnRzXCI7Y29uc3QgX192aXRlX2luamVjdGVkX29yaWdpbmFsX2ltcG9ydF9tZXRhX3VybCA9IFwiZmlsZTovLy9Wb2x1bWVzL0hlYXJ0JTIwb2YlMjBHb2xkL0dpdGh1Yi93b3JrL21hcnR5LXVpL3VpL3ZpdGUuY29uZmlnLnRzXCI7aW1wb3J0IHsgZGVmaW5lQ29uZmlnLCBsb2FkRW52IH0gZnJvbSAndml0ZSdcbmltcG9ydCByZWFjdCBmcm9tICdAdml0ZWpzL3BsdWdpbi1yZWFjdCdcbmltcG9ydCBjaGVja2VyIGZyb20gJ3ZpdGUtcGx1Z2luLWNoZWNrZXInXG5pbXBvcnQgcHJlcmVuZGVyIGZyb20gJ0BwcmVyZW5kZXJlci9yb2xsdXAtcGx1Z2luJ1xuaW1wb3J0IFB1cHBldGVlclJlbmRlcmVyIGZyb20gJ0BwcmVyZW5kZXJlci9yZW5kZXJlci1wdXBwZXRlZXInXG5pbXBvcnQgU2l0ZW1hcCBmcm9tICd2aXRlLXBsdWdpbi1zaXRlbWFwJ1xuXG4vLyBodHRwczovL3ZpdGVqcy5kZXYvY29uZmlnL1xuZXhwb3J0IGRlZmF1bHQgZGVmaW5lQ29uZmlnKCh7IG1vZGUgfSkgPT4ge1xuICAvLyBMb2FkIGVudiBmaWxlIGJhc2VkIG9uIGBtb2RlYCBpbiB0aGUgY3VycmVudCB3b3JraW5nIGRpcmVjdG9yeS5cbiAgY29uc3QgZW52ID0gbG9hZEVudihtb2RlLCBwcm9jZXNzLmN3ZCgpLCAnJylcbiAgY29uc3QgaXNEZXYgPSBtb2RlID09PSAnZGV2ZWxvcG1lbnQnXG4gIGNvbnN0IGRpc2FibGVQcmVyZW5kZXIgPSBpc0RldiB8fCBwcm9jZXNzLmVudi5ESVNBQkxFX1BSRVJFTkRFUiA9PT0gJzEnXG4gIGNvbnN0IHBvcnQgPSBOdW1iZXIoZW52LlZJVEVfUE9SVCB8fCBlbnYuUE9SVCB8fCBlbnYuVUlfREVWX1BPUlQgfHwgMzAwMClcbiAgXG4gIHJldHVybiB7XG4gICAgcmVzb2x2ZToge1xuICAgICAgZGVkdXBlOiBbJ3JlYWN0JywgJ3JlYWN0LWRvbScsICdyZWFjdC9qc3gtcnVudGltZScsICdyZWFjdC9qc3gtZGV2LXJ1bnRpbWUnXSxcbiAgICB9LFxuICAgIG9wdGltaXplRGVwczoge1xuICAgICAgaW5jbHVkZTogWydyZWFjdCcsICdyZWFjdC1kb20nLCAncmVhY3QvanN4LXJ1bnRpbWUnLCAncmVhY3QvanN4LWRldi1ydW50aW1lJywgJ3JlYWN0LXJvdXRlci1kb20nXSxcbiAgICB9LFxuICAgIHBsdWdpbnM6IFtcbiAgICAgIHJlYWN0KCksXG4gICAgICAvLyBDaGVja2VyIHRlbXBvcmFyaWx5IGRpc2FibGVkIGZvciBkZWJ1Z2dpbmdcbiAgICAgIC8qXG4gICAgICAuLi4oaXNEZXYgPyBbY2hlY2tlcih7XG4gICAgICAgIHR5cGVzY3JpcHQ6IHRydWUsXG4gICAgICAgIGVzbGludDoge1xuICAgICAgICAgIGxpbnRDb21tYW5kOiAnZXNsaW50IC4gLS1leHQgLmpzLC5qc3gsLnRzLC50c3gnLFxuICAgICAgICB9LFxuICAgICAgICBvdmVybGF5OiB7XG4gICAgICAgICAgaW5pdGlhbElzT3BlbjogZmFsc2UsXG4gICAgICAgICAgcG9zaXRpb246ICdicicsXG4gICAgICAgIH0sXG4gICAgICB9KV0gOiBbXSksXG4gICAgICAqL1xuICAgICAgXG4gICAgICAvLyBQcmVyZW5kZXJpbmcgZm9yIFNFTyAtIG9ubHkgaW4gcHJvZHVjdGlvbiBidWlsZHNcbiAgICAgIC4uLighZGlzYWJsZVByZXJlbmRlciA/IFtcbiAgICAgICAgcHJlcmVuZGVyKHtcbiAgICAgICAgICByb3V0ZXM6IFtcbiAgICAgICAgICAgICcvJyxcbiAgICAgICAgICAgICcvcHJvZHVjdCcsXG4gICAgICAgICAgICAnL3ZlcmlmaWFibGUtY3JlZGVudGlhbC1hcGknLFxuICAgICAgICAgICAgJy9ldWRpLXdhbGxldC12ZXJpZmljYXRpb24nLFxuICAgICAgICAgICAgJy9pc28tMTgwMTMtNS1tZG9jLXZlcmlmaWNhdGlvbicsXG4gICAgICAgICAgICAnL3NkLWp3dC12ZXJpZmljYXRpb24nLFxuICAgICAgICAgICAgJy9vcGVuLWJhZGdlcy12ZXJpZmljYXRpb24nLFxuICAgICAgICAgICAgJy9vcGVuLWJhZGdlcy1pc3N1YW5jZScsXG4gICAgICAgICAgICAnL3RydXN0LXJlZ2lzdHJ5LWluZnJhc3RydWN0dXJlJyxcbiAgICAgICAgICAgICcvaWRlbnRpdHknLFxuICAgICAgICAgICAgJy9mcm9tLWlkdi10by12ZXJpZmlhYmxlLWlkZW50aXR5JyxcbiAgICAgICAgICAgICcvc3RhbmRhcmRzJyxcbiAgICAgICAgICAgICcvcHJpY2luZycsXG4gICAgICAgICAgICAnL2RvY3MnLFxuICAgICAgICAgIF0sXG4gICAgICAgICAgcmVuZGVyZXI6IG5ldyBQdXBwZXRlZXJSZW5kZXJlcih7XG4gICAgICAgICAgICByZW5kZXJBZnRlclRpbWU6IDMwMDAsIC8vIFdhaXQgZm9yIE1VSSBDU1MtaW4tSlMgaHlkcmF0aW9uXG4gICAgICAgICAgICBoZWFkbGVzczogdHJ1ZSxcbiAgICAgICAgICB9KSxcbiAgICAgICAgICBwb3N0UHJvY2Vzcyhyb3V0ZSkge1xuICAgICAgICAgICAgLy8gQWRkIHByZXJlbmRlciBzdGF0dXMgbWV0YSB0YWdcbiAgICAgICAgICAgIHJvdXRlLmh0bWwgPSByb3V0ZS5odG1sLnJlcGxhY2UoXG4gICAgICAgICAgICAgICc8L2hlYWQ+JyxcbiAgICAgICAgICAgICAgJzxtZXRhIG5hbWU9XCJwcmVyZW5kZXItc3RhdHVzLWNvZGVcIiBjb250ZW50PVwiMjAwXCIgLz48L2hlYWQ+J1xuICAgICAgICAgICAgKTtcbiAgICAgICAgICB9LFxuICAgICAgICB9KSxcbiAgICAgICAgXG4gICAgICAgIC8vIFNpdGVtYXAgZ2VuZXJhdGlvblxuICAgICAgICBTaXRlbWFwKHtcbiAgICAgICAgICBob3N0bmFtZTogJ2h0dHBzOi8vZWxldmVuaWRsbGMuY29tJyxcbiAgICAgICAgICBkeW5hbWljUm91dGVzOiBbXG4gICAgICAgICAgICAnLycsXG4gICAgICAgICAgICAnL3Byb2R1Y3QnLFxuICAgICAgICAgICAgJy92ZXJpZmlhYmxlLWNyZWRlbnRpYWwtYXBpJyxcbiAgICAgICAgICAgICcvZXVkaS13YWxsZXQtdmVyaWZpY2F0aW9uJyxcbiAgICAgICAgICAgICcvaXNvLTE4MDEzLTUtbWRvYy12ZXJpZmljYXRpb24nLFxuICAgICAgICAgICAgJy9zZC1qd3QtdmVyaWZpY2F0aW9uJyxcbiAgICAgICAgICAgICcvb3Blbi1iYWRnZXMtdmVyaWZpY2F0aW9uJyxcbiAgICAgICAgICAgICcvb3Blbi1iYWRnZXMtaXNzdWFuY2UnLFxuICAgICAgICAgICAgJy90cnVzdC1yZWdpc3RyeS1pbmZyYXN0cnVjdHVyZScsXG4gICAgICAgICAgICAnL2lkZW50aXR5JyxcbiAgICAgICAgICAgICcvZnJvbS1pZHYtdG8tdmVyaWZpYWJsZS1pZGVudGl0eScsXG4gICAgICAgICAgICAnL3N0YW5kYXJkcycsXG4gICAgICAgICAgICAnL3ByaWNpbmcnLFxuICAgICAgICAgICAgJy9kb2NzJyxcbiAgICAgICAgICBdLFxuICAgICAgICAgIGV4Y2x1ZGU6IFtcbiAgICAgICAgICAgICcvY29uc29sZScsXG4gICAgICAgICAgICAnL2NvbnNvbGUvKicsXG4gICAgICAgICAgICAnL2FwcGxpY2FudCcsXG4gICAgICAgICAgICAnL2FwcGxpY2FudC8qJyxcbiAgICAgICAgICAgICcvYWRtaW4nLFxuICAgICAgICAgICAgJy9hZG1pbi8qJyxcbiAgICAgICAgICAgICcvdmVuZG9yJyxcbiAgICAgICAgICAgICcvdmVuZG9yLyonLFxuICAgICAgICAgICAgJy9kYXNoYm9hcmQnLFxuICAgICAgICAgICAgJy9sb2dpbicsXG4gICAgICAgICAgICAnL2F1dGgvKicsXG4gICAgICAgICAgXSxcbiAgICAgICAgICBjaGFuZ2VmcmVxOiAnd2Vla2x5JyxcbiAgICAgICAgICBwcmlvcml0eToge1xuICAgICAgICAgICAgJy8nOiAxLjAsXG4gICAgICAgICAgICAnL3Byb2R1Y3QnOiAwLjksXG4gICAgICAgICAgICAnL3ByaWNpbmcnOiAwLjksXG4gICAgICAgICAgICAnL3N0YW5kYXJkcyc6IDAuOCxcbiAgICAgICAgICAgICcvZG9jcyc6IDAuOCxcbiAgICAgICAgICAgICcqJzogMC43LFxuICAgICAgICAgIH0sXG4gICAgICAgICAgZ2VuZXJhdGVSb2JvdHNUeHQ6IHRydWUsXG4gICAgICAgICAgcm9ib3RzOiBbXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgIHVzZXJBZ2VudDogJyonLFxuICAgICAgICAgICAgICBhbGxvdzogJy8nLFxuICAgICAgICAgICAgICBkaXNhbGxvdzogW1xuICAgICAgICAgICAgICAgICcvY29uc29sZScsXG4gICAgICAgICAgICAgICAgJy9jb25zb2xlLyonLFxuICAgICAgICAgICAgICAgICcvYXBwbGljYW50JyxcbiAgICAgICAgICAgICAgICAnL2FwcGxpY2FudC8qJyxcbiAgICAgICAgICAgICAgICAnL2FkbWluJyxcbiAgICAgICAgICAgICAgICAnL2FkbWluLyonLFxuICAgICAgICAgICAgICAgICcvdmVuZG9yJyxcbiAgICAgICAgICAgICAgICAnL3ZlbmRvci8qJyxcbiAgICAgICAgICAgICAgICAnL2Rhc2hib2FyZCcsXG4gICAgICAgICAgICAgICAgJy9hdXRoLyonLFxuICAgICAgICAgICAgICAgICcvYXBpLyonLFxuICAgICAgICAgICAgICAgICcvdjEvKicsXG4gICAgICAgICAgICAgIF0sXG4gICAgICAgICAgICB9LFxuICAgICAgICAgIF0sXG4gICAgICAgIH0pLFxuICAgICAgXSA6IFtdKSxcbiAgICBdLFxuICAgIHNlcnZlcjoge1xuICAgICAgcG9ydDogcG9ydCxcbiAgICAgIGhvc3Q6ICcwLjAuMC4wJywgLy8gTGlzdGVuIG9uIGFsbCBuZXR3b3JrIGludGVyZmFjZXNcbiAgICAgIHN0cmljdFBvcnQ6IGZhbHNlLFxuICAgICAgY29yczogdHJ1ZSxcbiAgICAgIGFsbG93ZWRIb3N0czogZW52LlBVQkxJQ19ET01BSU4gPyBbZW52LlBVQkxJQ19ET01BSU4sICdsb2NhbGhvc3QnXSA6ICdhbGwnLFxuICAgICAgaGVhZGVyczoge1xuICAgICAgICAnQ2FjaGUtQ29udHJvbCc6ICduby1zdG9yZScsXG4gICAgICB9LFxuICAgICAgLy8gV2hlbiBhY2Nlc3NlZCB2aWEgYSBwdWJsaWMgdHVubmVsIGRvbWFpbiwgdGhlIGJyb3dzZXIgbXVzdCBjb25uZWN0XG4gICAgICAvLyB0aGUgSE1SIFdlYlNvY2tldCB0byB0aGUgcHVibGljIGhvc3QgdmlhIHdzczovLyBvbiBwb3J0IDQ0My5cbiAgICAgIC8vIFdpdGhvdXQgdGhpcywgVml0ZSB0cmllcyB3czovL2xvY2FsaG9zdDozMDAwIHdoaWNoIGZhaWxzIGNyb3NzLW9yaWdpbi5cbiAgICAgIC4uLihlbnYuUFVCTElDX0RPTUFJTiA/IHtcbiAgICAgICAgaG1yOiB7XG4gICAgICAgICAgcHJvdG9jb2w6ICd3c3MnLFxuICAgICAgICAgIGhvc3Q6IGVudi5QVUJMSUNfRE9NQUlOLFxuICAgICAgICAgIGNsaWVudFBvcnQ6IDQ0MyxcbiAgICAgICAgfSxcbiAgICAgIH0gOiB7fSksXG4gICAgICBwcm94eToge1xuICAgICAgICAvLyBQcm94eSAvdjEvKiBBUEkgcmVxdWVzdHMgdG8gbWljcm9zZXJ2aWNlcyBnYXRld2F5XG4gICAgICAgICcvdjEnOiB7XG4gICAgICAgICAgdGFyZ2V0OiBlbnYuVklURV9BUElfVVJMIHx8ICdodHRwOi8vMTI3LjAuMC4xOjgwMDAnLFxuICAgICAgICAgIGNoYW5nZU9yaWdpbjogdHJ1ZSxcbiAgICAgICAgICBzZWN1cmU6IGZhbHNlLFxuICAgICAgICAgIHdzOiB0cnVlLFxuICAgICAgICB9LFxuICAgICAgICAvLyBQcm94eSAvYXV0aC8qIHJlcXVlc3RzIHRvIHRoZSBiYWNrZW5kIChPSURDIGZsb3dzKVxuICAgICAgICAnL2F1dGgnOiB7XG4gICAgICAgICAgdGFyZ2V0OiBlbnYuVklURV9BUElfVVJMIHx8ICdodHRwOi8vMTI3LjAuMC4xOjgwMDAnLFxuICAgICAgICAgIGNoYW5nZU9yaWdpbjogdHJ1ZSxcbiAgICAgICAgICBzZWN1cmU6IGZhbHNlLFxuICAgICAgICAgIHdzOiB0cnVlLFxuICAgICAgICB9LFxuICAgICAgICAvLyBMZWdhY3kgL2FwaS8qIHByb3h5IChmb3IgYmFja3dhcmRzIGNvbXBhdGliaWxpdHkgZHVyaW5nIHRyYW5zaXRpb24pXG4gICAgICAgICcvYXBpJzoge1xuICAgICAgICAgIHRhcmdldDogZW52LlZJVEVfQVBJX1VSTCB8fCAnaHR0cDovLzEyNy4wLjAuMTo4MDAwJyxcbiAgICAgICAgICBjaGFuZ2VPcmlnaW46IHRydWUsXG4gICAgICAgICAgc2VjdXJlOiBmYWxzZSxcbiAgICAgICAgICB3czogdHJ1ZSxcbiAgICAgICAgfSxcbiAgICAgICAgLy8gUHJveHkgaGVhbHRoIGNoZWNrXG4gICAgICAgICcvaGVhbHRoJzoge1xuICAgICAgICAgIHRhcmdldDogZW52LlZJVEVfQVBJX1VSTCB8fCAnaHR0cDovLzEyNy4wLjAuMTo4MDAwJyxcbiAgICAgICAgICBjaGFuZ2VPcmlnaW46IHRydWUsXG4gICAgICAgICAgc2VjdXJlOiBmYWxzZSxcbiAgICAgICAgfSxcbiAgICAgICAgLy8gUHJveHkgT3BlbkFQSSBzY2hlbWEgZm9yIEFQSSBkb2N1bWVudGF0aW9uXG4gICAgICAgICcvb3BlbmFwaS5qc29uJzoge1xuICAgICAgICAgIHRhcmdldDogZW52LlZJVEVfQVBJX1VSTCB8fCAnaHR0cDovLzEyNy4wLjAuMTo4MDAwJyxcbiAgICAgICAgICBjaGFuZ2VPcmlnaW46IHRydWUsXG4gICAgICAgICAgc2VjdXJlOiBmYWxzZSxcbiAgICAgICAgfSxcbiAgICAgIH0sXG4gICAgfSxcbiAgICBidWlsZDoge1xuICAgICAgb3V0RGlyOiAnZGlzdCcsXG4gICAgICBzb3VyY2VtYXA6IHRydWUsXG4gICAgICBjaHVua1NpemVXYXJuaW5nTGltaXQ6IDEwMDAsIC8vIEluY3JlYXNlIGZyb20gZGVmYXVsdCA1MDBrQiB0byAxMDAwa0JcbiAgICAgIHJvbGx1cE9wdGlvbnM6IHtcbiAgICAgICAgb3V0cHV0OiB7XG4gICAgICAgICAgbWFudWFsQ2h1bmtzOiB7XG4gICAgICAgICAgICAncmVhY3QtdmVuZG9yJzogWydyZWFjdCcsICdyZWFjdC1kb20nLCAncmVhY3Qtcm91dGVyLWRvbSddLFxuICAgICAgICAgICAgJ211aS12ZW5kb3InOiBbJ0BtdWkvbWF0ZXJpYWwnLCAnQG11aS9pY29ucy1tYXRlcmlhbCcsICdAbXVpL3gtZGF0ZS1waWNrZXJzJ10sXG4gICAgICAgICAgICAnY2hhcnQtdmVuZG9yJzogWydyZWNoYXJ0cyddLFxuICAgICAgICAgIH0sXG4gICAgICAgIH0sXG4gICAgICB9LFxuICAgIH0sXG4gIH1cbn0pXG4iXSwKICAibWFwcGluZ3MiOiAiO0FBQWdVLFNBQVMsY0FBYyxlQUFlO0FBQ3RXLE9BQU8sV0FBVztBQUVsQixPQUFPLGVBQWU7QUFDdEIsT0FBTyx1QkFBdUI7QUFDOUIsT0FBTyxhQUFhO0FBR3BCLElBQU8sc0JBQVEsYUFBYSxDQUFDLEVBQUUsS0FBSyxNQUFNO0FBRXhDLFFBQU0sTUFBTSxRQUFRLE1BQU0sUUFBUSxJQUFJLEdBQUcsRUFBRTtBQUMzQyxRQUFNLFFBQVEsU0FBUztBQUN2QixRQUFNLG1CQUFtQixTQUFTLFFBQVEsSUFBSSxzQkFBc0I7QUFDcEUsUUFBTSxPQUFPLE9BQU8sSUFBSSxhQUFhLElBQUksUUFBUSxJQUFJLGVBQWUsR0FBSTtBQUV4RSxTQUFPO0FBQUEsSUFDTCxTQUFTO0FBQUEsTUFDUCxRQUFRLENBQUMsU0FBUyxhQUFhLHFCQUFxQix1QkFBdUI7QUFBQSxJQUM3RTtBQUFBLElBQ0EsY0FBYztBQUFBLE1BQ1osU0FBUyxDQUFDLFNBQVMsYUFBYSxxQkFBcUIseUJBQXlCLGtCQUFrQjtBQUFBLElBQ2xHO0FBQUEsSUFDQSxTQUFTO0FBQUEsTUFDUCxNQUFNO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBLE1BZ0JOLEdBQUksQ0FBQyxtQkFBbUI7QUFBQSxRQUN0QixVQUFVO0FBQUEsVUFDUixRQUFRO0FBQUEsWUFDTjtBQUFBLFlBQ0E7QUFBQSxZQUNBO0FBQUEsWUFDQTtBQUFBLFlBQ0E7QUFBQSxZQUNBO0FBQUEsWUFDQTtBQUFBLFlBQ0E7QUFBQSxZQUNBO0FBQUEsWUFDQTtBQUFBLFlBQ0E7QUFBQSxZQUNBO0FBQUEsWUFDQTtBQUFBLFlBQ0E7QUFBQSxVQUNGO0FBQUEsVUFDQSxVQUFVLElBQUksa0JBQWtCO0FBQUEsWUFDOUIsaUJBQWlCO0FBQUE7QUFBQSxZQUNqQixVQUFVO0FBQUEsVUFDWixDQUFDO0FBQUEsVUFDRCxZQUFZLE9BQU87QUFFakIsa0JBQU0sT0FBTyxNQUFNLEtBQUs7QUFBQSxjQUN0QjtBQUFBLGNBQ0E7QUFBQSxZQUNGO0FBQUEsVUFDRjtBQUFBLFFBQ0YsQ0FBQztBQUFBO0FBQUEsUUFHRCxRQUFRO0FBQUEsVUFDTixVQUFVO0FBQUEsVUFDVixlQUFlO0FBQUEsWUFDYjtBQUFBLFlBQ0E7QUFBQSxZQUNBO0FBQUEsWUFDQTtBQUFBLFlBQ0E7QUFBQSxZQUNBO0FBQUEsWUFDQTtBQUFBLFlBQ0E7QUFBQSxZQUNBO0FBQUEsWUFDQTtBQUFBLFlBQ0E7QUFBQSxZQUNBO0FBQUEsWUFDQTtBQUFBLFlBQ0E7QUFBQSxVQUNGO0FBQUEsVUFDQSxTQUFTO0FBQUEsWUFDUDtBQUFBLFlBQ0E7QUFBQSxZQUNBO0FBQUEsWUFDQTtBQUFBLFlBQ0E7QUFBQSxZQUNBO0FBQUEsWUFDQTtBQUFBLFlBQ0E7QUFBQSxZQUNBO0FBQUEsWUFDQTtBQUFBLFlBQ0E7QUFBQSxVQUNGO0FBQUEsVUFDQSxZQUFZO0FBQUEsVUFDWixVQUFVO0FBQUEsWUFDUixLQUFLO0FBQUEsWUFDTCxZQUFZO0FBQUEsWUFDWixZQUFZO0FBQUEsWUFDWixjQUFjO0FBQUEsWUFDZCxTQUFTO0FBQUEsWUFDVCxLQUFLO0FBQUEsVUFDUDtBQUFBLFVBQ0EsbUJBQW1CO0FBQUEsVUFDbkIsUUFBUTtBQUFBLFlBQ047QUFBQSxjQUNFLFdBQVc7QUFBQSxjQUNYLE9BQU87QUFBQSxjQUNQLFVBQVU7QUFBQSxnQkFDUjtBQUFBLGdCQUNBO0FBQUEsZ0JBQ0E7QUFBQSxnQkFDQTtBQUFBLGdCQUNBO0FBQUEsZ0JBQ0E7QUFBQSxnQkFDQTtBQUFBLGdCQUNBO0FBQUEsZ0JBQ0E7QUFBQSxnQkFDQTtBQUFBLGdCQUNBO0FBQUEsZ0JBQ0E7QUFBQSxjQUNGO0FBQUEsWUFDRjtBQUFBLFVBQ0Y7QUFBQSxRQUNGLENBQUM7QUFBQSxNQUNILElBQUksQ0FBQztBQUFBLElBQ1A7QUFBQSxJQUNBLFFBQVE7QUFBQSxNQUNOO0FBQUEsTUFDQSxNQUFNO0FBQUE7QUFBQSxNQUNOLFlBQVk7QUFBQSxNQUNaLE1BQU07QUFBQSxNQUNOLGNBQWMsSUFBSSxnQkFBZ0IsQ0FBQyxJQUFJLGVBQWUsV0FBVyxJQUFJO0FBQUEsTUFDckUsU0FBUztBQUFBLFFBQ1AsaUJBQWlCO0FBQUEsTUFDbkI7QUFBQTtBQUFBO0FBQUE7QUFBQSxNQUlBLEdBQUksSUFBSSxnQkFBZ0I7QUFBQSxRQUN0QixLQUFLO0FBQUEsVUFDSCxVQUFVO0FBQUEsVUFDVixNQUFNLElBQUk7QUFBQSxVQUNWLFlBQVk7QUFBQSxRQUNkO0FBQUEsTUFDRixJQUFJLENBQUM7QUFBQSxNQUNMLE9BQU87QUFBQTtBQUFBLFFBRUwsT0FBTztBQUFBLFVBQ0wsUUFBUSxJQUFJLGdCQUFnQjtBQUFBLFVBQzVCLGNBQWM7QUFBQSxVQUNkLFFBQVE7QUFBQSxVQUNSLElBQUk7QUFBQSxRQUNOO0FBQUE7QUFBQSxRQUVBLFNBQVM7QUFBQSxVQUNQLFFBQVEsSUFBSSxnQkFBZ0I7QUFBQSxVQUM1QixjQUFjO0FBQUEsVUFDZCxRQUFRO0FBQUEsVUFDUixJQUFJO0FBQUEsUUFDTjtBQUFBO0FBQUEsUUFFQSxRQUFRO0FBQUEsVUFDTixRQUFRLElBQUksZ0JBQWdCO0FBQUEsVUFDNUIsY0FBYztBQUFBLFVBQ2QsUUFBUTtBQUFBLFVBQ1IsSUFBSTtBQUFBLFFBQ047QUFBQTtBQUFBLFFBRUEsV0FBVztBQUFBLFVBQ1QsUUFBUSxJQUFJLGdCQUFnQjtBQUFBLFVBQzVCLGNBQWM7QUFBQSxVQUNkLFFBQVE7QUFBQSxRQUNWO0FBQUE7QUFBQSxRQUVBLGlCQUFpQjtBQUFBLFVBQ2YsUUFBUSxJQUFJLGdCQUFnQjtBQUFBLFVBQzVCLGNBQWM7QUFBQSxVQUNkLFFBQVE7QUFBQSxRQUNWO0FBQUEsTUFDRjtBQUFBLElBQ0Y7QUFBQSxJQUNBLE9BQU87QUFBQSxNQUNMLFFBQVE7QUFBQSxNQUNSLFdBQVc7QUFBQSxNQUNYLHVCQUF1QjtBQUFBO0FBQUEsTUFDdkIsZUFBZTtBQUFBLFFBQ2IsUUFBUTtBQUFBLFVBQ04sY0FBYztBQUFBLFlBQ1osZ0JBQWdCLENBQUMsU0FBUyxhQUFhLGtCQUFrQjtBQUFBLFlBQ3pELGNBQWMsQ0FBQyxpQkFBaUIsdUJBQXVCLHFCQUFxQjtBQUFBLFlBQzVFLGdCQUFnQixDQUFDLFVBQVU7QUFBQSxVQUM3QjtBQUFBLFFBQ0Y7QUFBQSxNQUNGO0FBQUEsSUFDRjtBQUFBLEVBQ0Y7QUFDRixDQUFDOyIsCiAgIm5hbWVzIjogW10KfQo=

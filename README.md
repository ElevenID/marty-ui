# Marty UI

Microservice-based control plane and UI for Marty credential, trust, policy, applicant, and flow management.

## 🚀 Quick Start

### Local Development (Recommended)

```bash
# Clone with sibling repositories
cd ~/workspace
git clone https://github.com/ElevenID/Marty.git
git clone https://github.com/ElevenID/marty-credentials.git
git clone https://github.com/ElevenID/marty-microservices-framework.git
git clone https://github.com/ElevenID/marty-ui.git

# Start the local microservice stack
cd marty-ui
make dev
```

Then, if you want the UI running natively in a separate terminal:

```bash
make run-ui
```

Primary local URLs:

- Gateway: <http://localhost:8000>
- Gateway docs: <http://localhost:8000/docs>
- Keycloak: <http://localhost:8180>
- UI dev server: <http://localhost:5173>

### Production Deployment

```bash
# Production deployment is environment-specific.
# For local production-like verification, build the UI and run the backend stack:
cd marty-ui/ui
npm run build
```

📖 **Full setup guide:** [DEVELOPMENT_SETUP.md](DEVELOPMENT_SETUP.md)

---

## Overview

This repository hosts the active `marty-ui` application stack:

- **Gateway** for public and authenticated API routing
- **Auth** and **Organization** services for identity and tenancy
- **Trust Profile**, **Compliance Profile**, **Presentation Policy**, and **Deployment Profile** services
- **Applicant**, **Flow**, **Notification**, **Verification**, and **Device Registration** services
- **React/Vite UI** for operator workflows and console experiences

## Architecture

```
┌───────────────┐
│  React / Vite │
└───────┬───────┘
   │
┌───────▼───────┐
│    Gateway    │
└───────┬───────┘
   │
 ┌──────┼─────────────────────────────────────────────┐
 │      │                                             │
▼▼▼    ▼▼▼                                           ▼▼▼
Auth  Organization  Trust/Profile/Policy services  Flow/Applicant/etc.
   │
   ▼
   Postgres / Redis / Keycloak / MailHog
```

Locally, the stack is orchestrated with `docker-compose.base.yml` plus profile overlays.

## Package Dependencies

This project depends on three Marty packages:

- **[marty-credentials](https://github.com/ElevenID/marty-credentials)** - Credential domain logic, status lists, Rust bindings (marty-rs)
- **[marty-common](https://github.com/ElevenID/Marty/tree/main/packages/marty-common)** - Shared infrastructure (crypto_bridge, gRPC, database)
- **[marty-microservices-framework](https://github.com/ElevenID/marty-microservices-framework)** - Microservices framework

**Development:** Packages are mounted as volumes for live code reloading  
**Production:** Packages are installed from GitHub Packages registry

See [IMPORT_MIGRATION.md](IMPORT_MIGRATION.md) for import path details.

## Features

### Issuer Service

- **Credential Issuance**: Creates ISO 18013-5 compliant mDL credentials
- **Document Types**: Supports driving licenses, ID cards, and custom documents
- **Security**: Uses secure random generation for credential IDs
- **Standards Compliance**: Implements mso_mdoc format with proper cryptographic signatures

### Verifier Service

- **Presentation Verification**: Validates mDoc presentations using OpenID4VP
- **Proximity Verification**: Supports ISO 18013-5 proximity presentation via BLE
- **Selective Disclosure**: Verifies only requested attributes
- **Security Validation**: Checks cryptographic signatures and certificate chains

### Wallet Service

- **Credential Management**: Stores and organizes multiple credentials
- **Selective Disclosure**: Allows users to share only required information
- **Secure Storage**: Implements secure area storage for sensitive data
- **Presentation Logic**: Handles both remote and proximity presentation flows

## Enhanced Features

### 🛡️ Age Verification with Selective Disclosure

- **Privacy-Preserving**: Verify age without disclosing birth date
- **Multiple Use Cases**: Alcohol purchase, voting, senior discounts, employment
- **Zero-Knowledge Proofs**: Demonstrate age thresholds without revealing exact age
- **Policy-Based**: Context-aware verification with privacy level reporting

### 📱 Offline QR Code Verification

- **Network-Free**: Verify credentials without internet connectivity
- **Cryptographic Security**: ECDSA signatures with CBOR encoding
- **Single-Use**: QR codes with built-in replay protection
- **Compact**: Optimized for mobile QR code display and scanning

### 🔒 Certificate Lifecycle Monitoring

- **mDL DSC Tracking**: Monitor Document Signer Certificate expiry
- **Proactive Alerts**: Early warning system for certificate renewals
- **Renewal Simulation**: Automated certificate renewal workflows
- **Dashboard**: Comprehensive certificate health monitoring

### 📋 Policy-Based Selective Disclosure

- **Context-Aware**: Intelligent attribute sharing based on verification context
- **Trust Levels**: Verifier trust assessment and appropriate disclosure
- **Privacy Controls**: User consent and attribute sensitivity classification
- **Integration**: Uses Marty's authorization engine for policy decisions

### Demo UI

- **Interactive Testing**: Web interface for all demo scenarios
- **QR Code Generation**: For mobile wallet integration and offline verification
- **Real-time Updates**: Live status updates during credential flows
- **Responsive Design**: Works on desktop and mobile devices
- **Enhanced Navigation**: Dedicated tab for advanced features
- **Interactive Demos**: Hands-on exploration of all enhanced capabilities

## Quick Start

### 1. Start backend services

```bash
cd marty-ui
make dev
```

### 2. Start the UI locally

```bash
cd ui
npm install
npm run dev
```

### 3. Open the app

- UI: <http://localhost:5173>
- Gateway: <http://localhost:8000>
- API docs: <http://localhost:8000/docs>

## Prerequisites

- **Docker Desktop** or Docker Engine with Compose support
- **Node.js** (optional, for native UI development)
- **Sibling Marty repositories** when working in editable local mode

### macOS Installation

```bash
# Install using Homebrew if needed
brew install node

# Docker Desktop is recommended on macOS
```

### Ubuntu/Debian Installation

```bash
sudo apt update
sudo apt install docker.io docker-compose-plugin nodejs npm
sudo systemctl start docker
sudo usermod -aG docker $USER
```

## Quick Start

1. **Start the backend stack:**

   ```bash
   make dev
   ```

2. **Start the UI locally (optional but common):**

   ```bash
   cd ui
   npm install
   npm run dev
   ```

3. **Access the local apps:**
   - UI: <http://localhost:5173>
   - Gateway: <http://localhost:8000>
   - Gateway docs: <http://localhost:8000/docs>
   - Keycloak: <http://localhost:8180>

4. **Clean up when done:**

   ```bash
   make down
   ```

## Detailed Usage

### Local stack commands

```bash
# start everything
make dev

# stop everything
make down

# inspect logs
make logs

# backend services only
make services-logs

# infra only
make infra

# restart backend services
make services-restart
```

### Main local endpoints

- Gateway: `http://localhost:8000`
- Gateway docs: `http://localhost:8000/docs`
- Auth docs: `http://localhost:8001/docs`
- Organization docs: `http://localhost:8002/docs`
- Keycloak: `http://localhost:8180`
- MailHog: `http://localhost:9025`

### Active service groups

The current compose stack centers on the gateway plus backend microservices such as:

- `auth`
- `organization`
- `trust-profile`
- `credential-template`
- `presentation-policy`
- `deployment-profile`
- `compliance-profile`
- `notification`
- `flow`
- `issuance`
- `verification`
- `event-stream`

## Configuration

### Environment Variables

The local stack supports a number of environment variables via `.env` and compose defaults. Common examples include:

- `PUBLIC_API_URL`
- `CORS_ORIGINS`
- `KEYCLOAK_REALM`
- `OIDC_ISSUER_URL_EXTERNAL`
- `POSTGRES_*`
- `REDIS_URL`

### Database Configuration

The default local Postgres container is configured via compose and is intended for development use.

- External port: `5433`

### Compose files

- `docker-compose.base.yml` - base stack definition
- `docker-compose.profile.dev.yml` - dev-mode overlay
- `docker-compose.profile.tunnel.yml` - optional public tunnel support
- `docker-compose.profile.obs.yml` - optional observability profile
- `docker-compose.profile.w3c-vc.yml` - disposable W3C VC Data Model v2 adapter profile
- `docker-compose.profile.conformance.yml` - project-scoped official interoperability isolation

## Development

### Current local development setup

Use the microservice stack managed by the Makefile and compose files:

```bash
# backend stack
make dev

# or infra only
make infra

# frontend in another terminal
cd ui
npm install
npm run dev
```

Useful helper targets:

```bash
make logs
make status
make services-build
make services-restart
make grpc-health
```

### Customizing Services

#### Adding or updating backend capabilities

New backend features should be implemented in the relevant service under `services/`, then surfaced through `services/gateway/` and the UI as needed.

Typical areas:

- `services/trust_profile/`
- `services/presentation_policy/`
- `services/revocation_profile/`
- `services/notification/`
- `services/auth/`
- `services/gateway/`

## Troubleshooting

### Common Issues

1. **Port conflicts:**

   ```bash
   lsof -i :5173
   lsof -i :8000
   lsof -i :8180
   ```

2. **Containers or services not starting:**

   ```bash
   make status
   make logs
   ```

3. **API/gRPC checks:**

   ```bash
   curl http://localhost:8000/health
   make grpc-health
   ```

4. **Database connection issues:**

   ```bash
   docker logs marty-postgres
   docker exec -it marty-postgres psql -U postgres
   ```

### Logs and Monitoring

View service logs:

```bash
# All services
make logs

# Backend services only
make services-logs
```

Monitor resource usage:

```bash
docker stats
```

## Security Considerations

### Production Deployment

This repository contains active development infrastructure, but the default local configuration is still development-oriented. For production use:

1. **Use proper certificates**: Replace self-signed certificates with CA-issued ones
2. **Implement authentication**: Add proper API authentication and authorization
3. **Secure database**: Use encrypted connections and strong passwords
4. **Network security**: Implement proper network policies and TLS
5. **Key management**: Use hardware security modules (HSMs) for key storage
6. **Audit logging**: Implement comprehensive audit trails
7. **Update dependencies**: Regularly update all dependencies for security patches

### Known Limitations

- Default compose settings are development-focused
- Some services rely on sibling repository checkouts during editable local development
- Local certificates and identity settings should not be treated as production defaults

## Standards and Compliance

This project works across standards and service domains including:

- **OID4VCI**
- **OpenID4VP**
- **W3C VC Data Model**: Verifiable Credentials specification
- **Trust / policy / revocation profile services** used by the Marty platform

## 📋 Future Work - SEO & Analytics

The marketing site infrastructure is complete with prerendering, sitemap, and structured data. The following action items need to be completed before production deployment:

### Required Setup

1. **Google Search Console Verification**
   - Visit [Google Search Console](https://search.google.com/search-console)
   - Add property for `https://elevenidllc.com`
   - Uncomment verification meta tag in `ui/index.html` (line 9)
   - Add your verification code from Search Console
   - Deploy and verify ownership

2. **Google Analytics (GA4)**
   - Create GA4 property at [Google Analytics](https://analytics.google.com/)
   - Copy your Measurement ID (format: `G-XXXXXXXXXX`)
   - Add to `.env.production`: `VITE_GA_MEASUREMENT_ID=G-XXXXXXXXXX`
   - See `ui/src/utils/analytics.example.js` for integration code

3. **Analytics Integration**
   - Add analytics hooks to `ui/src/App.jsx` (see example file)
   - Three useEffect hooks needed: init, page tracking, web vitals
   - Test in development with browser console

4. **Deploy & Verify**
   - Build production: `cd ui && bunx vite build`
   - Deploy `dist/` directory to production hosting
   - Submit sitemap in Search Console: `https://elevenidllc.com/sitemap.xml`
   - Verify pages are being indexed (check Index Coverage report)
   - Monitor Core Web Vitals in Search Console

### Documentation

- **Full setup guide**: `ui/SEO_MONITORING_GUIDE.md`
- **Analytics utilities**: `ui/src/utils/analytics.js`
- **Integration examples**: `ui/src/utils/analytics.example.js`
- **Environment config**: `ui/.env.example`

### Current Status

✅ **Complete:**
- 14 pages prerendered with full SEO metadata
- Meta tags, Open Graph, Twitter Cards configured
- JSON-LD structured data for all pages
- robots.txt and sitemap.xml generated
- Core Web Vitals monitoring utilities ready
- Analytics tracking code implemented
- web-vitals package installed

🔲 **Pending:**
- Search Console verification code
- GA4 Measurement ID configuration
- Analytics integration in App.jsx
- Production deployment
- Sitemap submission

## Contributing

To contribute to this project:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Submit a pull request

### Development Guidelines

- Follow PEP 8 for Python code
- Use TypeScript for new UI components
- Add comprehensive error handling
- Include unit tests for new features
- Update documentation for changes

## License

This project is released under the GNU Affero General Public License v3.0 (AGPL-3.0-only). See the [LICENSE](LICENSE) file for details.

## Resources

- [OID4VCI](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html)
- [OpenID4VP Specification](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html)
- [W3C Verifiable Credentials Data Model](https://www.w3.org/TR/vc-data-model/)

---

For questions or support, please create an issue in the repository or contact the development team.

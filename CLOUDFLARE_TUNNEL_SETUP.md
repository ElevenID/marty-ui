# Cloudflare Tunnel Setup for ElevenID LLC Beta

This guide walks you through setting up a Cloudflare Tunnel to expose your local ElevenID LLC instance at **beta.elevenidllc.com** for external review.

## Prerequisites

1. **Cloudflare account** with your domain `elevenidllc.com` added
2. **Cloudflare Zero Trust** enabled (free plan works)
3. **Docker & Docker Compose** installed locally
4. **ElevenID LLC running locally** in Docker

---

## Step 1: Create Cloudflare Tunnel

### 1.1 Access Cloudflare Zero Trust Dashboard

1. Log into [Cloudflare Dashboard](https://dash.cloudflare.com)
2. Navigate to **Zero Trust** → **Networks** → **Tunnels**
3. Click **"Create a tunnel"**

### 1.2 Choose Tunnel Type

- Select **"Cloudflared"** (recommended for Docker)
- Click **"Next"**

### 1.3 Name Your Tunnel

- **Name:** `elevenid-local-review` (or any descriptive name)
- Click **"Save tunnel"**

### 1.4 Copy Your Tunnel Token

**⚠️ IMPORTANT:** You'll see a command like:

```bash
cloudflared tunnel run --token eyJhIjoiYWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY3ODkwIiwidCI6ImFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6MTIzNDU2Nzg5MCIsInMiOiJhYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5ejEyMzQ1Njc4OTAifQ==
```

**Copy the entire token** (the long base64 string starting with `eyJ`). This is your `CLOUDFLARE_TUNNEL_TOKEN`.

**Do NOT close this page yet** - you'll need it for the next step.

### 1.5 Configure Public Hostnames

Still on the Cloudflare Tunnel configuration page:

#### For the primary public UI entrypoint:

1. Click **"Add a public hostname"**
2. Configure:
   - **Subdomain:** `beta`
   - **Domain:** `elevenidllc.com`
   - **Service Type:** `HTTP`
    - **URL:** `nginx-proxy:80`
3. Click **"Save hostname"**

#### For API Service (Optional - for direct backend access):

1. Click **"Add a public hostname"** again
2. Configure:
   - **Subdomain:** `api-beta` (or `beta-api`)
   - **Domain:** `elevenidllc.com`
   - **Service Type:** `HTTP`
    - **URL:** `gateway:8000`
3. Click **"Save hostname"**

> **Note:** The primary public hostname already proxies UI, auth, and API traffic through `nginx-proxy`, so the separate API hostname is optional.

### 1.6 Skip Connector Installation

- You'll see instructions to install `cloudflared` locally
- **Skip this step** - we'll run it in Docker instead
- Click **"Done"** or close the modal

---

## Step 2: Configure Environment Variables

### 2.1 Configure `.env`

In the `marty-ui` repository root, update `.env` with your tunnel settings:

```bash
cd "/Volumes/Heart of Gold/Github/work/marty-ui"
cp .env.example .env
```

### 2.2 Edit `.env`

Open `.env` and add your tunnel token:

```bash
# Cloudflare Tunnel Configuration
# ================================

# Your Cloudflare Tunnel Token (from Step 1.4)
# Paste the entire token here (starts with eyJ...)
CLOUDFLARE_TUNNEL_TOKEN=eyJhIjoiYWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY3ODkwIiwidCI6ImFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6MTIzNDU2Nzg5MCIsInMiOiJhYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5ejEyMzQ1Njc4OTAifQ==

# Public URLs
PUBLIC_URL=https://beta.elevenidllc.com
PUBLIC_API_URL=https://beta.elevenidllc.com

# Security Settings (HTTPS)
COOKIE_SECURE=true
COOKIE_SAMESITE=none

# Keycloak Configuration (if exposing externally)
# Uncomment and configure if you need external Keycloak access
# KC_HOSTNAME=beta.elevenidllc.com
# KC_HOSTNAME_PORT=443
# OIDC_ISSUER_URL=https://beta.elevenidllc.com/auth/realms/11id
```

### 2.3 Secure the File

```bash
# Add to .gitignore to prevent committing secrets
echo ".env" >> .gitignore
```

---

## Step 3: Start Services with Tunnel

### 3.1 Using Make (Recommended)

```bash
# Start backend services with tunnel-aware settings
make run-api-tunnel

# Start Cloudflare tunnel sidecars
make tunnel-start

# Start the UI in tunnel mode
make dev-ui-tunnel
```

This will:
- Start the backend stack with tunnel-aware environment overrides
- Start the Cloudflare Tunnel connector
- Start the local tunnel proxy and UI dev server
- Use environment variables from `.env`

### 3.2 Using Docker Compose Directly

```bash
# Start with tunnel overlay
docker compose \
    -f docker-compose.base.yml \
    -f docker-compose.profile.dev.yml \
    -f docker-compose.profile.tunnel.yml \
  up -d
```

---

## Step 4: Verify Tunnel is Working

### 4.1 Check Tunnel Status in Cloudflare

1. Go back to **Cloudflare Zero Trust** → **Networks** → **Tunnels**
2. Your tunnel should show as **"Healthy"** with a green indicator
3. Status should be **"Active"**

### 4.2 Check Docker Logs

```bash
# View cloudflared logs
make tunnel-logs

# Should see:
# "Connection established"
# "Registered tunnel connection"
```

### 4.3 Test Public Access

1. Open a browser (or ask someone else to test)
2. Navigate to: **https://beta.elevenidllc.com**
3. You should see the ElevenID LLC UI loading
4. Test login and navigation

### 4.4 Test from Different Network

- Try accessing from your phone (on cellular data, not WiFi)
- Share the link with a colleague
- Access should work from anywhere in the world

---

## Step 5: Security Considerations

### 5.1 Authentication

The tunnel exposes your local instance to the internet. Consider:

- **Keycloak is accessible** - ensure strong admin password
- **Test accounts** - change default passwords in production
- **Database** - not exposed (only via API)

### 5.2 Rate Limiting

Add Cloudflare rate limiting:

1. Go to **Cloudflare Dashboard** → **Security** → **WAF**
2. Create rate limiting rules for your subdomain
3. Example: 100 requests per minute per IP

### 5.3 Access Policies (Optional)

Add access restrictions in Cloudflare Zero Trust:

1. Go to **Zero Trust** → **Access** → **Applications**
2. Create an application for `beta.elevenidllc.com`
3. Add policies (e.g., email domain, IP ranges)

---

## Troubleshooting

### Tunnel shows "Down" or "Unhealthy"

```bash
# Check tunnel-related containers
make tunnel-status

# View logs for errors
make tunnel-logs

# Common fix: restart tunnel
make tunnel-restart
```

### "Connection refused" or 502 Bad Gateway

```bash
# Check if the tunnel proxy is running
docker ps --filter name='tunnel-nginx-proxy|cloudflared-tunnel'

# Check proxy health
curl http://localhost:9080/health

# Check network connectivity
docker exec -it cloudflared-tunnel sh
```

### Services can't reach each other

```bash
# Verify all services are on marty-network
docker network inspect marty-network

# Ensure cloudflared, tunnel-nginx-proxy, and gateway are listed
```

### Token Invalid

- Double-check you copied the entire token (including ey... at start)
- Regenerate token in Cloudflare dashboard if needed
- Update `.env` with the new token

---

## Stopping the Tunnel

```bash
make down
```

---

## Architecture Diagram

```
Internet
    ↓
Cloudflare Tunnel (beta.elevenidllc.com)
    ↓
Docker: cloudflared container
    ↓
Docker Network: marty-network
    ↓
nginx-proxy:80
    ├─ UI dev server on host (:3000 or :3002)
    ├─ gateway:8000
    └─ keycloak:8080
```

---

## Next Steps

- [ ] Test complete authentication flow
- [ ] Update Keycloak redirect URIs for public domain
- [ ] Configure CORS if needed
- [ ] Set up monitoring/alerts for tunnel health
- [ ] Document access URLs for reviewers
- [ ] Consider upgrading to production-grade nginx config

---

## Resources

- [Cloudflare Tunnel Documentation](https://developers.cloudflare.com/cloudflare-one/connections/connect-apps/)
- [Cloudflared Docker Image](https://hub.docker.com/r/cloudflare/cloudflared)
- [Zero Trust Dashboard](https://one.dash.cloudflare.com/)

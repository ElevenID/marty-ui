# Cloudflare Tunnel Setup for ElevenID Beta

This guide walks you through setting up a Cloudflare Tunnel to expose your local ElevenID instance at **beta.elevenfold.com** for external review.

## Prerequisites

1. **Cloudflare account** with your domain `elevenfold.com` added
2. **Cloudflare Zero Trust** enabled (free plan works)
3. **Docker & Docker Compose** installed locally
4. **ElevenID running locally** in Docker

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

#### For UI Service:

1. Click **"Add a public hostname"**
2. Configure:
   - **Subdomain:** `beta`
   - **Domain:** `elevenfold.com`
   - **Service Type:** `HTTP`
   - **URL:** `ui:80`
3. Click **"Save hostname"**

#### For API Service (Optional - for direct API access):

1. Click **"Add a public hostname"** again
2. Configure:
   - **Subdomain:** `api-beta` (or `beta-api`)
   - **Domain:** `elevenfold.com`
   - **Service Type:** `HTTP`
   - **URL:** `oid4vc-api:8000`
3. Click **"Save hostname"**

> **Note:** The UI at `beta.elevenfold.com` already proxies API requests to the backend, so the separate API hostname is optional.

### 1.6 Skip Connector Installation

- You'll see instructions to install `cloudflared` locally
- **Skip this step** - we'll run it in Docker instead
- Click **"Done"** or close the modal

---

## Step 2: Configure Environment Variables

### 2.1 Create `.env.tunnel` File

In the Marty workspace root, create a file named `.env.tunnel`:

```bash
cd "/Volumes/Heart of Gold/Github/work/Marty"
cp .env.tunnel.example .env.tunnel
```

### 2.2 Edit `.env.tunnel`

Open `.env.tunnel` and add your tunnel token:

```bash
# Cloudflare Tunnel Configuration
# ================================

# Your Cloudflare Tunnel Token (from Step 1.4)
# Paste the entire token here (starts with eyJ...)
CLOUDFLARE_TUNNEL_TOKEN=eyJhIjoiYWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY3ODkwIiwidCI6ImFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6MTIzNDU2Nzg5MCIsInMiOiJhYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5ejEyMzQ1Njc4OTAifQ==

# Public URLs
PUBLIC_URL=https://beta.elevenfold.com
PUBLIC_API_URL=https://beta.elevenfold.com

# Security Settings (HTTPS)
COOKIE_SECURE=true
COOKIE_SAMESITE=none

# Keycloak Configuration (if exposing externally)
# Uncomment and configure if you need external Keycloak access
# KC_HOSTNAME=beta.elevenfold.com
# KC_HOSTNAME_PORT=443
# OIDC_ISSUER_URL=https://beta.elevenfold.com/auth/realms/11id
```

### 2.3 Secure the File

```bash
# Add to .gitignore to prevent committing secrets
echo ".env.tunnel" >> .gitignore
```

---

## Step 3: Start Services with Tunnel

### 3.1 Using Make (Recommended)

```bash
# Start dev environment with Cloudflare Tunnel
make dev-tunnel
```

This will:
- Start all dev profile services (UI, API, Keycloak, Postgres, Redis)
- Start the Cloudflare Tunnel connector
- Use environment variables from `.env.tunnel`

### 3.2 Using Docker Compose Directly

```bash
# Start with tunnel overlay
docker compose \
  -f docker-compose.yml \
  -f docker-compose.tunnel.yml \
  --env-file .env.tunnel \
  --profile dev \
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
docker compose logs cloudflared

# Should see:
# "Connection established"
# "Registered tunnel connection"
```

### 4.3 Test Public Access

1. Open a browser (or ask someone else to test)
2. Navigate to: **https://beta.elevenfold.com**
3. You should see the ElevenID UI loading
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
- **Demo accounts** - change default passwords in production
- **Database** - not exposed (only via API)

### 5.2 Rate Limiting

Add Cloudflare rate limiting:

1. Go to **Cloudflare Dashboard** → **Security** → **WAF**
2. Create rate limiting rules for your subdomain
3. Example: 100 requests per minute per IP

### 5.3 Access Policies (Optional)

Add access restrictions in Cloudflare Zero Trust:

1. Go to **Zero Trust** → **Access** → **Applications**
2. Create an application for `beta.elevenfold.com`
3. Add policies (e.g., email domain, IP ranges)

---

## Troubleshooting

### Tunnel shows "Down" or "Unhealthy"

```bash
# Check cloudflared container
docker compose ps cloudflared

# View logs for errors
docker compose logs cloudflared

# Common fix: restart tunnel
docker compose restart cloudflared
```

### "Connection refused" or 502 Bad Gateway

```bash
# Check if UI service is running
docker compose ps ui

# Check UI health
curl http://localhost:9080

# Check network connectivity
docker compose exec cloudflared ping ui
```

### Services can't reach each other

```bash
# Verify all services are on marty-network
docker network inspect marty-network

# Ensure cloudflared and ui are both listed
```

### Token Invalid

- Double-check you copied the entire token (including ey... at start)
- Regenerate token in Cloudflare dashboard if needed
- Update `.env.tunnel` with new token

---

## Stopping the Tunnel

### Stop all services including tunnel:

```bash
make down-tunnel
```

### Or manually:

```bash
docker compose \
  -f docker-compose.yml \
  -f docker-compose.tunnel.yml \
  down
```

---

## Architecture Diagram

```
Internet
    ↓
Cloudflare Tunnel (beta.elevenfold.com)
    ↓
Docker: cloudflared container
    ↓
Docker Network: marty-network
    ↓
ui:80 (nginx) → oid4vc-api:8000 (FastAPI)
                    ↓
                keycloak:8080
                    ↓
                postgres:5432
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

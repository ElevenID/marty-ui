# Oracle Cloud (OKE) + Cloudflare Deployment Guide

**Target environment:** Oracle Kubernetes Engine (OKE) — Always-Free tier  
**Public domain:** `elevenidllc.com` (Cloudflare DNS)  
**Tunnel:** Cloudflare Zero Trust Tunnel (outbound-only, no open Oracle ports)  
**Registry:** Oracle Container Registry (OCIR)

---

## Architecture Overview

```
Internet (HTTPS)
      │
      ▼
┌─────────────────────────────────────────────────┐
│           Cloudflare (CDN + TLS)                │
│  elevenidllc.com  →  tunnelID.cfargotunnel.com  │
│  api.elevenidllc.com  →  same tunnel            │
│  auth.elevenidllc.com →  same tunnel            │
└──────────────────────┬──────────────────────────┘
                       │  Cloudflare Tunnel (outbound)
                       ▼
┌─────────────────────────────────────────────────────────────────────┐
│  Oracle Kubernetes Engine  (OKE — Always Free ARM A1.Flex nodes)    │
│  Namespace: marty-prod                                              │
│                                                                     │
│  cloudflared ──► ui:80           (nginx + React SPA)               │
│              ──► gateway:8000    (API Gateway)                     │
│              ──► keycloak:8080   (Identity / OIDC)                 │
│                                                                     │
│  Microservices: auth · org · credential-template · trust-profile   │
│                 issuance · applicant · notification · compliance    │
│                 presentation-policy · deployment-profile · flow     │
│                                                                     │
│  Infrastructure: postgres · redis · rabbitmq (StatefulSets + PVC)  │
└─────────────────────────────────────────────────────────────────────┘
```

---

## File Layout

```
k8s/oracle/
  00-namespace.yaml          Namespace + ServiceAccount
  01-configmap.yaml          Non-secret configuration (URLs, env settings)
  02-secrets-template.yaml   Guide for what secrets to create (never commit real values)
  03-postgres.yaml           PostgreSQL StatefulSet + PVC + init script
  04-redis-rabbitmq.yaml     Redis + RabbitMQ StatefulSets + PVCs
  05-keycloak.yaml           Keycloak Deployment + realm import Job
  06-db-migrate.yaml         Alembic migration Job
  07-microservices.yaml      Gateway + 11 backend service Deployments
  08-ui.yaml                 nginx UI Deployment + production nginx config
  09-cloudflared.yaml        Cloudflare Tunnel Deployment (2 replicas for HA)

scripts/
  build-push-ocir.sh         Build all Docker images and push to OCIR
  deploy-oracle.sh           Full OKE deploy / secret setup / rolling update
```

---

## Step-by-Step Deployment

### Step 1 — OCI Prerequisites

#### 1.1 Create OKE Cluster (Always Free)

1. Go to **OCI Console → Developer Services → Kubernetes Clusters (OKE)**
2. Click **Create cluster** → **Quick Create**
3. Configure:
   - **Name:** `marty-prod`
   - **Kubernetes version:** latest stable
   - **Node shape:** `VM.Standard.A1.Flex` (ARM — free tier)
   - **OCPUs per node:** 2 · **RAM:** 12 GB (gives 2 nodes for free)
   - **Node count:** 2
   - **Node pool size:** 2
4. Click **Create Cluster** — creation takes ~10 minutes

#### 1.2 Configure kubectl

```bash
# Install OCI CLI if not already installed
bash -c "$(curl -L https://raw.githubusercontent.com/oracle/oci-cli/master/scripts/install/install.sh)"

# Configure OCI CLI
oci setup config   # follow prompts — you'll need tenancy OCID, user OCID, region

# Download kubeconfig for your cluster (replace CLUSTER_OCID)
oci ce cluster create-kubeconfig \
  --cluster-id <CLUSTER_OCID> \
  --file ~/.kube/config \
  --region <OCI_REGION> \
  --token-version 2.0.0

# Test connection
kubectl get nodes
```

#### 1.3 Generate OCIR Auth Token

1. OCI Console → **Identity & Security → Users → Your user**
2. Under **Resources**, click **Auth Tokens → Generate Token**
3. Description: `OCIR push/pull`
4. **Copy the token immediately** — it won't be shown again

---

### Step 2 — Cloudflare Tunnel Setup

#### 2.1 Create the Tunnel

1. Log in to [Cloudflare Zero Trust](https://one.dash.cloudflare.com/) → **Networks → Tunnels**
2. Click **Create a tunnel** → **Cloudflared** → Next
3. **Tunnel name:** `marty-prod`
4. Copy the **tunnel token** (the long `eyJ…` string)

#### 2.2 Add Public Hostnames

On the same page, add three hostnames:

| Subdomain | Domain          | Service Type | URL                 |
|-----------|-----------------|--------------|---------------------|
| (root)    | elevenidllc.com | HTTP         | `ui.marty-prod.svc.cluster.local:80`    |
| api       | elevenidllc.com | HTTP         | `gateway.marty-prod.svc.cluster.local:8000` |
| auth      | elevenidllc.com | HTTP         | `keycloak.marty-prod.svc.cluster.local:8080` |

> **Note:** The cluster-local DNS names only resolve from inside the cluster.  
> When configuring via the Cloudflare dashboard, use short names: `http://ui:80`, `http://gateway:8000`, `http://keycloak:8080`  
> (cloudflared resolves these relative to the namespace — make sure the service names match.)

Click **Save tunnel**.

#### 2.3 Cloudflare DNS (automatic)

Cloudflare automatically adds CNAME records when you configure hostnames in the tunnel. Check under **DNS → Records** that these appear:

```
elevenidllc.com      CNAME  <tunnel-id>.cfargotunnel.com  (Proxied ✓)
api.elevenidllc.com  CNAME  <tunnel-id>.cfargotunnel.com  (Proxied ✓)
auth.elevenidllc.com CNAME  <tunnel-id>.cfargotunnel.com  (Proxied ✓)
```

---

### Step 3 — Configure Secrets

```bash
# Copy the example env file
cp .env.production.example .env.production

# Edit and fill in ALL values
nano .env.production   # or code .env.production

# Generate strong random values for secrets you don't have yet:
openssl rand -hex 32   # for POSTGRES_PASSWORD, SESSION_SECRET_KEY, etc.
openssl rand -hex 32   # for RABBITMQ_ERLANG_COOKIE
```

Key values to fill in `.env.production`:

| Variable | Where to get it |
|----------|----------------|
| `OCI_REGION` | Your OCI region (e.g. `us-ashburn-1`) |
| `OCIR_TENANCY_NAMESPACE` | OCI Console → Tenancy Details → Object Storage Namespace |
| `OCI_USERNAME` | Your OCI user name / email |
| `OCIR_AUTH_TOKEN` | From Step 1.3 |
| `POSTGRES_PASSWORD` | Generate: `openssl rand -hex 20` |
| `KEYCLOAK_DB_PASSWORD` | Generate: `openssl rand -hex 20` |
| `KEYCLOAK_ADMIN_PASSWORD` | Choose a strong password |
| `MARTY_API_CLIENT_SECRET` | Must match the Keycloak `marty-api` client secret |
| `RABBITMQ_PASSWORD` | Generate: `openssl rand -hex 20` |
| `RABBITMQ_ERLANG_COOKIE` | Generate: `openssl rand -hex 32` |
| `SESSION_SECRET_KEY` | Generate: `openssl rand -hex 32` |
| `CLOUDFLARE_TUNNEL_TOKEN` | From Step 2.1 |
| `SMTP_USERNAME` / `SMTP_PASSWORD` | Your email provider credentials |

---

### Step 4 — Build and Push Images

> **ARM64 note:** OCI Always-Free uses ARM A1.Flex nodes. You need ARM-compatible images.  
> If your Mac is Apple Silicon (M1/M2/M3), `docker buildx` can produce ARM64 images natively.  
> If you're on Intel, you'll need to either use `--platform linux/amd64` and pick x86 OKE node shapes, or use a CI build runner.

```bash
# Make scripts executable
chmod +x scripts/build-push-ocir.sh scripts/deploy-oracle.sh

# Source your env file
source .env.production

# Build and push all images (ARM64 for Always-Free A1.Flex nodes)
./scripts/build-push-ocir.sh \
  --region "$OCI_REGION" \
  --namespace "$OCIR_TENANCY_NAMESPACE" \
  --tag prod \
  --platform linux/arm64

# ── If your Dockerfiles aren't ARM-ready, use x86 and change node shape ──
# ./scripts/build-push-ocir.sh --platform linux/amd64 --tag prod ...
# (then choose VM.Standard.E2.1.Micro nodes in OKE — still free but only 1GB RAM each)
```

---

### Step 5 — Deploy to OKE

```bash
# Full deploy (first time)
./scripts/deploy-oracle.sh deploy

# Check status
./scripts/deploy-oracle.sh status

# Tail logs for a specific service
kubectl logs -f deployment/gateway -n marty-prod
kubectl logs -f deployment/cloudflared -n marty-prod
```

The deploy script will:
1. Create the namespace and ServiceAccount
2. Push all secrets to Kubernetes via `kubectl create secret`
3. Load the Keycloak realm JSON from `marty-ui/config/keycloak/`
4. Apply all StatefulSets (Postgres, Redis, RabbitMQ) and wait for readiness
5. Run the Alembic migration Job
6. Start Keycloak and run the configurator Job
7. Deploy all 12 microservices + UI
8. Deploy cloudflared (2 replicas for HA)

---

### Step 6 — Verify

```bash
# All pods should be Running
kubectl get pods -n marty-prod

# Cloudflared should show 2/2 Running
kubectl get deployment cloudflared -n marty-prod

# Test endpoints (after DNS propagates ~1 min)
curl https://elevenidllc.com
curl https://api.elevenidllc.com/health
curl https://auth.elevenidllc.com/health/ready
```

---

## Day-2 Operations

### Rolling Image Update

```bash
source .env.production

# Build and push new version
./scripts/build-push-ocir.sh --tag v1.1 --region "$OCI_REGION" --namespace "$OCIR_TENANCY_NAMESPACE"

# Update running deployments
IMAGE_TAG=v1.1 ./scripts/deploy-oracle.sh update-images
```

### Scale a Service

```bash
# Scale gateway to 2 replicas
kubectl scale deployment/gateway --replicas=2 -n marty-prod
```

### Database Backups

```bash
# Manual Postgres dump (run from a local machine with kubectl access)
kubectl exec -it statefulset/postgres -n marty-prod -- \
  pg_dump -U marty marty | gzip > backup-$(date +%Y%m%d).sql.gz
```

### View Logs

```bash
# All pods in namespace
kubectl logs -f --selector=app.kubernetes.io/part-of=marty-platform -n marty-prod --max-log-requests=20

# Specific service
kubectl logs -f deployment/auth -n marty-prod

# Cloudflare tunnel
kubectl logs -f deployment/cloudflared -n marty-prod
```

### Re-run Migrations (after upgrade)

```bash
# Delete old job and run fresh
kubectl delete job db-migrate -n marty-prod --ignore-not-found
source .env.production && ./scripts/deploy-oracle.sh deploy
```

---

## Always-Free Tier Resource Budget

| Resource | Free Allowance | Estimated Usage |
|----------|---------------|-----------------|
| A1.Flex OCPUs | 4 total | ~3.5 (all services) |
| A1.Flex RAM | 24 GB total | ~18 GB |
| Block Volume | 200 GB total | ~60 GB (2 nodes × 50 GB OS + PVCs) |
| OCIR Storage | 500 MB | ~1.5 GB ⚠️ — may exceed free tier |
| Object Storage | 20 GB | Not used |

> **OCIR tip:** The 500 MB free storage is per-region. Each image layer is shared. If you exceed it, storage is billed at ~$0.0255/GB/month — very cheap but worth monitoring.  
> Prune old tags with: `oci artifacts container image delete --image-id <ocid>`

---

## Troubleshooting

### Pods stuck in `ImagePullBackOff`

```bash
# Check the OCIR pull secret
kubectl get secret ocir-secret -n marty-prod -o yaml

# Re-create it
kubectl delete secret ocir-secret -n marty-prod
./scripts/deploy-oracle.sh setup-secrets
```

### Cloudflared not connecting

```bash
kubectl logs deployment/cloudflared -n marty-prod

# Verify the tunnel token is set
kubectl get secret cloudflared-secret -n marty-prod -o jsonpath='{.data.CLOUDFLARE_TUNNEL_TOKEN}' | base64 -d | head -c 10
```

### Keycloak not starting

```bash
kubectl describe pod -l app=keycloak -n marty-prod
kubectl logs -l app=keycloak -n marty-prod --previous
```

### ARM compatibility issues

If you see `exec format error` in pod logs, your image was built for the wrong architecture:

```bash
# Check what arch an image is
docker manifest inspect <image>

# Rebuild for arm64
./scripts/build-push-ocir.sh --platform linux/arm64 --tag prod-arm64 ...

# Or switch OKE node pool to x86 (VM.Standard.E2.1.Micro — still free, 1 OCPU / 1 GB RAM per node)
```

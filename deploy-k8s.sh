#!/bin/bash

# Marty UI - Kubernetes Deployment Script
set -e

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
DEMO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CLUSTER_NAME="${CLUSTER_NAME:-marty-ui}"
NAMESPACE="${NAMESPACE:-marty-ui}"
IMAGE_TAG="${IMAGE_TAG:-latest}"
REGISTRY="${REGISTRY:-localhost:5001}"

echo -e "${BLUE}🚀 Marty UI - Kubernetes Deployment${NC}"
echo -e "${BLUE}===================================${NC}"

# Function to print step headers
print_step() {
    echo -e "\n${YELLOW}📦 $1${NC}"
}

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Check prerequisites
print_step "Checking prerequisites..."

if ! command_exists kind; then
    echo -e "${RED}❌ Kind is not installed${NC}"
    echo -e "${YELLOW}💡 Install with: brew install kind${NC}"
    exit 1
fi

if ! command_exists kubectl; then
    echo -e "${RED}❌ kubectl is not installed${NC}"
    echo -e "${YELLOW}💡 Install with: brew install kubectl${NC}"
    exit 1
fi

echo -e "${GREEN}✅ Prerequisites satisfied${NC}"

cd "$DEMO_DIR"

# Create Kind cluster if it doesn't exist
print_step "Setting up Kind cluster..."

if ! kind get clusters | grep -q "$CLUSTER_NAME"; then
    echo -e "🏗️  Creating Kind cluster: $CLUSTER_NAME..."
    attempts=0
    max_attempts=2
    while [ $attempts -lt $max_attempts ]; do
        if kind create cluster --config=k8s/kind-config.yaml --name="$CLUSTER_NAME"; then
            echo -e "${GREEN}✅ Kind cluster created successfully${NC}"
            break
        else
            attempts=$((attempts+1))
            echo -e "${YELLOW}⚠️  Cluster creation failed (attempt $attempts/$max_attempts). Retrying after cleanup...${NC}"
            kind delete cluster --name "$CLUSTER_NAME" >/dev/null 2>&1 || true
            sleep 5
        fi
    done
    if ! kind get clusters | grep -q "$CLUSTER_NAME"; then
        echo -e "${RED}❌ Failed to create Kind cluster after $max_attempts attempts${NC}"
        exit 1
    fi
    echo -e "⏳ Waiting for cluster node readiness..."
    kubectl wait --for=condition=Ready nodes --all --timeout=300s || echo -e "${YELLOW}⚠️  Node readiness wait timed out, continuing${NC}"
else
    echo -e "${GREEN}✅ Kind cluster '$CLUSTER_NAME' already exists${NC}"
fi

# Set kubectl context
echo -e "🔧 Setting kubectl context..."
kubectl config use-context kind-$CLUSTER_NAME

# Install ingress controller
print_step "Installing NGINX Ingress Controller..."
kubectl apply -f https://raw.githubusercontent.com/kubernetes/ingress-nginx/main/deploy/static/provider/kind/deploy.yaml

echo -e "⏳ Waiting for ingress controller to be ready..."
kubectl wait --namespace ingress-nginx \
  --for=condition=ready pod \
  --selector=app.kubernetes.io/component=controller \
  --timeout=300s

# Load Docker images into Kind cluster
print_step "Loading Docker images into Kind cluster..."

for service in issuer verifier wallet ui; do
    image_name="${REGISTRY}/marty-ui-${service}:${IMAGE_TAG}"
    if docker images | grep -q "marty-ui-${service}"; then
        echo -e "📥 Loading ${image_name}..."
        kind load docker-image "$image_name" --name="$CLUSTER_NAME"
    else
        echo -e "${YELLOW}⚠️  Image marty-ui-${service} not found. Run ./build.sh first.${NC}"
    fi
done

# Apply Kubernetes manifests
print_step "Deploying application manifests..."

echo -e "📝 Applying namespace and configuration..."
kubectl apply -f k8s/namespace-and-config.yaml

echo -e "📝 Applying PostgreSQL..."
kubectl apply -f k8s/postgres.yaml

echo -e "⏳ Waiting for PostgreSQL to be ready..."
kubectl wait --for=condition=ready pod -l app=postgres -n "$NAMESPACE" --timeout=300s

echo -e "📝 Applying application services..."
kubectl apply -f k8s/issuer-service.yaml
kubectl apply -f k8s/verifier-service.yaml
kubectl apply -f k8s/wallet-service.yaml
kubectl apply -f k8s/demo-ui.yaml

# Wait for deployments
print_step "Waiting for all deployments to be ready..."
kubectl wait --for=condition=available --timeout=300s deployment --all -n "$NAMESPACE"

# Verify deployment
print_step "Verifying deployment..."

echo -e "🔍 Checking pod status..."
kubectl get pods -n "$NAMESPACE"

echo -e "\n🔍 Checking service status..."
kubectl get services -n "$NAMESPACE"

echo -e "\n🔍 Checking ingress status..."
kubectl get ingress -n "$NAMESPACE"

# Health checks
print_step "Running health checks via ingress (http://localhost:9080) ..."

echo -e "⏳ Polling ingress for readiness (up to 60s)..."
for i in {1..12}; do
    if curl -sf http://localhost:9080/ >/dev/null; then
         echo -e "${GREEN}✅ UI root responding${NC}"; break; fi
    sleep 5
    [ $i -eq 12 ] && echo -e "${YELLOW}⚠️  UI still not responding at http://localhost:9080/ (may still be starting)${NC}" || true
done

services=(issuer verifier wallet)
for svc in "${services[@]}"; do
    url="http://localhost:9080/api/${svc}/health"
    if curl -sf "$url" >/dev/null; then
        echo -e "${GREEN}✅ ${svc^} service healthy (${url})${NC}"
    else
        echo -e "${YELLOW}⚠️  ${svc^} service not healthy yet (${url})${NC}"
    fi
done

print_step "Deployment completed!"

echo -e "${GREEN}🎉 OpenWallet Foundation Demo deployed successfully!${NC}"
echo -e "\n${BLUE}📋 Access Information:${NC}"
echo -e "🌐 Demo UI:        http://localhost:9080/"
echo -e "🏥 Health Checks:"
echo -e "   - UI:           http://localhost:9080/ (root path)"
echo -e "   - Issuer API:   http://localhost:9080/api/issuer/health"
echo -e "   - Verifier API: http://localhost:9080/api/verifier/health"
echo -e "   - Wallet API:   http://localhost:9080/api/wallet/health"

echo -e "\n${BLUE}🛠️  Useful Commands:${NC}"
echo -e "📊 View pods:       kubectl get pods -n $NAMESPACE"
echo -e "📋 View logs:       kubectl logs -f deployment/<service-name> -n $NAMESPACE"
echo -e "🔧 Port forward:    kubectl port-forward service/<service-name> 8080:8080 -n $NAMESPACE"
echo -e "🗑️  Delete cluster:  kind delete cluster --name=$CLUSTER_NAME"

echo -e "\n${YELLOW}💡 Note: Ingress exposed on ports 9080 (HTTP) / 9443 (HTTPS). Add '127.0.0.1 marty-ui.local' to /etc/hosts to use hostname routing.${NC}"

#!/bin/bash

# Marty UI - Build Script
set -e

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
DEMO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMAGE_TAG="${IMAGE_TAG:-latest}"
REGISTRY="${REGISTRY:-localhost:5001}"

echo -e "${BLUE}🚀 Marty UI - Build Script${NC}"
echo -e "${BLUE}==========================${NC}"

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

if ! command_exists docker; then
    echo -e "${RED}❌ Docker is not installed${NC}"
    exit 1
fi

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

echo -e "${GREEN}✅ All prerequisites satisfied${NC}"

# Build Docker images
print_step "Building Docker images..."

cd "$DEMO_DIR"

# Build issuer service
echo -e "🏗️  Building issuer service..."
docker build -f docker/issuer.Dockerfile -t ${REGISTRY}/marty-ui-issuer:${IMAGE_TAG} .

# Build verifier service
echo -e "🏗️  Building verifier service..."
docker build -f docker/verifier.Dockerfile -t ${REGISTRY}/marty-ui-verifier:${IMAGE_TAG} .

# Build wallet service
echo -e "🏗️  Building wallet service..."
docker build -f docker/wallet.Dockerfile -t ${REGISTRY}/marty-ui-wallet:${IMAGE_TAG} .

# Build UI application
echo -e "🏗️  Building UI application..."
docker build -f docker/ui.Dockerfile -t ${REGISTRY}/marty-ui-ui:${IMAGE_TAG} .

print_step "Testing images..."

# Test that images were built successfully
for service in issuer verifier wallet ui; do
    if docker images | grep -q "marty-ui-${service}"; then
        echo -e "${GREEN}✅ marty-ui-${service} image built successfully${NC}"
    else
        echo -e "${RED}❌ Failed to build marty-ui-${service} image${NC}"
        exit 1
    fi
done

print_step "Build completed successfully!"
echo -e "${GREEN}🎉 All Docker images built and ready for deployment${NC}"
echo -e "${BLUE}💡 Next step: Run ./deploy-k8s.sh to deploy to Kind cluster${NC}"

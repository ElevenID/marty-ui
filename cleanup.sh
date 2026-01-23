#!/bin/bash

# Marty UI - Cleanup Script
set -e

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
CLUSTER_NAME="${CLUSTER_NAME:-marty-ui}"
NAMESPACE="${NAMESPACE:-marty-ui}"

echo -e "${BLUE}🧹 Marty UI - Cleanup${NC}"
echo -e "${BLUE}=====================${NC}"

# Function to print step headers
print_step() {
    echo -e "\n${YELLOW}📦 $1${NC}"
}

print_step "Cleaning up demo resources..."

# Check if Kind cluster exists
if kind get clusters | grep -q "$CLUSTER_NAME"; then
    echo -e "🗑️  Deleting Kind cluster: $CLUSTER_NAME..."
    kind delete cluster --name="$CLUSTER_NAME"
    echo -e "${GREEN}✅ Kind cluster deleted${NC}"
else
    echo -e "${YELLOW}⚠️  Kind cluster '$CLUSTER_NAME' not found${NC}"
fi

# Clean up Docker images
print_step "Cleaning up Docker images..."

for service in issuer verifier wallet ui; do
    image_name="localhost:5001/marty-ui-${service}"
    if docker images | grep -q "marty-ui-${service}"; then
        echo -e "🗑️  Removing Docker image: ${image_name}..."
        docker rmi "${image_name}:latest" 2>/dev/null || true
        echo -e "${GREEN}✅ Removed ${service} image${NC}"
    else
        echo -e "${YELLOW}⚠️  Image marty-ui-${service} not found${NC}"
    fi
done

# Clean up any dangling images
echo -e "🧹 Cleaning up dangling Docker images..."
docker image prune -f >/dev/null 2>&1 || true

print_step "Cleanup completed!"
echo -e "${GREEN}🎉 All demo resources have been cleaned up${NC}"
echo -e "${BLUE}💡 To redeploy, run ./build.sh followed by ./deploy-k8s.sh${NC}"

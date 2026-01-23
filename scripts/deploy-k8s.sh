#!/bin/bash

# Marty UI - Kubernetes Deployment Script
# This script deploys the complete environment to a Kind cluster

set -euo pipefail

# Configuration
CLUSTER_NAME="marty-ui"
NAMESPACE="marty-ui"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
K8S_DIR="${SCRIPT_DIR}/../k8s"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."

    local missing_deps=()

    if ! command -v kind &> /dev/null; then
        missing_deps+=(kind)
    fi

    if ! command -v kubectl &> /dev/null; then
        missing_deps+=(kubectl)
    fi

    if ! command -v docker &> /dev/null; then
        missing_deps+=(docker)
    fi

    if [ ${#missing_deps[@]} -ne 0 ]; then
        log_error "Missing required dependencies: ${missing_deps[*]}"
        log_info "Please install the missing dependencies and try again."
        exit 1
    fi

    # Check if Docker is running
    if ! docker info >/dev/null 2>&1; then
        log_error "Docker is not running. Please start Docker and try again."
        exit 1
    fi

    log_success "All prerequisites are satisfied"
}

# Create Kind cluster
create_cluster() {
    log_info "Creating Kind cluster: $CLUSTER_NAME"

    if kind get clusters | grep -q "^${CLUSTER_NAME}$"; then
        log_warning "Cluster $CLUSTER_NAME already exists"
        read -p "Do you want to recreate it? (y/N): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            log_info "Deleting existing cluster..."
            kind delete cluster --name "$CLUSTER_NAME"
        else
            log_info "Using existing cluster"
            return 0
        fi
    fi

    kind create cluster --config="${K8S_DIR}/kind-config.yaml" --name="$CLUSTER_NAME"

    # Wait for cluster to be ready
    log_info "Waiting for cluster to be ready..."
    kubectl wait --for=condition=Ready nodes --all --timeout=300s

    log_success "Kind cluster created successfully"
}

# Load container images into Kind
load_images() {
    log_info "Loading container images into Kind cluster..."

    # List of images to load (these would be built separately)
    local images=(
        "marty-ui-issuer:latest"
        "marty-ui-verifier:latest"
        "marty-ui-wallet:latest"
        "marty-ui-ui:latest"
    )

    for image in "${images[@]}"; do
        if docker image inspect "$image" >/dev/null 2>&1; then
            log_info "Loading image: $image"
            kind load docker-image "$image" --name="$CLUSTER_NAME"
        else
            log_warning "Image $image not found locally. Skipping..."
            log_info "Note: You'll need to build this image first or it will fail to deploy"
        fi
    done

    log_success "Images loaded successfully"
}

# Install ingress controller
install_ingress() {
    log_info "Installing ingress controller..."

    kubectl apply -f https://raw.githubusercontent.com/kubernetes/ingress-nginx/main/deploy/static/provider/kind/deploy.yaml

    log_info "Waiting for ingress controller to be ready..."
    kubectl wait --namespace ingress-nginx \
        --for=condition=ready pod \
        --selector=app.kubernetes.io/component=controller \
        --timeout=300s

    log_success "Ingress controller installed successfully"
}

# Deploy demo applications
deploy_demo() {
    log_info "Deploying OpenWallet Foundation demo applications..."

    # Apply manifests in order
    local manifests=(
        "namespace-and-config.yaml"
        "postgres.yaml"
        "issuer-service.yaml"
        "verifier-service.yaml"
        "wallet-service.yaml"
        "demo-ui.yaml"
    )

    for manifest in "${manifests[@]}"; do
        log_info "Applying manifest: $manifest"
        kubectl apply -f "${K8S_DIR}/${manifest}"
    done

    log_info "Waiting for deployments to be ready..."

    # Wait for PostgreSQL
    kubectl wait --namespace="$NAMESPACE" \
        --for=condition=available deployment/postgres \
        --timeout=300s

    # Wait for services
    kubectl wait --namespace="$NAMESPACE" \
        --for=condition=available deployment/issuer-service \
        --timeout=300s

    kubectl wait --namespace="$NAMESPACE" \
        --for=condition=available deployment/verifier-service \
        --timeout=300s

    kubectl wait --namespace="$NAMESPACE" \
        --for=condition=available deployment/wallet-service \
        --timeout=300s

    kubectl wait --namespace="$NAMESPACE" \
        --for=condition=available deployment/demo-ui \
        --timeout=300s

    log_success "Demo applications deployed successfully"
}

# Display access information
display_access_info() {
    log_success "Marty UI is ready!"
    echo
    log_info "Access URLs:"
    echo "  • Demo UI:          http://localhost:3000"
    echo "  • Issuer Service:   http://localhost:8090"
    echo "  • Verifier Service: http://localhost:8091"
    echo "  • Wallet Service:   http://localhost:8092"
    echo "  • Ingress (via web): http://marty-ui.local:8080"
    echo
    log_info "Add this to your /etc/hosts file for ingress access:"
    echo "  127.0.0.1 marty-ui.local"
    echo
    log_info "Useful commands:"
    echo "  • View logs:        kubectl logs -n $NAMESPACE -l app=<service-name> -f"
    echo "  • Port forward:     kubectl port-forward -n $NAMESPACE svc/<service-name> <local-port>:<service-port>"
    echo "  • Delete cluster:   kind delete cluster --name $CLUSTER_NAME"
    echo
    log_info "Demo includes:"
    echo "  • mDoc/mDL Issuer using Multipaz SDK"
    echo "  • OpenID4VP Verifier with multiple presentation scenarios"
    echo "  • Wallet service with proximity and remote presentation"
    echo "  • Interactive web UI for testing all flows"
    echo "  • Sample credentials and users pre-configured"
}

# Cleanup function
cleanup() {
    if [ $? -ne 0 ]; then
        log_error "Deployment failed. Checking cluster state..."
        kubectl get pods -n "$NAMESPACE" || true
        kubectl get services -n "$NAMESPACE" || true
    fi
}

# Main deployment function
main() {
    trap cleanup EXIT

    log_info "Starting OpenWallet Foundation mDoc/mDL Demo deployment..."

    check_prerequisites
    create_cluster
    load_images
    install_ingress
    deploy_demo
    display_access_info

    log_success "Deployment completed successfully!"
}

# Help function
show_help() {
    echo "OpenWallet Foundation mDoc/mDL Demo Deployment Script"
    echo
    echo "Usage: $0 [OPTIONS]"
    echo
    echo "Options:"
    echo "  -h, --help     Show this help message"
    echo "  --cleanup      Delete the demo cluster"
    echo "  --status       Show cluster status"
    echo
    echo "Examples:"
    echo "  $0                 # Deploy the demo"
    echo "  $0 --cleanup       # Delete the demo cluster"
    echo "  $0 --status        # Show cluster status"
}

# Handle command line arguments
case "${1:-}" in
    -h|--help)
        show_help
        exit 0
        ;;
    --cleanup)
        log_info "Deleting cluster: $CLUSTER_NAME"
        kind delete cluster --name "$CLUSTER_NAME"
        log_success "Cluster deleted successfully"
        exit 0
        ;;
    --status)
        log_info "Cluster status for: $CLUSTER_NAME"
        if kind get clusters | grep -q "^${CLUSTER_NAME}$"; then
            kubectl cluster-info --context "kind-${CLUSTER_NAME}"
            echo
            kubectl get pods -n "$NAMESPACE" 2>/dev/null || echo "Demo namespace not found"
        else
            log_warning "Cluster $CLUSTER_NAME does not exist"
        fi
        exit 0
        ;;
    "")
        # No arguments, proceed with deployment
        main
        ;;
    *)
        log_error "Unknown option: $1"
        show_help
        exit 1
        ;;
esac

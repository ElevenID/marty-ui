# OpenWallet Foundation mDoc/mDL Demo

A comprehensive demonstration of mobile document (mDoc) and mobile driving license (mDL) functionality using the OpenWallet Foundation's Multipaz SDK, deployed on Kubernetes with Kind.

## Overview

This demo showcases a complete mDoc/mDL ecosystem including:

- **Issuer Service**: Issues mDL credentials using ISO 18013-5 standards
- **Verifier Service**: Verifies mDoc presentations using OpenID4VP
- **Wallet Service**: Manages credential storage and selective disclosure
- **Demo UI**: Interactive web interface for testing all flows

## Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Demo UI       │    │   Issuer API    │    │  Verifier API   │
│ (React/Nginx)   │    │   (FastAPI)     │    │   (FastAPI)     │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         └───────────────────────┼───────────────────────┘
                                 │
         ┌─────────────────┐    ┌─────────────────┐
         │   Wallet API    │    │   PostgreSQL    │
         │   (FastAPI)     │    │   (Database)    │
         └─────────────────┘    └─────────────────┘
```

All services run in a Kubernetes cluster managed by Kind, with ingress routing and persistent storage.

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

### 1. Build and Deploy

```bash
# Navigate to the Marty UI directory
cd marty-ui

# Build all services (including enhanced features)
./build.sh

# Deploy to Kind cluster
./deploy-k8s.sh

# Access the demo
open http://localhost
```

### 2. Explore Enhanced Features

- **Basic Demo**: Use the Issuer, Verifier, and Wallet tabs for standard mDoc/mDL operations
- **Enhanced Demo**: Click the "Enhanced" tab to explore advanced features:
  - Age verification without birth date disclosure
  - Offline QR code verification
  - Certificate lifecycle monitoring
  - Policy-based selective disclosure

## Prerequisites

- **Docker**: For building container images
- **Kind**: For local Kubernetes cluster
- **kubectl**: For Kubernetes management
- **Node.js** (optional): For UI development

### macOS Installation

```bash
# Install using Homebrew
brew install kind kubectl

# Docker Desktop or Docker Engine required
# Download from: https://docs.docker.com/desktop/mac/
```

### Ubuntu/Debian Installation

```bash
# Install kubectl
curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
sudo install -o root -g root -m 0755 kubectl /usr/local/bin/kubectl

# Install Kind
curl -Lo ./kind https://kind.sigs.k8s.io/dl/v0.20.0/kind-linux-amd64
chmod +x ./kind
sudo mv ./kind /usr/local/bin/kind

# Install Docker
sudo apt update
sudo apt install docker.io
sudo systemctl start docker
sudo usermod -aG docker $USER
```

## Quick Start

1. **Build the demo containers:**

   ```bash
   ./build.sh
   ```

2. **Deploy to Kind cluster:**

   ```bash
   ./deploy-k8s.sh
   ```

3. **Access the demo:**
   - Demo UI: <http://localhost/>
   - API Health Checks: <http://localhost/health>

4. **Clean up when done:**

   ```bash
   ./cleanup.sh
   ```

## Detailed Usage

### Building Images

The build script creates Docker images for all services:

```bash
./build.sh
```

This will:

- Check prerequisites (Docker, Kind, kubectl)
- Build Docker images for issuer, verifier, wallet, and UI services
- Tag images for local registry use
- Verify successful builds

### Deployment

The deployment script sets up a complete Kubernetes environment:

```bash
./deploy-k8s.sh
```

This will:

- Create a Kind cluster with ingress support
- Install NGINX Ingress Controller
- Load Docker images into the cluster
- Deploy PostgreSQL database
- Deploy all application services
- Wait for all pods to be ready
- Run health checks

### Using the Demo

1. **Navigate to <http://localhost/>** in your browser

2. **Issuer Demo:**
   - Click "Issuer Demo" to access credential issuance
   - Fill in personal information (name, date of birth, license number)
   - Click "Issue Credential" to create an mDL
   - QR code will be generated for mobile wallet scanning

3. **Verifier Demo:**
   - Click "Verifier Demo" to access verification
   - Select required attributes (age_over_18, driving_privileges, etc.)
   - Generate verification request
   - Scan QR code with mobile wallet to present credentials

4. **Wallet Demo:**
   - Click "Wallet Demo" to access credential management
   - View stored credentials
   - Test selective disclosure by choosing which attributes to share
   - Manage credential lifecycle (store, present, delete)

### API Endpoints

#### Issuer Service (Port 8080)

- `POST /issue` - Issue new mDL credential
- `GET /health` - Health check
- `GET /docs` - OpenAPI documentation

#### Verifier Service (Port 8081)

- `POST /verify` - Verify mDoc presentation
- `POST /request` - Create verification request
- `GET /health` - Health check
- `GET /docs` - OpenAPI documentation

#### Wallet Service (Port 8082)

- `POST /store` - Store credential in wallet
- `GET /credentials` - List stored credentials
- `POST /present` - Create presentation
- `DELETE /credentials/{id}` - Delete credential
- `GET /health` - Health check
- `GET /docs` - OpenAPI documentation

## Configuration

### Environment Variables

The demo supports the following environment variables:

- `CLUSTER_NAME`: Kind cluster name (default: `marty-ui`)
- `NAMESPACE`: Kubernetes namespace (default: `marty-ui`)
- `IMAGE_TAG`: Docker image tag (default: `latest`)
- `REGISTRY`: Container registry (default: `localhost:5001`)

### Database Configuration

PostgreSQL is configured with:

- Database: `marty_ui`
- Username: `demo_user`
- Password: `demo_password`
- Port: 5432

### Kubernetes Resources

Each service is allocated:

- CPU: 100m (request) / 500m (limit)
- Memory: 128Mi (request) / 512Mi (limit)
- Replicas: 1 (can be scaled)

## Development

### Local Development Setup

For development outside Kubernetes:

1. **Start PostgreSQL:**

   ```bash
    docker run --name postgres-dev \
       -e POSTGRES_DB=marty_ui \
     -e POSTGRES_USER=demo_user \
     -e POSTGRES_PASSWORD=demo_password \
     -p 5432:5432 -d postgres:15
   ```

2. **Install Python dependencies:**

   ```bash
   cd src
   pip install -r requirements.txt
   ```

3. **Run services:**

   ```bash
   # Terminal 1 - Issuer
   uvicorn issuer_service:app --host 0.0.0.0 --port 8080 --reload

   # Terminal 2 - Verifier  
   uvicorn verifier_service:app --host 0.0.0.0 --port 8081 --reload

   # Terminal 3 - Wallet
   uvicorn wallet_service:app --host 0.0.0.0 --port 8082 --reload
   ```

4. **Run UI (optional):**

   ```bash
   cd ui
   npm install
   npm start
   ```

### Customizing Services

#### Adding New Document Types

Edit `src/issuer_service.py` to add new document types:

```python
DOCUMENT_TYPES = {
    "driving_license": {
        "namespace": "org.iso.18013.5.1.mDL",
        "required_fields": ["family_name", "given_name", "birth_date", "issue_date", "expiry_date"]
    },
    "identity_card": {
        "namespace": "org.iso.18013.5.1.mID",
        "required_fields": ["family_name", "given_name", "birth_date", "nationality"]
    }
}
```

#### Modifying Verification Logic

Edit `src/verifier_service.py` to customize verification requirements:

```python
VERIFICATION_POLICIES = {
    "age_verification": {
        "required_attributes": ["age_over_18", "age_over_21"],
        "optional_attributes": ["birth_date"]
    },
    "identity_verification": {
        "required_attributes": ["family_name", "given_name", "birth_date"],
        "optional_attributes": ["portrait", "address"]
    }
}
```

## Troubleshooting

### Common Issues

1. **Port conflicts:**

   ```bash
   # Check what's using port 80
   lsof -i :80

   # Kill conflicting processes or change ingress port
   kubectl patch service ingress-nginx-controller -n ingress-nginx -p '{"spec":{"ports":[{"port":8080,"targetPort":80}]}}'
   ```

2. **Images not loading:**

   ```bash
   # Verify images exist
   docker images | grep marty-ui

   # Rebuild if missing
   ./build.sh

   # Load into Kind manually
   kind load docker-image localhost:5001/marty-ui-issuer:latest --name marty-ui
   ```

3. **Pods not starting:**

   ```bash
   # Check pod logs
   kubectl logs -f deployment/issuer-service -n marty-ui

   # Check resource usage
   kubectl top pods -n marty-ui

   # Describe pod for events
   kubectl describe pod <pod-name> -n marty-ui
   ```

4. **Database connection issues:**

   ```bash
   # Check PostgreSQL pod
   kubectl logs -f deployment/postgres -n marty-ui

   # Test database connection
   kubectl exec -it deployment/postgres -n marty-ui -- psql -U demo_user -d marty_ui
   ```

### Logs and Monitoring

View service logs:

```bash
# All services
kubectl logs -f -l app=issuer-service -n marty-ui
kubectl logs -f -l app=verifier-service -n marty-ui
kubectl logs -f -l app=wallet-service -n marty-ui
kubectl logs -f -l app=demo-ui -n marty-ui

# Combined logs
kubectl logs -f --selector=tier=backend -n marty-ui
```

Monitor resource usage:

```bash
# Pod resource usage
kubectl top pods -n marty-ui

# Node resource usage  
kubectl top nodes

# Describe services
kubectl describe services -n marty-ui
```

## Security Considerations

### Production Deployment

This demo is for **educational and testing purposes only**. For production use:

1. **Use proper certificates**: Replace self-signed certificates with CA-issued ones
2. **Implement authentication**: Add proper API authentication and authorization
3. **Secure database**: Use encrypted connections and strong passwords
4. **Network security**: Implement proper network policies and TLS
5. **Key management**: Use hardware security modules (HSMs) for key storage
6. **Audit logging**: Implement comprehensive audit trails
7. **Update dependencies**: Regularly update all dependencies for security patches

### Known Limitations

- Mock implementation of Multipaz SDK (requires JNI integration for production)
- Self-signed certificates for testing only
- In-memory key storage (should use HSMs in production)
- No rate limiting or authentication
- Development-grade database configuration

## Standards and Compliance

This demo implements:

- **ISO 18013-5**: Mobile driving license standard
- **ISO 23220-1**: Building blocks for identity management
- **OpenID4VP**: OpenID for Verifiable Presentations
- **W3C VC Data Model**: Verifiable Credentials specification
- **CBOR**: Concise Binary Object Representation
- **COSE**: CBOR Object Signing and Encryption

## Contributing

To contribute to this demo:

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

This demo is released under the MIT License. See LICENSE file for details.

## Resources

- [OpenWallet Foundation](https://openwallet.foundation/)
- [ISO 18013-5 Standard](https://www.iso.org/standard/69084.html)
- [OpenID4VP Specification](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html)
- [Kind Documentation](https://kind.sigs.k8s.io/)
- [Kubernetes Documentation](https://kubernetes.io/docs/)

---

For questions or support, please create an issue in the repository or contact the development team.

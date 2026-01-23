# Project Structure Summary

## Marty UI

This directory contains the production Marty UI and associated services, deployed on Kubernetes with Kind.

### Directory Structure

```
marty-ui/
├── README.md                    # Comprehensive documentation
├── build.sh                     # Script to build Docker images
├── deploy-k8s.sh               # Script to deploy to Kind cluster
├── cleanup.sh                   # Script to clean up resources
│
├── src/                         # Python backend services
│   ├── requirements.txt         # Python dependencies
│   ├── issuer_service.py        # Credential issuance service
│   ├── verifier_service.py      # Credential verification service
│   └── wallet_service.py        # Credential management service
│
├── ui/                          # React frontend application
│   ├── package.json             # Node.js dependencies
│   ├── nginx.conf               # Nginx configuration for production
│   ├── public/                  # Static assets
│   └── src/                     # React components
│       ├── App.js               # Main application component
│       ├── components/          # UI components
│       │   ├── Navigation.js    # Navigation component
│       │   ├── Home.js          # Home page
│       │   ├── IssuerDemo.js    # Issuer demonstration
│       │   ├── VerifierDemo.js  # Verifier demonstration
│       │   └── WalletDemo.js    # Wallet demonstration
│       └── index.js             # Application entry point
│
├── k8s/                         # Kubernetes manifests
│   ├── kind-config.yaml         # Kind cluster configuration
│   ├── namespace-and-config.yaml # Namespace and ConfigMap
│   ├── postgres.yaml            # PostgreSQL database
│   ├── issuer-service.yaml      # Issuer service deployment
│   ├── verifier-service.yaml    # Verifier service deployment
│   ├── wallet-service.yaml      # Wallet service deployment
│   └── demo-ui.yaml             # UI application deployment
│
└── docker/                      # Docker configurations
    ├── issuer.Dockerfile        # Issuer service container
    ├── verifier.Dockerfile      # Verifier service container
    ├── wallet.Dockerfile        # Wallet service container
    └── ui.Dockerfile            # UI application container
```

### Key Features

1. **Complete mDoc/mDL Ecosystem**: Includes issuer, verifier, wallet services and UI
2. **Kubernetes Deployment**: Fully configured for Kind cluster deployment
3. **Standards Compliant**: Implements ISO 18013-5 and OpenID4VP standards
4. **Interactive Demo**: Web UI for testing all credential flows
5. **Production Ready**: Includes health checks, ingress, and monitoring

### Quick Start

1. `./build.sh` - Build all Docker images
2. `./deploy-k8s.sh` - Deploy to Kind cluster
3. Open <http://localhost/> - Access demo UI
4. `./cleanup.sh` - Clean up when done

### Technologies Used

- **Backend**: Python, FastAPI, PostgreSQL
- **Frontend**: React.js, Material-UI, Nginx
- **Orchestration**: Kubernetes, Kind, Docker
- **Standards**: ISO 18013-5, OpenID4VP, W3C VC
- **Security**: CBOR, COSE, mso_mdoc format

This demo provides a complete reference implementation for mDoc/mDL systems using modern cloud-native technologies and industry standards.

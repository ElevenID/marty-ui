# OpenWallet Foundation Demo - E2E Tests

Comprehensive end-to-end tests for the mDoc/mDL demo using Playwright.

## Overview

This test suite validates the complete functionality of the OpenWallet Foundation mDoc/mDL demo, including:

- ✅ **Basic Demo Flow**: Issuer, Verifier, and Wallet functionality
- 🛡️ **Enhanced Features**: Age verification, offline QR, certificate monitoring, policy engine
- 🔄 **Integration Tests**: Complete credential lifecycle workflows
- 🔧 **Cross-browser Testing**: Chrome, Firefox, Safari support
- 📱 **Responsive Design**: Mobile and tablet viewport testing
- ♿ **Accessibility**: Keyboard navigation and screen reader compatibility

## Quick Start

### Prerequisites

- Node.js 18+
- Demo running at `http://localhost` (use `./deploy-k8s.sh`)

### Install and Run

```bash
# Navigate to test directory
cd tests/

# Install dependencies
npm install

# Install browsers
npx playwright install

# Run all tests
npm test

# Run with UI mode
npm run test:ui

# Run specific test suite
npm run test:basic
npm run test:enhanced
npm run test:integration
```

### Using Test Runner Script

```bash
# Run tests with automatic demo setup
./run-tests.sh

# Run in headed mode
./run-tests.sh --headed

# Debug mode
./run-tests.sh --debug

# Specific browser
./run-tests.sh --browser firefox
```

## Test Structure

### Test Files

```
tests/
├── e2e/
│   ├── basic-demo.spec.js       # Core functionality tests
│   ├── enhanced-features.spec.js # Enhanced features tests
│   └── integration.spec.js       # End-to-end workflows
├── utils/
│   ├── test-helpers.js          # Reusable test utilities
│   ├── global-setup.js          # Test environment setup
│   └── global-teardown.js       # Test cleanup
├── playwright.config.js         # Playwright configuration
├── package.json                 # Dependencies and scripts
└── run-tests.sh                 # Test runner script
```

### Test Categories

#### 1. Basic Demo Flow Tests (`basic-demo.spec.js`)

- Navigation and UI components
- Issuer service credential issuance
- Verifier service presentation verification
- Wallet service credential management
- Responsive design validation

#### 2. Enhanced Features Tests (`enhanced-features.spec.js`)

- Age verification with selective disclosure
- Offline QR code generation and verification
- Certificate lifecycle monitoring
- Policy-based selective disclosure
- Feature integration and performance

#### 3. Integration Tests (`integration.spec.js`)

- Complete credential lifecycle workflows
- Cross-feature integration scenarios
- Error handling and recovery
- Security and privacy validation
- Accessibility and usability testing

## Test Configuration

### Environment Variables

```bash
# Base URL for the demo application
BASE_URL=http://localhost

# Browser selection
BROWSER=chromium  # chromium, firefox, webkit

# Test mode
HEADED=false     # Run with browser UI
DEBUG=false      # Enable debug mode
```

### Playwright Configuration

Key configuration options in `playwright.config.js`:

- **Multi-browser Support**: Chrome, Firefox, Safari
- **Mobile Testing**: iPhone, Android viewports
- **Parallel Execution**: Faster test runs
- **Automatic Screenshots**: On failure
- **Video Recording**: For failed tests
- **Global Setup/Teardown**: Demo readiness checks

## Test Utilities

### DemoTestHelpers Class

Provides reusable methods for common operations:

```javascript
const helpers = new DemoTestHelpers(page);

// Navigation
await helpers.navigateToTab('Enhanced');

// Form interactions
await helpers.fillFormField('Given Name', 'Jane');
await helpers.clickButton('Create Request');

// API mocking
await helpers.mockApiResponse('/api/issuer/issue', mockResponse);

// Assertions
await helpers.verifySuccessMessage('Credential issued!');
await helpers.verifyChipStatus('VERIFIED', 'success');
```

### Mock Data

Pre-defined mock responses for API testing:

- `mockCredentialData`: Sample credential information
- `mockVerifiablePresentation`: Valid presentation format
- `mockApiResponses`: Success responses for all endpoints

## Test Scenarios

### Core Functionality

1. **Home Page Load**: Navigation, UI components, feature overview
2. **Credential Issuance**: Step-by-step issuance workflow
3. **Presentation Verification**: QR scanning, verification checks
4. **Wallet Management**: Credential storage, sharing, deletion

### Enhanced Features

1. **Age Verification**:
   - Multiple use cases (alcohol, voting, employment)
   - Privacy-preserving selective disclosure
   - Zero-knowledge proof simulation

2. **Offline QR Verification**:
   - QR code generation with CBOR encoding
   - Network-free verification
   - Cryptographic signature validation

3. **Certificate Monitoring**:
   - DSC lifecycle tracking
   - Expiry alerts and renewal
   - Certificate health dashboard

4. **Policy Engine**:
   - Context-aware disclosure decisions
   - Trust level assessment
   - Privacy score calculation

### Integration Workflows

1. **Complete Lifecycle**: Issue → Store → Share → Verify
2. **Privacy-Preserving Flow**: Issue → Age Verify → Policy Check
3. **Offline Scenario**: Issue → Generate QR → Offline Verify
4. **Certificate Validation**: Monitor → Renew → Verify Chain

## Error Handling

### Test Resilience

- **Service Failures**: Graceful degradation testing
- **Network Issues**: Offline/online transitions
- **Invalid Data**: Malformed credentials and presentations
- **Authentication Errors**: Invalid signatures and certificates

### Debugging

```bash
# Run specific test with debug
npx playwright test basic-demo.spec.js --debug

# Record test for replay
npx playwright codegen http://localhost

# View test report
npx playwright show-report

# Screenshots and videos
ls test-results/
```

## Continuous Integration

### GitHub Actions

Automated testing on:

- Push to main/develop branches
- Pull requests
- Manual workflow dispatch

### CI/CD Features

- **Multi-browser Matrix**: Parallel testing across browsers
- **Demo Deployment**: Automatic Kind cluster setup
- **Artifact Collection**: Screenshots, videos, reports
- **Failure Analysis**: Logs and diagnostics

### Local CI Simulation

```bash
# Simulate CI environment
CI=true npm test

# Generate JUnit reports
npm run test:ci
```

## Best Practices

### Writing Tests

1. **Use Page Object Pattern**: Encapsulate UI interactions
2. **Mock API Responses**: Consistent, fast, reliable tests
3. **Test User Journeys**: Real-world scenarios
4. **Assert Meaningful States**: Not just presence, but correctness
5. **Handle Async Operations**: Proper waits and timeouts

### Maintenance

1. **Keep Tests Independent**: No shared state between tests
2. **Use Descriptive Names**: Clear test intentions
3. **Update with Features**: Tests should evolve with code
4. **Monitor Performance**: Test execution time
5. **Review Failures**: Distinguish real issues from flaky tests

## Troubleshooting

### Common Issues

1. **Demo Not Running**:

   ```bash
   cd marty-ui
   ./deploy-k8s.sh
   ```

2. **Browser Installation**:

   ```bash
   npx playwright install
   ```

3. **Port Conflicts**:

   ```bash
   BASE_URL=http://localhost:3000 npm test
   ```

4. **Timeout Issues**:
   - Increase timeouts in `playwright.config.js`
   - Check demo performance
   - Verify network connectivity

### Support

For issues with the test suite:

1. Check demo application logs
2. Review Playwright documentation
3. Examine test failure screenshots
4. Run tests in debug mode

## Performance Benchmarks

### Expected Test Times

- **Basic Demo Tests**: ~2-3 minutes
- **Enhanced Features**: ~3-4 minutes
- **Integration Tests**: ~4-5 minutes
- **Full Suite**: ~8-10 minutes

### Optimization

- Parallel execution across test files
- API mocking for faster responses
- Strategic use of `waitForLoadState`
- Minimal screenshot/video capture

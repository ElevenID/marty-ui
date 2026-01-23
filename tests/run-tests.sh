#!/bin/bash

# OpenWallet Foundation Demo - E2E Test Runner
set -e

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEMO_DIR="$(dirname "$TEST_DIR")"
BROWSER="${BROWSER:-chromium}"
HEADED="${HEADED:-false}"
DEBUG="${DEBUG:-false}"
BASE_URL="${BASE_URL:-http://localhost:9080}"

echo -e "${BLUE}🧪 OpenWallet Foundation Demo - E2E Test Runner${NC}"
echo -e "${BLUE}===============================================${NC}"

# Function to print step headers
print_step() {
    echo -e "\n${YELLOW}🔧 $1${NC}"
}

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to check if demo is running
check_demo_status() {
    if curl -f "$BASE_URL" > /dev/null 2>&1; then
        return 0
    else
        return 1
    fi
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --browser)
            BROWSER="$2"
            shift 2
            ;;
        --headed)
            HEADED="true"
            shift
            ;;
        --debug)
            DEBUG="true"
            shift
            ;;
        --help)
            echo "Usage: $0 [options]"
            echo "Options:"
            echo "  --browser BROWSER   Browser to use (chromium, firefox, webkit)"
            echo "  --headed           Run tests in headed mode"
            echo "  --debug            Run tests in debug mode"
            echo "  --help             Show this help message"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

print_step "Checking prerequisites..."

# Check if Node.js is installed
if ! command_exists node; then
    echo -e "${RED}❌ Node.js is not installed${NC}"
    echo -e "${YELLOW}💡 Install with: brew install node${NC}"
    exit 1
fi

# Check if npm is installed
if ! command_exists npm; then
    echo -e "${RED}❌ npm is not installed${NC}"
    exit 1
fi

echo -e "${GREEN}✅ Prerequisites satisfied${NC}"

print_step "Installing test dependencies..."

cd "$TEST_DIR"

# Install dependencies if needed
if [ ! -d "node_modules" ]; then
    echo "📦 Installing npm dependencies..."
    npm install
fi

# Install Playwright browsers if needed
if [ ! -d "node_modules/@playwright" ]; then
    echo "🎭 Installing Playwright..."
    npm install @playwright/test
fi

echo "🌐 Installing Playwright browsers..."
npx playwright install "$BROWSER" --with-deps

print_step "Checking demo status..."

if check_demo_status; then
    echo -e "${GREEN}✅ Demo is running at $BASE_URL${NC}"
else
    echo -e "${YELLOW}⚠️  Demo is not running at $BASE_URL${NC}"
    echo -e "${YELLOW}💡 Start the demo with: cd $DEMO_DIR && ./deploy-k8s.sh${NC}"

    read -p "Would you like to start the demo now? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        print_step "Starting demo..."
        cd "$DEMO_DIR"

        echo "🏗️  Building demo services..."
        ./build.sh

        echo "🚀 Deploying to Kind cluster..."
        ./deploy-k8s.sh

        echo "⏳ Waiting for demo to be ready..."
        timeout 300 bash -c "until curl -f $BASE_URL > /dev/null 2>&1; do sleep 5; done"

        echo -e "${GREEN}✅ Demo is now running!${NC}"
        cd "$TEST_DIR"
    else
        echo -e "${RED}❌ Cannot run tests without demo running${NC}"
        exit 1
    fi
fi

print_step "Running E2E tests..."

# Build test command
TEST_CMD="npx playwright test --project=$BROWSER"

if [ "$HEADED" = "true" ]; then
    TEST_CMD="$TEST_CMD --headed"
fi

if [ "$DEBUG" = "true" ]; then
    TEST_CMD="$TEST_CMD --debug"
fi

# Add environment variables
export BASE_URL="$BASE_URL"

echo -e "${BLUE}🏃 Running tests with: $TEST_CMD${NC}"

# Run tests
if eval "$TEST_CMD"; then
    echo -e "\n${GREEN}🎉 All tests passed!${NC}"

    # Show test report
    if [ -f "playwright-report/index.html" ]; then
        echo -e "${BLUE}📊 Test report available at: playwright-report/index.html${NC}"
        echo -e "${BLUE}💡 View with: npx playwright show-report${NC}"
    fi
else
    echo -e "\n${RED}❌ Some tests failed${NC}"

    # Show failure information
    if [ -d "test-results" ]; then
        echo -e "${YELLOW}📁 Test results saved to: test-results/${NC}"
        echo -e "${YELLOW}🖼️  Screenshots saved to: test-results/screenshots/${NC}"
    fi

    if [ -f "playwright-report/index.html" ]; then
        echo -e "${BLUE}📊 Detailed report: npx playwright show-report${NC}"
    fi

    exit 1
fi

print_step "Test run completed!"
echo -e "${GREEN}✨ E2E testing finished successfully${NC}"

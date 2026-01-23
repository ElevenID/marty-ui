#!/bin/bash
# Pytest runner script for running Python unit/integration tests in Docker
# Usage: ./run-pytest.sh [unit|api-keys|integration|all]

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Print header
echo -e "${BLUE}╔════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║              Marty UI Pytest Runner                            ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════════════╝${NC}"

# Function to print usage
usage() {
    echo ""
    echo "Usage: $0 [command] [options]"
    echo ""
    echo "Commands:"
    echo "  unit              Run all unit tests"
    echo "  api-keys          Run API keys unit tests only"
    echo "  integration       Run integration tests (requires full stack)"
    echo "  all               Run all Python tests"
    echo "  build             Build pytest container only"
    echo "  shell             Open a shell in the pytest container"
    echo "  clean             Clean up containers and test results"
    echo ""
    echo "Options:"
    echo "  -h, --help        Show this help message"
    echo "  -v, --verbose     Extra verbose output"
    echo "  -k PATTERN        Only run tests matching PATTERN"
    echo "  --cov             Generate coverage report"
    echo ""
    echo "Examples:"
    echo "  $0 unit                    # Run all unit tests"
    echo "  $0 api-keys                # Run only API keys tests"
    echo "  $0 unit -k 'test_create'   # Run tests matching 'test_create'"
    echo "  $0 unit --cov              # Run unit tests with coverage"
    echo ""
}

# Default options
VERBOSE=""
PATTERN=""
COVERAGE=""
EXTRA_ARGS=""

# Parse options after command
parse_options() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -v|--verbose)
                VERBOSE="-vv"
                shift
                ;;
            -k)
                PATTERN="-k $2"
                shift 2
                ;;
            --cov)
                COVERAGE="--cov=src --cov-report=html:/app/pytest-results/coverage"
                shift
                ;;
            *)
                EXTRA_ARGS="$EXTRA_ARGS $1"
                shift
                ;;
        esac
    done
}

# Ensure the results directory exists
ensure_results_dir() {
    mkdir -p pytest-results
}

# Build pytest container
build_pytest() {
    echo -e "${YELLOW}Building pytest container...${NC}"
    docker compose -f docker-compose.test.yml --profile pytest build pytest
    echo -e "${GREEN}✓ Build complete${NC}"
}

# Start minimal services needed for unit tests
start_services() {
    echo -e "${YELLOW}Starting minimal services for tests...${NC}"
    docker compose -f docker-compose.test.yml up -d redis applicant-db
    
    # Wait for services to be healthy
    echo -e "${YELLOW}Waiting for services to be ready...${NC}"
    local retries=15
    while [ $retries -gt 0 ]; do
        if docker compose -f docker-compose.test.yml exec -T applicant-db pg_isready -U marty -d marty_applicants > /dev/null 2>&1; then
            break
        fi
        retries=$((retries - 1))
        echo "  Waiting for database... ($retries attempts left)"
        sleep 2
    done
    
    if [ $retries -eq 0 ]; then
        echo -e "${RED}✗ Services failed to start${NC}"
        exit 1
    fi
    
    echo -e "${GREEN}✓ Services ready${NC}"
}

# Run pytest with specified test path
run_pytest() {
    local test_path="${1:-tests/unit/}"
    ensure_results_dir
    
    echo -e "${YELLOW}Running pytest: ${test_path}${NC}"
    
    # Build pytest options
    local pytest_opts="-v --tb=short"
    pytest_opts="$pytest_opts $VERBOSE $PATTERN $COVERAGE $EXTRA_ARGS"
    pytest_opts="$pytest_opts --junitxml=/app/pytest-results/junit.xml"
    pytest_opts="$pytest_opts --html=/app/pytest-results/report.html --self-contained-html"
    
    echo -e "${BLUE}Command: pytest $test_path $pytest_opts${NC}"
    echo ""
    
    docker compose -f docker-compose.test.yml --profile pytest run --rm pytest \
        pytest "$test_path" $pytest_opts
    
    local exit_code=$?
    
    echo ""
    if [ $exit_code -eq 0 ]; then
        echo -e "${GREEN}╔════════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${GREEN}║  ✓ Tests passed!                                               ║${NC}"
        echo -e "${GREEN}╚════════════════════════════════════════════════════════════════╝${NC}"
    else
        echo -e "${RED}╔════════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${RED}║  ✗ Tests failed!                                               ║${NC}"
        echo -e "${RED}╚════════════════════════════════════════════════════════════════╝${NC}"
    fi
    
    echo ""
    echo -e "${BLUE}Test reports saved to:${NC}"
    echo "  - pytest-results/report.html"
    echo "  - pytest-results/junit.xml"
    if [ -n "$COVERAGE" ]; then
        echo "  - pytest-results/coverage/index.html"
    fi
    
    return $exit_code
}

# Run unit tests
run_unit_tests() {
    start_services
    run_pytest "tests/unit/"
}

# Run API keys tests only
run_api_keys_tests() {
    # API keys tests don't need external services - just run them
    ensure_results_dir
    run_pytest "tests/unit/api_keys/"
}

# Run integration tests
run_integration_tests() {
    echo -e "${YELLOW}Starting full service stack for integration tests...${NC}"
    docker compose -f docker-compose.test.yml up -d
    
    echo -e "${YELLOW}Waiting for all services to be healthy...${NC}"
    local retries=30
    while [ $retries -gt 0 ]; do
        if docker compose -f docker-compose.test.yml exec -T oid4vc-api curl -sf http://localhost:8000/health > /dev/null 2>&1; then
            break
        fi
        retries=$((retries - 1))
        echo "  Waiting for API... ($retries attempts left)"
        sleep 2
    done
    
    if [ $retries -eq 0 ]; then
        echo -e "${RED}✗ API failed to become healthy${NC}"
        exit 1
    fi
    
    echo -e "${GREEN}✓ All services ready${NC}"
    run_pytest "tests/integration/"
}

# Run all tests
run_all_tests() {
    start_services
    run_pytest "tests/"
}

# Open shell in pytest container
open_shell() {
    echo -e "${YELLOW}Opening shell in pytest container...${NC}"
    docker compose -f docker-compose.test.yml --profile pytest run --rm pytest /bin/bash
}

# Clean up
clean() {
    echo -e "${YELLOW}Cleaning up test containers and results...${NC}"
    docker compose -f docker-compose.test.yml --profile pytest down -v 2>/dev/null || true
    rm -rf pytest-results/*
    echo -e "${GREEN}✓ Cleanup complete${NC}"
}

# Main command handler
COMMAND="${1:-help}"
shift 2>/dev/null || true
parse_options "$@"

case "$COMMAND" in
    unit)
        run_unit_tests
        ;;
    api-keys)
        run_api_keys_tests
        ;;
    integration)
        run_integration_tests
        ;;
    all)
        run_all_tests
        ;;
    build)
        build_pytest
        ;;
    shell)
        open_shell
        ;;
    clean)
        clean
        ;;
    -h|--help|help)
        usage
        ;;
    *)
        echo -e "${RED}Unknown command: $COMMAND${NC}"
        usage
        exit 1
        ;;
esac

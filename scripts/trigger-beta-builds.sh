#!/bin/bash
# Trigger beta builds for all Marty dependencies
# This script helps you quickly build and publish beta versions

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

echo "🚀 Marty Beta Release Trigger"
echo "=============================="
echo ""

# Function to trigger workflow
trigger_workflow() {
    local repo_path=$1
    local workflow_file=$2
    local repo_name=$(basename "$repo_path")
    
    if [ ! -d "$repo_path" ]; then
        echo "⚠️  Skipping $repo_name - directory not found: $repo_path"
        return
    fi
    
    echo "📦 $repo_name"
    echo "   Workflow: $workflow_file"
    
    cd "$repo_path"
    
    # Check if workflow exists
    if [ ! -f ".github/workflows/$workflow_file" ]; then
        echo "   ⚠️  Workflow file not found, skipping"
        return
    fi
    
    # Check if there are uncommitted changes
    if ! git diff --quiet; then
        echo "   ⚠️  Warning: Uncommitted changes detected"
        echo "   Commit changes before triggering workflow for accurate version"
    fi
    
    # Push to trigger automatic build
    echo "   ℹ️  Push to main/dev branch to trigger automatic build"
    echo "   Or manually trigger via:"
    echo "   gh workflow run $workflow_file"
    echo ""
}

echo "The following workflows have been configured:"
echo ""

# Trigger each beta workflow
trigger_workflow "$WORKSPACE_ROOT/marty-credentials" "release-beta.yml"
trigger_workflow "$WORKSPACE_ROOT/marty-microservices-framework" "release-beta.yml"
trigger_workflow "$WORKSPACE_ROOT/Marty" "publish-marty-common-beta.yml"

echo "=============================="
echo ""
echo "✅ Beta workflows are configured!"
echo ""
echo "To trigger beta builds:"
echo ""
echo "Option 1: Automatic (recommended)"
echo "  1. Commit your changes in each repository"
echo "  2. Push to 'main' or 'dev' branch"
echo "  3. Beta build triggers automatically"
echo ""
echo "Option 2: Manual trigger via GitHub CLI"
echo "  cd marty-credentials && gh workflow run release-beta.yml"
echo "  cd marty-microservices-framework && gh workflow run release-beta.yml"
echo "  cd Marty && gh workflow run publish-marty-common-beta.yml"
echo ""
echo "Option 3: Manual trigger via GitHub web UI"
echo "  1. Go to repository → Actions tab"
echo "  2. Select 'Release Beta' workflow"
echo "  3. Click 'Run workflow'"
echo ""
echo "📚 See docs/BETA_RELEASES.md for more information"
echo ""
echo "After builds complete (~5-10 minutes):"
echo "  cd marty-ui"
echo "  docker compose --profile dev build  # Rebuilds with beta packages"
echo "  docker compose --profile dev up -d  # Starts dev environment"
echo ""

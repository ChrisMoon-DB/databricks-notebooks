#!/bin/bash

# ============================================================================
# Databricks Notebook Testing Script
# ============================================================================
# This script helps you test the notebooks in your Databricks workspace
#
# Prerequisites:
# 1. Databricks CLI installed: pip install databricks-cli
# 2. Configured with your workspace:
#    databricks configure --token
#    (You'll need your workspace URL and personal access token)
# ============================================================================

set -e

echo "============================================================================"
echo "DATABRICKS NOTEBOOK TESTING"
echo "============================================================================"
echo ""

# Check if Databricks CLI is configured
if ! databricks workspace ls / &>/dev/null; then
    echo "❌ Databricks CLI not configured"
    echo ""
    echo "To configure, run:"
    echo "  databricks configure --token"
    echo ""
    echo "You'll need:"
    echo "  - Databricks workspace URL (e.g., https://your-workspace.cloud.databricks.com)"
    echo "  - Personal access token (generate from User Settings > Access Tokens)"
    echo ""
    exit 1
fi

echo "✓ Databricks CLI configured"
echo ""

# Set target path in workspace
WORKSPACE_PATH="/Users/$(databricks current-user me | grep -o '"userName":"[^"]*"' | cut -d'"' -f4)/data-privacy-demo"

echo "Target workspace path: $WORKSPACE_PATH"
echo ""

# Create workspace directory
echo "Creating workspace directory..."
databricks workspace mkdirs "$WORKSPACE_PATH"
echo "✓ Directory created"
echo ""

# Import notebooks
echo "Uploading notebooks..."

echo "  → setup_environment.py"
databricks workspace import \
    ./setup_environment.py \
    "$WORKSPACE_PATH/setup_environment" \
    --language PYTHON \
    --format SOURCE \
    --overwrite

echo "  → data_privacy.ipynb"
databricks workspace import \
    ./data_privacy.ipynb \
    "$WORKSPACE_PATH/data_privacy" \
    --format JUPYTER \
    --overwrite

echo "  → data_encryption.ipynb"
databricks workspace import \
    ./data_encryption.ipynb \
    "$WORKSPACE_PATH/data_encryption" \
    --format JUPYTER \
    --overwrite

echo ""
echo "✓ All notebooks uploaded"
echo ""

echo "============================================================================"
echo "✅ UPLOAD COMPLETE"
echo "============================================================================"
echo ""
echo "Next steps:"
echo "1. Open your Databricks workspace"
echo "2. Navigate to: $WORKSPACE_PATH"
echo "3. Open data_privacy notebook"
echo "4. Attach to a cluster (Serverless recommended)"
echo "5. Update configuration:"
echo "   - Set USE_TEMP_TABLES = True for demo"
echo "   - Update group names to match your environment"
echo "6. Run the notebook!"
echo ""
echo "The setup_environment script will be called automatically via %run"
echo ""


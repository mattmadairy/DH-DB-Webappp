#!/usr/bin/env bash
# Safe Dependency Installation Script
# This script installs/updates dependencies without affecting your data

set -e  # Exit on any error

echo "=== DH Webapp Dependency Installation ==="
echo "This will install/update Python dependencies safely"
echo ""

# Check if we're in the right directory
if [ ! -f "DH_DB_Webapp/requirements.txt" ]; then
    echo "Error: requirements.txt not found in DH_DB_Webapp/ directory"
    echo "Please run this script from the project root directory"
    exit 1
fi

cd DH_DB_Webapp

echo "📦 Updating pip..."
python -m pip install --upgrade pip

echo ""
echo "📦 Installing production dependencies..."
python -m pip install -r requirements.txt

echo ""
echo "✅ Dependencies installed successfully!"
echo ""
echo "To install development dependencies as well, run:"
echo "python -m pip install -r requirements-dev.txt"
echo ""
echo "To test the installation:"
echo "python -c \"import app; print('✅ App imports successfully')\""
echo ""
echo "To run the application:"
echo "python app.py"
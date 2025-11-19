#!/bin/bash
# Quick start script for DH Member Database Web Application (Linux/Mac)

echo "Starting DH Member Database Web Application..."
echo ""

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo "Virtual environment not found. Running installation..."
    ./install.sh
    if [ $? -ne 0 ]; then
        echo "Installation failed. Please check errors above."
        exit 1
    fi
fi

# Activate virtual environment
source venv/bin/activate

# Check if database exists
if [ ! -f "members.db" ]; then
    echo "Database not found. Initializing..."
    python init_db.py
fi

# Start the application
echo ""
echo "========================================"
echo "Application starting..."
echo "Open your browser to: http://127.0.0.1:5000"
echo "Press Ctrl+C to stop the server"
echo "========================================"
echo ""

python app.py

#!/bin/bash
# Production startup script for Linux/Mac

echo "========================================"
echo "DH Member Database - Production Mode"
echo "========================================"
echo ""

# Activate virtual environment if it exists
if [ -f "venv/bin/activate" ]; then
    source venv/bin/activate
fi

# Check if database exists
if [ ! -f "members.db" ]; then
    echo "Initializing database..."
    python init_db.py
    echo ""
fi

# Start with appropriate production server
echo "Starting production server..."
echo "Access the application at: http://localhost:8080"
echo "Press Ctrl+C to stop"
echo ""

# Use Gunicorn on Linux/Mac, Waitress as fallback
if command -v gunicorn &> /dev/null; then
    gunicorn -w 4 -b 0.0.0.0:8080 app:app
else
    python run_production.py
fi

#!/bin/bash
# Run the app in background (Linux/Mac)

echo "Starting DH Member Database in background..."

# Activate virtual environment if it exists
if [ -f "venv/bin/activate" ]; then
    source venv/bin/activate
fi

# Check if database exists
if [ ! -f "members.db" ]; then
    echo "Initializing database..."
    python init_db.py
fi

# Start in background
nohup python app.py > app.log 2>&1 &
PID=$!

echo "Application started in background (PID: $PID)"
echo "Access at: http://127.0.0.1:5000"
echo "Logs: app.log"
echo ""
echo "To stop the application, run: kill $PID"
echo "Or run: pkill -f 'python app.py'"

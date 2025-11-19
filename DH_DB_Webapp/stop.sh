#!/bin/bash
# Stop the background application

echo "Stopping DH Member Database..."

# Kill python processes running app.py
pkill -f "python.*app.py"

if [ $? -eq 0 ]; then
    echo "Application stopped successfully."
else
    echo "No running application found."
fi

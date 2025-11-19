#!/bin/bash
# Installation script for DH Member Database Web Application (Linux/Mac)

echo "========================================"
echo "DH Member Database - Installation"
echo "========================================"
echo ""

# Function to install Python on different systems
install_python() {
    echo "Python is not installed. Attempting to install..."
    echo ""
    
    # Detect OS and install Python
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        # Linux
        if command -v apt-get &> /dev/null; then
            # Debian/Ubuntu
            echo "Detected Debian/Ubuntu system"
            echo "Installing Python 3..."
            sudo apt-get update
            sudo apt-get install -y python3 python3-pip python3-venv
        elif command -v yum &> /dev/null; then
            # RHEL/CentOS/Fedora
            echo "Detected RHEL/CentOS/Fedora system"
            echo "Installing Python 3..."
            sudo yum install -y python3 python3-pip
        elif command -v dnf &> /dev/null; then
            # Fedora (newer)
            echo "Detected Fedora system"
            echo "Installing Python 3..."
            sudo dnf install -y python3 python3-pip
        elif command -v pacman &> /dev/null; then
            # Arch Linux
            echo "Detected Arch Linux system"
            echo "Installing Python 3..."
            sudo pacman -S --noconfirm python python-pip
        else
            echo "ERROR: Could not detect package manager"
            echo "Please install Python 3.8+ manually"
            exit 1
        fi
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        # macOS
        echo "Detected macOS system"
        if command -v brew &> /dev/null; then
            echo "Installing Python 3 using Homebrew..."
            brew install python3
        else
            echo "ERROR: Homebrew not found"
            echo "Please install Homebrew first: https://brew.sh"
            echo "Or install Python manually from: https://www.python.org/downloads/"
            exit 1
        fi
    else
        echo "ERROR: Unsupported operating system"
        echo "Please install Python 3.8+ manually"
        exit 1
    fi
    
    # Verify installation
    if ! command -v python3 &> /dev/null; then
        echo "ERROR: Python installation failed"
        echo "Please install Python 3.8+ manually"
        exit 1
    fi
    
    echo "Python installed successfully!"
    python3 --version
    echo ""
}

# Check if Python is installed
if ! command -v python3 &> /dev/null; then
    install_python
fi

echo "Step 1/5: Python found"
python3 --version
echo ""

# Create virtual environment
echo "Step 2/5: Creating virtual environment..."
if [ -d "venv" ]; then
    echo "Virtual environment already exists, skipping..."
else
    python3 -m venv venv
    if [ $? -ne 0 ]; then
        echo "ERROR: Failed to create virtual environment"
        exit 1
    fi
    echo "Virtual environment created successfully"
fi
echo ""

# Activate virtual environment and install dependencies
echo "Step 3/5: Installing dependencies..."
source venv/bin/activate
pip install -r requirements.txt
if [ $? -ne 0 ]; then
    echo "ERROR: Failed to install dependencies"
    exit 1
fi
echo "Dependencies installed successfully"
echo ""

# Check dependencies
echo "Step 4/5: Verifying dependencies..."
python check_dependencies.py
if [ $? -ne 0 ]; then
    echo "WARNING: Some dependencies may be missing"
    echo "Continuing with installation..."
fi
echo ""

# Initialize database
echo "Step 5/5: Initializing database..."
python init_db.py
if [ $? -ne 0 ]; then
    echo "ERROR: Failed to initialize database"
    exit 1
fi
echo "Database initialized successfully"
echo ""

echo "========================================"
echo "Installation Complete!"
echo "========================================"
echo ""
echo "To run the application:"
echo "  1. Activate virtual environment: source venv/bin/activate"
echo "  2. Run the app: python app.py"
echo "  3. Open browser: http://127.0.0.1:5000"
echo ""
echo "Or simply run: ./start.sh"
echo ""

"""
Dependency checker script
Verifies all required dependencies are installed and working
"""
import sys
import subprocess

def check_python_version():
    """Check if Python version is compatible"""
    print("Checking Python version...")
    version = sys.version_info
    if version.major >= 3 and version.minor >= 8:
        print(f"✓ Python {version.major}.{version.minor}.{version.micro} (OK)")
        return True
    else:
        print(f"✗ Python {version.major}.{version.minor}.{version.micro} (Need 3.8+)")
        return False

def check_dependency(package_name, import_name=None):
    """Check if a dependency is installed and can be imported"""
    if import_name is None:
        import_name = package_name
    
    try:
        __import__(import_name)
        print(f"✓ {package_name}")
        return True
    except ImportError:
        print(f"✗ {package_name} (Missing)")
        return False

def check_all_dependencies():
    """Check all required dependencies"""
    print("\n" + "="*50)
    print("Checking Dependencies")
    print("="*50 + "\n")
    
    all_ok = True
    
    # Check Python version first
    if not check_python_version():
        all_ok = False
    
    print("\nChecking required packages...")
    
    # Core dependencies
    dependencies = [
        ("Flask", "flask"),
        ("Werkzeug", "werkzeug"),
        ("Jinja2", "jinja2"),
        ("MarkupSafe", "markupafe"),
        ("itsdangerous", "itsdangerous"),
        ("click", "click"),
        ("blinker", "blinker"),
        ("Waitress", "waitress"),
    ]
    
    # Optional but recommended
    optional_deps = [
        ("python-dateutil", "dateutil"),
    ]
    
    for package_name, import_name in dependencies:
        if not check_dependency(package_name, import_name):
            all_ok = False
    
    print("\nChecking optional packages...")
    for package_name, import_name in optional_deps:
        check_dependency(package_name, import_name)
    
    # Check for gunicorn on non-Windows systems
    if sys.platform != 'win32':
        print("\nChecking Linux/Mac specific packages...")
        check_dependency("Gunicorn", "gunicorn")
    
    print("\n" + "="*50)
    if all_ok:
        print("✓ All required dependencies are installed!")
        print("="*50)
        return 0
    else:
        print("✗ Some dependencies are missing!")
        print("\nTo install missing dependencies, run:")
        print("  pip install -r requirements.txt")
        print("="*50)
        return 1

if __name__ == "__main__":
    sys.exit(check_all_dependencies())

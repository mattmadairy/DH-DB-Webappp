"""
Production startup script using Waitress WSGI server
Safe for production deployment on Windows and Linux
"""
from waitress import serve
from app import app
import os

def main():
    """Run the application with Waitress production server"""
    host = os.environ.get('HOST', '0.0.0.0')
    port = int(os.environ.get('PORT', 8080))
    
    print("=" * 50)
    print(f"Starting DH Member Database (Production Mode)")
    print(f"Server: http://{host}:{port}")
    print("Press Ctrl+C to stop")
    print("=" * 50)
    
    serve(app, host=host, port=port, threads=4)

if __name__ == '__main__':
    main()

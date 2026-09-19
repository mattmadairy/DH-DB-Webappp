"""
Configuration file for DH Member Database Web Application
"""
import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

class Config:
    """Base configuration"""
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key-change-in-production'
    DATABASE_NAME = os.environ.get('DATABASE_NAME') or 'members.db'
    
    # Session configuration
    SESSION_COOKIE_SECURE = os.environ.get('SESSION_COOKIE_SECURE', 'False').lower() == 'true'
    SESSION_COOKIE_HTTPONLY = os.environ.get('SESSION_COOKIE_HTTPONLY', 'True').lower() == 'true'
    SESSION_COOKIE_SAMESITE = os.environ.get('SESSION_COOKIE_SAMESITE', 'Lax')
    PERMANENT_SESSION_LIFETIME = int(os.environ.get('PERMANENT_SESSION_LIFETIME', '3600'))
    
    # WTF CSRF Configuration
    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = None  # No time limit for CSRF tokens

    # Email / SMTP configuration for password reset emails
    MAIL_SERVER = os.environ.get('MAIL_SERVER')
    MAIL_PORT = int(os.environ.get('MAIL_PORT', '587'))
    MAIL_USE_TLS = os.environ.get('MAIL_USE_TLS', 'True').lower() == 'true'
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')
    MAIL_DEFAULT_SENDER = os.environ.get('MAIL_DEFAULT_SENDER') or os.environ.get('MAIL_USERNAME')
    APP_BASE_URL = os.environ.get('APP_BASE_URL')  # e.g. https://members.example.org, used to build reset links
    
class DevelopmentConfig(Config):
    """Development configuration"""
    DEBUG = True
    TESTING = False
    # SERVER_NAME = 'localhost:5000'  # Commented out to allow access from different IPs
    
class ProductionConfig(Config):
    """Production configuration"""
    DEBUG = False
    TESTING = False
    SECRET_KEY = os.environ.get('SECRET_KEY')  # Must be set in production
    SESSION_COOKIE_SECURE = True  # Require HTTPS in production
    
class TestingConfig(Config):
    """Testing configuration"""
    DEBUG = True
    TESTING = True
    DATABASE_NAME = 'test_members.db'
    WTF_CSRF_ENABLED = False  # Disable CSRF for testing

# Configuration dictionary
config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}

#!/usr/bin/env python3
"""
Production Deployment Script for DH Member Database Web Application

This script handles safe deployment of updates to production without affecting existing data.
It installs dependencies, runs database migrations, and provides production server options.

Usage:
    python deploy_production.py

Requirements:
    - Python 3.8+
    - Access to production environment
    - Backup of production database (recommended)
"""

import os
import sys
import subprocess
import shutil
from pathlib import Path
import argparse
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('deploy_production.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

class ProductionDeployer:
    def __init__(self, project_root=None):
        self.project_root = Path(project_root or Path(__file__).parent)
        self.app_dir = self.project_root / "DH_DB_Webapp"
        self.backup_dir = self.project_root / "backups"

        # Ensure we're in the right directory
        if not self.app_dir.exists():
            raise FileNotFoundError(f"Application directory not found: {self.app_dir}")

        os.chdir(self.app_dir)
        logger.info(f"Working directory: {self.app_dir}")

    def create_backup(self):
        """Create backup of database and critical files"""
        logger.info("Creating backup of current data...")

        self.backup_dir.mkdir(exist_ok=True)
        timestamp = subprocess.run(['date', '+%Y%m%d_%H%M%S'],
                                 capture_output=True, text=True).stdout.strip()

        backup_path = self.backup_dir / f"backup_{timestamp}"
        backup_path.mkdir()

        # Backup database files
        db_files = ['members.db', 'dh_database.db']
        for db_file in db_files:
            if (self.app_dir / db_file).exists():
                shutil.copy2(self.app_dir / db_file, backup_path / db_file)
                logger.info(f"Backed up {db_file}")

        # Backup configuration files
        config_files = ['.env', 'config.py']
        for config_file in config_files:
            if (self.app_dir / config_file).exists():
                shutil.copy2(self.app_dir / config_file, backup_path / config_file)
                logger.info(f"Backed up {config_file}")

        logger.info(f"Backup created at: {backup_path}")
        return backup_path

    def install_dependencies(self):
        """Install/update Python dependencies"""
        logger.info("Installing/updating dependencies...")

        # Upgrade pip first
        subprocess.run([sys.executable, '-m', 'pip', 'install', '--upgrade', 'pip'],
                      check=True)

        # Install production dependencies
        subprocess.run([sys.executable, '-m', 'pip', 'install', '-r', 'requirements.txt'],
                      check=True)

        logger.info("Dependencies installed successfully")

    def run_database_migrations(self):
        """Run database migrations safely"""
        logger.info("Checking for database migrations...")

        migrations_dir = self.app_dir / "migrations"
        if not migrations_dir.exists():
            logger.info("No migrations directory found, skipping migrations")
            return

        # Get list of migration files
        migration_files = sorted([f for f in migrations_dir.iterdir()
                                if f.suffix == '.sql'])

        if not migration_files:
            logger.info("No migration files found")
            return

        # Import database module to check migration status
        sys.path.insert(0, str(self.app_dir))
        try:
            import database

            for migration_file in migration_files:
                logger.info(f"Running migration: {migration_file.name}")

                with open(migration_file, 'r') as f:
                    sql = f.read()

                # Execute migration
                # Note: You'll need to implement migration tracking in your database.py
                # For now, this is a placeholder
                logger.warning(f"Migration execution not implemented for: {migration_file.name}")
                logger.warning("Please run migrations manually or implement migration tracking")

        except ImportError as e:
            logger.error(f"Could not import database module: {e}")
            logger.warning("Skipping database migrations - run manually if needed")

    def validate_installation(self):
        """Validate that the installation is working"""
        logger.info("Validating installation...")

        try:
            # Test import of main application
            sys.path.insert(0, str(self.app_dir))
            import app

            # Test database connection
            import database
            # Add any database validation checks here

            logger.info("Installation validation successful")
            return True

        except Exception as e:
            logger.error(f"Installation validation failed: {e}")
            return False

    def generate_production_config(self):
        """Generate production configuration recommendations"""
        logger.info("Generating production configuration recommendations...")

        config_recommendations = """
# Production Configuration Recommendations
# ======================================

# 1. Environment Variables (create .env file):
# SECRET_KEY=your-very-secure-random-key-here
# FLASK_ENV=production
# DATABASE_URL=sqlite:///members.db  # or your production DB URL

# 2. Gunicorn Configuration (gunicorn.conf.py):
bind = "0.0.0.0:8000"
workers = 3
worker_class = "sync"
worker_connections = 1000
timeout = 30
keepalive = 2
user = "www-data"  # or your web user
group = "www-data"  # or your web group
tmp_upload_dir = "/tmp"

# 3. Systemd Service (/etc/systemd/system/dh-webapp.service):
[Unit]
Description=DH Member Database Web App
After=network.target

[Service]
User=www-data
Group=www-data
WorkingDirectory=/path/to/your/app/DH_DB_Webapp
Environment="PATH=/path/to/your/venv/bin"
ExecStart=/path/to/your/venv/bin/gunicorn --config gunicorn.conf.py app:app
Restart=always

[Install]
WantedBy=multi-user.target

# 4. Nginx Configuration (/etc/nginx/sites-available/dh-webapp):
server {
    listen 80;
    server_name your-domain.com;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    location /static {
        alias /path/to/your/app/DH_DB_Webapp/static;
        expires 1y;
        add_header Cache-Control "public, immutable";
    }
}
"""

        with open(self.app_dir / "production_config_recommendations.txt", "w") as f:
            f.write(config_recommendations)

        logger.info("Production configuration recommendations saved to: production_config_recommendations.txt")

    def deploy(self, skip_backup=False, skip_validation=False):
        """Main deployment process"""
        logger.info("Starting production deployment...")

        try:
            # Create backup (unless skipped)
            if not skip_backup:
                backup_path = self.create_backup()
                logger.info(f"Backup created at: {backup_path}")
            else:
                logger.warning("Skipping backup creation!")

            # Install dependencies
            self.install_dependencies()

            # Run database migrations
            self.run_database_migrations()

            # Validate installation
            if not skip_validation:
                if not self.validate_installation():
                    raise Exception("Installation validation failed")

            # Generate production config
            self.generate_production_config()

            logger.info("✅ Production deployment completed successfully!")
            logger.info("\nNext steps:")
            logger.info("1. Review production_config_recommendations.txt")
            logger.info("2. Configure environment variables (.env file)")
            logger.info("3. Test the application: python app.py")
            logger.info("4. Set up production server (Gunicorn/Waitress)")
            logger.info("5. Configure reverse proxy (Nginx/Apache) if needed")

        except Exception as e:
            logger.error(f"❌ Deployment failed: {e}")
            logger.info("Check the backup and logs for recovery information")
            sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description="Deploy DH Webapp to production")
    parser.add_argument("--skip-backup", action="store_true",
                       help="Skip database backup (not recommended)")
    parser.add_argument("--skip-validation", action="store_true",
                       help="Skip installation validation")
    parser.add_argument("--project-root", help="Path to project root directory")

    args = parser.parse_args()

    try:
        deployer = ProductionDeployer(args.project_root)
        deployer.deploy(skip_backup=args.skip_backup,
                       skip_validation=args.skip_validation)
    except Exception as e:
        logger.error(f"Deployment script failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
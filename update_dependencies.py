#!/usr/bin/env python3
"""
Safe Dependency Update Script for DH Member Database Web Application

This script updates Python dependencies without affecting your existing data.
It creates backups and validates the installation before and after updates.

Usage:
    python update_dependencies.py

This script will:
1. Create backup of current environment
2. Update pip and all dependencies
3. Validate that the application still works
4. Provide rollback instructions if needed
"""

import os
import sys
import subprocess
import shutil
from pathlib import Path
import logging
from datetime import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('dependency_update.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

class DependencyUpdater:
    def __init__(self, project_root=None):
        self.project_root = Path(project_root or Path(__file__).parent)
        self.app_dir = self.project_root / "DH_DB_Webapp"
        self.backup_dir = self.project_root / "dependency_backups"

        if not self.app_dir.exists():
            raise FileNotFoundError(f"Application directory not found: {self.app_dir}")

        os.chdir(self.app_dir)
        logger.info(f"Working directory: {self.app_dir}")

    def create_backup(self):
        """Create backup of current installation state"""
        logger.info("Creating backup of current installation...")

        self.backup_dir.mkdir(exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        backup_path = self.backup_dir / f"deps_backup_{timestamp}"
        backup_path.mkdir()

        # Backup requirements files
        req_files = ['requirements.txt', 'requirements-dev.txt']
        for req_file in req_files:
            if (self.app_dir / req_file).exists():
                shutil.copy2(self.app_dir / req_file, backup_path / req_file)

        # Get current pip freeze
        try:
            result = subprocess.run([sys.executable, '-m', 'pip', 'freeze'],
                                  capture_output=True, text=True, check=True)
            with open(backup_path / "installed_packages.txt", "w") as f:
                f.write(result.stdout)
        except subprocess.CalledProcessError as e:
            logger.warning(f"Could not create pip freeze backup: {e}")

        logger.info(f"Backup created at: {backup_path}")
        return backup_path

    def update_pip(self):
        """Update pip to latest version"""
        logger.info("Updating pip...")
        subprocess.run([sys.executable, '-m', 'pip', 'install', '--upgrade', 'pip'],
                      check=True)
        logger.info("Pip updated successfully")

    def update_dependencies(self):
        """Update all dependencies from requirements.txt"""
        logger.info("Updating dependencies from requirements.txt...")

        # First, check if requirements.txt exists
        req_file = self.app_dir / "requirements.txt"
        if not req_file.exists():
            raise FileNotFoundError("requirements.txt not found")

        # Update dependencies
        subprocess.run([sys.executable, '-m', 'pip', 'install', '--upgrade', '-r', 'requirements.txt'],
                      check=True)

        logger.info("Dependencies updated successfully")

    def validate_application(self):
        """Validate that the application still works after updates"""
        logger.info("Validating application functionality...")

        try:
            # Test imports
            sys.path.insert(0, str(self.app_dir))

            # Test main app import
            import app
            logger.info("✓ Main application imports successfully")

            # Test database module
            import database
            logger.info("✓ Database module imports successfully")

            # Test other critical imports
            import flask
            import flask_login
            logger.info("✓ Flask components import successfully")

            # Try to create app instance (without running it)
            test_app = app.create_app() if hasattr(app, 'create_app') else None
            if test_app:
                logger.info("✓ Flask app instance created successfully")

            logger.info("✓ Application validation successful")
            return True

        except Exception as e:
            logger.error(f"❌ Application validation failed: {e}")
            return False

    def show_current_versions(self):
        """Show current versions of key packages"""
        logger.info("Current package versions:")

        key_packages = [
            'Flask',
            'Werkzeug',
            'Flask-Login',
            'Flask-Limiter',
            'requests',
            'icalendar',
            'google-api-python-client'
        ]

        for package in key_packages:
            try:
                result = subprocess.run([sys.executable, '-c', f'import {package}; print({package}.__version__)'],
                                      capture_output=True, text=True, check=True)
                version = result.stdout.strip()
                logger.info(f"  {package}: {version}")
            except (subprocess.CalledProcessError, ImportError):
                logger.info(f"  {package}: Not installed or version unavailable")

    def update(self):
        """Main update process"""
        logger.info("Starting dependency update process...")
        logger.info("=" * 50)

        try:
            # Show current state
            logger.info("Current installation state:")
            self.show_current_versions()

            # Create backup
            backup_path = self.create_backup()
            logger.info(f"✅ Backup created at: {backup_path}")

            # Update pip
            self.update_pip()

            # Update dependencies
            self.update_dependencies()

            # Validate application
            if not self.validate_application():
                raise Exception("Application validation failed after update")

            # Show updated versions
            logger.info("\nUpdated package versions:")
            self.show_current_versions()

            logger.info("\n" + "=" * 50)
            logger.info("✅ Dependency update completed successfully!")
            logger.info("\nIf you encounter any issues:")
            logger.info(f"1. Check the backup at: {backup_path}")
            logger.info("2. Review the log file: dependency_update.log")
            logger.info("3. To rollback: pip install -r backup_path/requirements.txt")

        except Exception as e:
            logger.error(f"❌ Dependency update failed: {e}")
            logger.info("\nTo rollback:")
            logger.info("1. Check the most recent backup in the dependency_backups/ folder")
            logger.info("2. Run: pip install -r path/to/backup/requirements.txt")
            logger.info("3. Restore database files if needed")
            sys.exit(1)

def main():
    try:
        updater = DependencyUpdater()
        updater.update()
    except Exception as e:
        logger.error(f"Update script failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
"""
Migration script to add security columns and tables to existing database
Run this once to update your database schema with security features
"""
import sqlite3
from datetime import datetime

DB_NAME = 'members.db'

def migrate_database():
    """Add security columns and tables to existing database"""
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    
    print("Starting database migration for security features...")
    
    # Check if columns already exist
    c.execute("PRAGMA table_info(users)")
    columns = [column[1] for column in c.fetchall()]
    
    # Add security columns to users table if they don't exist
    if 'failed_login_attempts' not in columns:
        print("Adding failed_login_attempts column...")
        c.execute("ALTER TABLE users ADD COLUMN failed_login_attempts INTEGER DEFAULT 0")
    
    if 'locked_until' not in columns:
        print("Adding locked_until column...")
        c.execute("ALTER TABLE users ADD COLUMN locked_until TEXT")
    
    if 'last_login' not in columns:
        print("Adding last_login column...")
        c.execute("ALTER TABLE users ADD COLUMN last_login TEXT")
    
    if 'last_password_change' not in columns:
        print("Adding last_password_change column...")
        c.execute("ALTER TABLE users ADD COLUMN last_password_change TEXT")
    
    # Create audit_log table if it doesn't exist
    c.execute("""
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            username TEXT,
            action TEXT NOT NULL,
            target_user TEXT,
            ip_address TEXT,
            user_agent TEXT,
            timestamp TEXT NOT NULL,
            success INTEGER DEFAULT 1,
            details TEXT
        )
    """)
    print("Audit log table created/verified...")
    
    # Create password_history table if it doesn't exist
    c.execute("""
        CREATE TABLE IF NOT EXISTS password_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            password_hash TEXT NOT NULL,
            changed_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    """)
    print("Password history table created/verified...")
    
    # Update existing users to have initial last_password_change timestamp
    c.execute("UPDATE users SET last_password_change = ? WHERE last_password_change IS NULL", 
              (datetime.now().isoformat(),))
    
    conn.commit()
    conn.close()
    
    print("\n✅ Database migration completed successfully!")
    print("All security features are now available.")

if __name__ == '__main__':
    try:
        migrate_database()
    except Exception as e:
        print(f"\n❌ Migration failed: {e}")
        print("Please check the error and try again.")

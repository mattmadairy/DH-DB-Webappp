"""
Migration script to add applications table and required columns to existing database
Run this once to add the new table for membership applications
"""

import sqlite3
import os

# Database file path
DB_NAME = 'members.db'

def migrate():
    """Add applications table to database and ensure all columns exist"""
    
    if not os.path.exists(DB_NAME):
        print(f"Error: Database file '{DB_NAME}' not found!")
        return False
    
    print(f"Connecting to {DB_NAME}...")
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    
    # Check if table already exists
    c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='applications'")
    table_exists = c.fetchone() is not None
    
    if not table_exists:
        print("Creating applications table...")
        
        # Create applications table with all columns including payment_confirmed and waiver_agreed
        c.execute("""
            CREATE TABLE IF NOT EXISTS applications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                first_name TEXT NOT NULL,
                middle_name TEXT,
                last_name TEXT NOT NULL,
                suffix TEXT,
                nickname TEXT,
                sex TEXT,
                dob TEXT,
                email TEXT,
                email2 TEXT,
                phone TEXT,
                phone2 TEXT,
                address TEXT,
                city TEXT,
                state TEXT,
                zip TEXT,
                sponsor TEXT,
                hql TEXT,
                carry_permit TEXT,
                hunters_education TEXT,
                felony_conviction TEXT,
                felony_details TEXT,
                inactive_docket TEXT,
                inactive_docket_details TEXT,
                restraining_order TEXT,
                restraining_order_details TEXT,
                firearm_legal TEXT,
                firearm_legal_details TEXT,
                payment_confirmed TEXT,
                waiver_agreed TEXT,
                status TEXT DEFAULT 'pending',
                submitted_at TEXT NOT NULL,
                reviewed_at TEXT,
                reviewed_by INTEGER,
                notes TEXT,
                FOREIGN KEY (reviewed_by) REFERENCES users(id)
            )
        """)
        
        conn.commit()
        
        # Verify table was created
        c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='applications'")
        if c.fetchone():
            print("✓ Applications table created successfully!")
            
            # Show table structure
            c.execute("PRAGMA table_info(applications)")
            columns = c.fetchall()
            print(f"\nTable structure ({len(columns)} columns):")
            for col in columns[:5]:  # Show first 5 columns
                print(f"  - {col[1]} ({col[2]})")
            print(f"  ... and {len(columns) - 5} more columns")
        else:
            print("✗ Failed to create applications table")
            conn.close()
            return False
    else:
        print("✓ Applications table already exists")
        
        # Check if we need to add missing columns
        c.execute("PRAGMA table_info(applications)")
        columns = [col[1] for col in c.fetchall()]
        
        columns_added = False
        
        if 'sex' not in columns:
            print("Adding sex column...")
            c.execute("ALTER TABLE applications ADD COLUMN sex TEXT")
            print("✓ sex column added")
            columns_added = True
        else:
            print("✓ sex column already exists")
        
        if 'payment_confirmed' not in columns:
            print("Adding payment_confirmed column...")
            c.execute("ALTER TABLE applications ADD COLUMN payment_confirmed TEXT")
            print("✓ payment_confirmed column added")
            columns_added = True
        else:
            print("✓ payment_confirmed column already exists")
        
        if 'waiver_agreed' not in columns:
            print("Adding waiver_agreed column...")
            c.execute("ALTER TABLE applications ADD COLUMN waiver_agreed TEXT")
            print("✓ waiver_agreed column added")
            columns_added = True
        else:
            print("✓ waiver_agreed column already exists")
        
        if columns_added:
            conn.commit()
    
    conn.close()
    return True

if __name__ == "__main__":
    print("="*60)
    print("Database Migration: Applications Table")
    print("="*60)
    
    success = migrate()
    
    print("="*60)
    if success:
        print("Migration completed successfully!")
    else:
        print("Migration failed!")
    print("="*60)

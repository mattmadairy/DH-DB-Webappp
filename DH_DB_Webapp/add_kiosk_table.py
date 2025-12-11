"""
Migration script to add check_ins table to existing database
Run this script to add kiosk functionality to an existing production database
"""

import sqlite3
import os

DB_NAME = "members.db"

def add_kiosk_table():
    """Add check_ins table to the database"""
    
    # Check if database exists
    if not os.path.exists(DB_NAME):
        print(f"Error: Database '{DB_NAME}' not found!")
        print("Please run this script from the directory containing members.db")
        return False
    
    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        
        # Check if table already exists
        cursor.execute("""
            SELECT name FROM sqlite_master 
            WHERE type='table' AND name='check_ins'
        """)
        
        if cursor.fetchone():
            print("✓ check_ins table already exists")
            conn.close()
            return True
        
        # Create check_ins table
        print("Creating check_ins table...")
        cursor.execute("""
            CREATE TABLE check_ins (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                member_number TEXT NOT NULL,
                check_in_time TEXT NOT NULL,
                activities TEXT,
                guest1_name TEXT,
                guest2_name TEXT,
                other_activity TEXT,
                sign_out_time TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        conn.commit()
        print("✓ check_ins table created successfully!")
        
        # Verify table was created
        cursor.execute("""
            SELECT name FROM sqlite_master 
            WHERE type='table' AND name='check_ins'
        """)
        
        if cursor.fetchone():
            print("✓ Table verified in database")
            
            # Show table structure
            cursor.execute("PRAGMA table_info(check_ins)")
            columns = cursor.fetchall()
            print("\nTable structure:")
            for col in columns:
                print(f"  - {col[1]} ({col[2]})")
            
            conn.close()
            return True
        else:
            print("✗ Table creation failed")
            conn.close()
            return False
            
    except sqlite3.Error as e:
        print(f"✗ Database error: {e}")
        return False
    except Exception as e:
        print(f"✗ Unexpected error: {e}")
        return False

if __name__ == "__main__":
    print("="*60)
    print("Kiosk Table Migration Script")
    print("="*60)
    print(f"Target database: {DB_NAME}\n")
    
    success = add_kiosk_table()
    
    print("\n" + "="*60)
    if success:
        print("Migration completed successfully!")
        print("The kiosk functionality is now ready to use.")
    else:
        print("Migration failed!")
        print("Please check the error messages above.")
    print("="*60)

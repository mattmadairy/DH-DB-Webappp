"""
Migration script to add tos_accepted and guest TOS columns to check_ins table
"""
import sqlite3

def migrate():
    conn = sqlite3.connect('members.db')
    c = conn.cursor()
    
    try:
        # Check if columns already exist
        c.execute("PRAGMA table_info(check_ins)")
        columns = [row[1] for row in c.fetchall()]
        
        if 'tos_accepted' not in columns:
            print("Adding tos_accepted column to check_ins table...")
            c.execute('ALTER TABLE check_ins ADD COLUMN tos_accepted INTEGER DEFAULT 0')
            conn.commit()
            print("✓ tos_accepted column added successfully!")
        else:
            print("✓ tos_accepted column already exists")
            
        if 'guest1_tos_accepted' not in columns:
            print("Adding guest1_tos_accepted column to check_ins table...")
            c.execute('ALTER TABLE check_ins ADD COLUMN guest1_tos_accepted INTEGER DEFAULT 0')
            conn.commit()
            print("✓ guest1_tos_accepted column added successfully!")
        else:
            print("✓ guest1_tos_accepted column already exists")
            
        if 'guest2_tos_accepted' not in columns:
            print("Adding guest2_tos_accepted column to check_ins table...")
            c.execute('ALTER TABLE check_ins ADD COLUMN guest2_tos_accepted INTEGER DEFAULT 0')
            conn.commit()
            print("✓ guest2_tos_accepted column added successfully!")
        else:
            print("✓ guest2_tos_accepted column already exists")
            
    except Exception as e:
        print(f"✗ Error during migration: {e}")
        conn.rollback()
    finally:
        conn.close()

if __name__ == '__main__':
    migrate()

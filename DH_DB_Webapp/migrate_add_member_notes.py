"""
Migration script to add member_notes column to members table
"""
import sqlite3

def migrate():
    conn = sqlite3.connect('members.db')
    c = conn.cursor()
    
    try:
        # Check if column already exists
        c.execute("PRAGMA table_info(members)")
        columns = [row[1] for row in c.fetchall()]
        
        if 'member_notes' not in columns:
            print("Adding member_notes column to members table...")
            c.execute('ALTER TABLE members ADD COLUMN member_notes TEXT')
            conn.commit()
            print("✓ member_notes column added successfully!")
        else:
            print("✓ member_notes column already exists")
            
    except Exception as e:
        print(f"✗ Error during migration: {e}")
        conn.rollback()
    finally:
        conn.close()

if __name__ == '__main__':
    migrate()

"""
Script to rebuild the committees table with proper columns.
This will drop the existing committees table and recreate it with all the proper columns.
All existing committee memberships will be lost - make sure to backup if needed!
"""

import sqlite3

DB_NAME = "members.db"

def rebuild_committees_table():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    
    print("Starting committees table rebuild...")
    
    # Drop the existing committees table
    print("Dropping existing committees table...")
    c.execute("DROP TABLE IF EXISTS committees")
    
    # Recreate the committees table with proper structure
    print("Creating new committees table with proper columns...")
    c.execute("""
        CREATE TABLE committees (
            committee_id INTEGER PRIMARY KEY AUTOINCREMENT,
            member_id INTEGER NOT NULL,
            executive_committee INTEGER DEFAULT 0,
            membership INTEGER DEFAULT 0,
            trap INTEGER DEFAULT 0,
            still_target INTEGER DEFAULT 0,
            gun_bingo_social_events INTEGER DEFAULT 0,
            rifle INTEGER DEFAULT 0,
            pistol INTEGER DEFAULT 0,
            archery INTEGER DEFAULT 0,
            building_and_grounds INTEGER DEFAULT 0,
            hunting INTEGER DEFAULT 0,
            notes TEXT,
            FOREIGN KEY (member_id) REFERENCES members(id)
        )
    """)
    
    conn.commit()
    
    # Verify the table structure
    print("\nVerifying new table structure...")
    c.execute("PRAGMA table_info(committees)")
    columns = c.fetchall()
    
    print("\nColumns in committees table:")
    for col in columns:
        print(f"  - {col[1]} ({col[2]})")
    
    conn.close()
    print("\n✓ Committees table successfully rebuilt!")
    print("\nNote: All previous committee memberships have been cleared.")
    print("You will need to reassign committee memberships through the web interface.")

if __name__ == "__main__":
    import os
    
    # Check if database exists
    if not os.path.exists(DB_NAME):
        print(f"ERROR: Database file '{DB_NAME}' not found!")
        print("Please make sure you're running this script from the correct directory.")
        exit(1)
    
    # Confirm action
    print("="*60)
    print("COMMITTEES TABLE REBUILD SCRIPT")
    print("="*60)
    print(f"\nDatabase: {DB_NAME}")
    print("\nWARNING: This will DELETE all existing committee memberships!")
    print("Make sure you have a backup if needed.")
    
    response = input("\nDo you want to continue? (yes/no): ")
    
    if response.lower() in ['yes', 'y']:
        rebuild_committees_table()
    else:
        print("\nOperation cancelled.")

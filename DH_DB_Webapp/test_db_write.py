"""
Diagnostic script to check database permissions and write capabilities
"""
import sqlite3
import os

DB_NAME = "members.db"

print("="*60)
print("DATABASE DIAGNOSTICS")
print("="*60)

# Check if database exists
if not os.path.exists(DB_NAME):
    print(f"\n❌ ERROR: Database file '{DB_NAME}' not found!")
    exit(1)

print(f"\n✓ Database file exists: {DB_NAME}")

# Check file permissions
try:
    stat_info = os.stat(DB_NAME)
    print(f"\n✓ Database file size: {stat_info.st_size} bytes")
    print(f"✓ Can read file: {os.access(DB_NAME, os.R_OK)}")
    print(f"✓ Can write file: {os.access(DB_NAME, os.W_OK)}")
except Exception as e:
    print(f"\n❌ Error checking file permissions: {e}")

# Try to connect and read
print("\n" + "="*60)
print("TESTING DATABASE CONNECTION")
print("="*60)

try:
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    
    print("\n✓ Successfully connected to database")
    
    # Check if committees table exists
    c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='committees'")
    if c.fetchone():
        print("✓ Committees table exists")
        
        # Get table structure
        c.execute("PRAGMA table_info(committees)")
        columns = c.fetchall()
        print(f"✓ Committees table has {len(columns)} columns:")
        for col in columns:
            print(f"    - {col[1]} ({col[2]})")
        
        # Try to count rows
        c.execute("SELECT COUNT(*) FROM committees")
        count = c.fetchone()[0]
        print(f"\n✓ Current rows in committees table: {count}")
        
    else:
        print("❌ Committees table does NOT exist")
    
    conn.close()
    
except Exception as e:
    print(f"\n❌ Error during read test: {e}")

# Try to write to the database
print("\n" + "="*60)
print("TESTING DATABASE WRITE")
print("="*60)

try:
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    
    # Try to insert a test row (member_id 99999 should not exist)
    print("\nAttempting to insert test row...")
    c.execute("""
        INSERT INTO committees (member_id, executive_committee, membership, trap, 
                               still_target, gun_bingo_social_events, rifle, 
                               pistol, archery, building_and_grounds, hunting, notes)
        VALUES (99999, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 'TEST ROW - DELETE ME')
    """)
    
    conn.commit()
    print("✓ Successfully inserted test row")
    
    # Verify the insert
    c.execute("SELECT * FROM committees WHERE member_id=99999")
    row = c.fetchone()
    if row:
        print("✓ Test row verified in database")
        
        # Clean up - delete the test row
        c.execute("DELETE FROM committees WHERE member_id=99999")
        conn.commit()
        print("✓ Test row deleted successfully")
    
    conn.close()
    print("\n✓ DATABASE WRITE TEST PASSED!")
    
except sqlite3.OperationalError as e:
    print(f"\n❌ Operational Error: {e}")
    print("\nPossible causes:")
    print("  - Database file is locked by another process")
    print("  - Database file is read-only")
    print("  - Insufficient permissions")
    
except Exception as e:
    print(f"\n❌ Error during write test: {e}")
    import traceback
    traceback.print_exc()

print("\n" + "="*60)
print("END OF DIAGNOSTICS")
print("="*60)

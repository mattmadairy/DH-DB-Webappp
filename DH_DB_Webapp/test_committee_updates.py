"""
Test updating committees for multiple members to see where it fails
"""
import sqlite3

DB_NAME = "members.db"

def get_connection():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn

def update_member_committees(member_id, updates):
    print(f"\n{'='*60}")
    print(f"Updating committees for member_id={member_id}")
    print(f"Updates: {updates}")
    
    conn = get_connection()
    c = conn.cursor()
    
    # Check if row exists for member_id
    c.execute("SELECT 1 FROM committees WHERE member_id=?", (member_id,))
    exists = c.fetchone()
    
    if not exists:
        print(f"  → No existing row, will INSERT")
        # Insert a new row with all committee columns set to 0 except those in updates
        c.execute("PRAGMA table_info(committees)")
        columns = [row[1] for row in c.fetchall() if row[1] not in ('member_id', 'committee_id', 'notes')]
        print(f"  → Columns to insert: {columns}")
        col_names = ', '.join(['member_id'] + columns)
        col_placeholders = ', '.join(['?'] * (1 + len(columns)))
        values = [member_id] + [updates.get(col, 0) for col in columns]
        
        sql = f"INSERT INTO committees ({col_names}) VALUES ({col_placeholders})"
        print(f"  → SQL: {sql}")
        print(f"  → Values: {values}")
        
        try:
            c.execute(sql, values)
            conn.commit()
            print(f"  ✓ INSERT successful")
        except Exception as e:
            print(f"  ✗ INSERT failed: {e}")
            conn.rollback()
            conn.close()
            return False
    else:
        print(f"  → Row exists, will UPDATE")
        # Build SET clause dynamically
        set_clause = ', '.join([f'{k}=?' for k in updates.keys()])
        values = list(updates.values())
        values.append(member_id)
        
        sql = f"UPDATE committees SET {set_clause} WHERE member_id=?"
        print(f"  → SQL: {sql}")
        print(f"  → Values: {values}")
        
        try:
            c.execute(sql, values)
            conn.commit()
            print(f"  ✓ UPDATE successful")
        except Exception as e:
            print(f"  ✗ UPDATE failed: {e}")
            conn.rollback()
            conn.close()
            return False
    
    conn.close()
    return True

# Test with a few member IDs
print("TESTING COMMITTEE UPDATES")
print("="*60)

# Get some member IDs from the database
conn = get_connection()
c = conn.cursor()
c.execute("SELECT id, first_name, last_name FROM members WHERE deleted=0 LIMIT 5")
members = c.fetchall()
conn.close()

if not members:
    print("No members found in database!")
else:
    print(f"\nFound {len(members)} members to test with:")
    for m in members:
        print(f"  - ID {m['id']}: {m['first_name']} {m['last_name']}")
    
    print("\n" + "="*60)
    print("TESTING UPDATES")
    print("="*60)
    
    # Test updating each member
    for m in members:
        test_updates = {
            'executive_committee': 1,
            'membership': 0,
            'trap': 1
        }
        success = update_member_committees(m['id'], test_updates)
        if not success:
            print(f"\n✗ FAILED at member {m['id']}")
            break
    else:
        print("\n" + "="*60)
        print("✓ ALL UPDATES SUCCESSFUL")
        print("="*60)

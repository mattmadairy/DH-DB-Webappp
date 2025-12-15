"""
Migration script to move existing committee membership data from the old denormalized 'committees' table to the new normalized 'committee_memberships' and 'committee_names' tables.

Usage:
    python migrate_committees_to_normalized.py members.db
"""
import sqlite3
import sys

def migrate_committees(db_path):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()

    # 1. Ensure committee_names and committee_memberships tables exist
    c.execute("""
    CREATE TABLE IF NOT EXISTS committee_names (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT UNIQUE NOT NULL
    )
    """)
    c.execute("""
    CREATE TABLE IF NOT EXISTS committee_memberships (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        member_id INTEGER NOT NULL,
        committee_id INTEGER NOT NULL,
        role TEXT CHECK(role IN ('member','chair')),
        UNIQUE(member_id, committee_id),
        FOREIGN KEY (member_id) REFERENCES members(id),
        FOREIGN KEY (committee_id) REFERENCES committee_names(id)
    )
    """)
    conn.commit()

    # 2. Get all committee columns from the old 'committees' table
    c.execute("PRAGMA table_info(committees)")
    columns = [row['name'] for row in c.fetchall() if row['name'] not in ('member_id', 'committee_id', 'notes')]

    # 3. Insert committee names into committee_names
    for cname in columns:
        c.execute("INSERT OR IGNORE INTO committee_names (name) VALUES (?)", (cname,))
    conn.commit()

    # 4. Build a map of committee name to id
    c.execute("SELECT id, name FROM committee_names")
    committee_map = {row['name']: row['id'] for row in c.fetchall()}

    # 5. Migrate memberships and chair roles
    c.execute("SELECT * FROM committees")
    for row in c.fetchall():
        member_id = row['member_id']
        notes = row['notes'] or ''
        for cname in columns:
            if row[cname] == 1:
                role = 'chair' if (f"{cname} Chair" in notes or f"{cname.lower()} chair" in notes.lower()) else 'member'
                committee_id = committee_map[cname]
                c.execute(
                    "INSERT OR IGNORE INTO committee_memberships (member_id, committee_id, role) VALUES (?, ?, ?)",
                    (member_id, committee_id, role)
                )
    conn.commit()
    print("Migration complete. All committee memberships have been moved to the normalized schema.")
    conn.close()

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python migrate_committees_to_normalized.py <database_path>")
        sys.exit(1)
    migrate_committees(sys.argv[1])

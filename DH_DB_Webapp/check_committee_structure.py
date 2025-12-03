"""
Check committees table constraints and existing data
"""
import sqlite3

DB_NAME = "members.db"

conn = sqlite3.connect(DB_NAME)
c = conn.cursor()

print("Committees Table Schema:")
print("="*60)
c.execute("PRAGMA table_info(committees)")
for col in c.fetchall():
    print(f"  {col[1]} - {col[2]} - PK:{col[5]} - NotNull:{col[3]}")

print("\n\nTable Indexes and Constraints:")
print("="*60)
c.execute("SELECT sql FROM sqlite_master WHERE type='index' AND tbl_name='committees'")
indexes = c.fetchall()
if indexes:
    for idx in indexes:
        print(idx[0])
else:
    print("  No indexes found")

c.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='committees'")
table_sql = c.fetchone()
print("\n\nFull CREATE TABLE statement:")
print("="*60)
print(table_sql[0])

print("\n\nCurrent data in committees table:")
print("="*60)
c.execute("SELECT member_id, COUNT(*) as count FROM committees GROUP BY member_id")
rows = c.fetchall()
print(f"Total unique members with committee data: {len(rows)}")
if len(rows) > 0:
    print(f"First few entries:")
    for row in rows[:10]:
        print(f"  member_id: {row[0]}, entries: {row[1]}")
    if len(rows) > 10:
        print(f"  ... and {len(rows) - 10} more")

conn.close()

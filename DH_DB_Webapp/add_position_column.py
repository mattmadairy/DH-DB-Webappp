import sqlite3

conn = sqlite3.connect(r"c:\Users\Matt\VS CODE REPO'S\DH-DB-Webappp\members.db")
c = conn.cursor()
c.execute("ALTER TABLE roles ADD COLUMN position TEXT")
conn.commit()
conn.close()
print("Added 'position' column to roles table.")

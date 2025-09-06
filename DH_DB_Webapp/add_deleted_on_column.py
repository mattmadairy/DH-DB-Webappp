import sqlite3
conn = sqlite3.connect('members.db')
c = conn.cursor()
c.execute("ALTER TABLE members ADD COLUMN deleted_on TEXT;")
conn.commit()
conn.close()
print("Column 'deleted_on' added to members table.")

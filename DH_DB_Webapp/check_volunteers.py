import sqlite3

DB_NAME = 'members.db'
conn = sqlite3.connect(DB_NAME)
c = conn.cursor()

# Check recent volunteer sign-ins
c.execute("SELECT id, event_id, name, signed_in_at, signed_out_at FROM event_signins WHERE signin_type = 'volunteer' ORDER BY signed_in_at DESC LIMIT 10")
volunteers = c.fetchall()

print('Recent volunteer sign-ins:')
for volunteer in volunteers:
    print(f'ID: {volunteer[0]}, Event_ID: {volunteer[1]}, Name: {volunteer[2]}, Signed_In: {volunteer[3]}, Signed_Out: {volunteer[4]}')

# Check what unique event_ids exist for volunteers
c.execute("SELECT DISTINCT event_id FROM event_signins WHERE signin_type = 'volunteer'")
event_ids = c.fetchall()
print(f'\nUnique event_ids for volunteers: {[row[0] for row in event_ids]}')

# Check attendees too
c.execute("SELECT DISTINCT event_id FROM event_signins WHERE signin_type = 'attendee'")
attendee_event_ids = c.fetchall()
print(f'Unique event_ids for attendees: {[row[0] for row in attendee_event_ids]}')

conn.close()
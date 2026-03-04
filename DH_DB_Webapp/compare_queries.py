import sqlite3
import sys
sys.path.append('.')
import database

print('Direct SQLite query:')
conn = sqlite3.connect('members.db')
cursor = conn.cursor()
cursor.execute('SELECT event_id, signin_type, name FROM event_signins ORDER BY event_id, signin_type')
results = cursor.fetchall()
print('All sign-ins:')
for row in results:
    print(f'  {row[0]}: {row[1]} = {row[2]}')
conn.close()

print()
print('Database functions:')
volunteers_0 = database.get_event_volunteers('cal_0_1772496000')
attendees_0 = database.get_event_attendees('cal_0_1772496000')
volunteers_1 = database.get_event_volunteers('cal_1_1772496000')
attendees_1 = database.get_event_attendees('cal_1_1772496000')

print(f'cal_0_1772496000: {len(volunteers_0)} volunteers, {len(attendees_0)} attendees')
print(f'cal_1_1772496000: {len(volunteers_1)} volunteers, {len(attendees_1)} attendees')

if volunteers_0:
    print(f'Volunteers for cal_0: {[row["name"] for row in volunteers_0]}')
if attendees_0:
    print(f'Attendees for cal_0: {[row["name"] for row in attendees_0]}')
if volunteers_1:
    print(f'Volunteers for cal_1: {[row["name"] for row in volunteers_1]}')
if attendees_1:
    print(f'Attendees for cal_1: {[row["name"] for row in attendees_1]}')
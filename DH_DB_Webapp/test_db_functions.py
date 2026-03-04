import sys
sys.path.append('.')
import database

print('Testing database functions:')
volunteers_0 = database.get_event_volunteers('cal_0_1772496000')
attendees_0 = database.get_event_attendees('cal_0_1772496000')
volunteers_1 = database.get_event_volunteers('cal_1_1772496000')
attendees_1 = database.get_event_attendees('cal_1_1772496000')

print(f'cal_0_1772496000: {len(volunteers_0)} volunteers, {len(attendees_0)} attendees')
print(f'cal_1_1772496000: {len(volunteers_1)} volunteers, {len(attendees_1)} attendees')

if attendees_0:
    print(f'Attendees for cal_0: {[row["name"] for row in attendees_0]}')
if attendees_1:
    print(f'Attendees for cal_1: {[row["name"] for row in attendees_1]}')
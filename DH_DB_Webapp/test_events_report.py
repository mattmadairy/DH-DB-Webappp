import sys
sys.path.append('.')
from app import fetch_calendar_events
import database

# Get calendar events
calendar_events, error = fetch_calendar_events()
if error:
    print(f'Error fetching calendar events: {error}')
    sys.exit(1)

print('Calendar events:')
for i, event in enumerate(calendar_events):
    event_id = f'cal_{i}_{int(event["start"].timestamp())}'
    volunteers = database.get_event_volunteers(event_id)
    attendees = database.get_event_attendees(event_id)
    total_signins = len(volunteers) + len(attendees)

    print(f'  {i}: {event["summary"]} ({event["start"].strftime("%Y-%m-%d")}) - ID: {event_id}')
    print(f'      Volunteers: {len(volunteers)}, Attendees: {len(attendees)}, Total: {total_signins}')

    if total_signins > 0:
        print('      -> WOULD BE INCLUDED IN REPORT')
    else:
        print('      -> WOULD BE FILTERED OUT')
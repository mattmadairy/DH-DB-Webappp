import app
from app import fetch_calendar_events
import database
import datetime
import pytz

# Get today's events
calendar_events, error = fetch_calendar_events()
today = datetime.datetime.now(pytz.UTC).date()

today_events = []
for event in calendar_events:
    event_date = event['start'].date()
    if event_date == today:
        today_events.append(event)

print(f'Today\'s events: {len(today_events)}')

# Test volunteer queries for each event
for i, event in enumerate(today_events):
    event_id = f'cal_{i}_{int(event["start"].timestamp())}'
    volunteers = database.get_event_volunteers(event_id)
    attendees = database.get_event_attendees(event_id)

    print(f'Event: {event["summary"]}')
    print(f'  ID: {event_id}')
    print(f'  Volunteers: {len(volunteers)}')
    for v in volunteers:
        print(f'    - {v["name"]} (ID: {v["id"]}, Event: {v["event_id"]})')
    print(f'  Attendees: {len(attendees)}')
    print()

# Also test with the full calendar index (not just today's events)
print('Testing with full calendar index:')
for i, event in enumerate(calendar_events[:5]):  # First 5 events
    event_id = f'cal_{i}_{int(event["start"].timestamp())}'
    volunteers = database.get_event_volunteers(event_id)
    if volunteers:
        print(f'Event {i}: {event["summary"]} - ID: {event_id} - Volunteers: {len(volunteers)}')
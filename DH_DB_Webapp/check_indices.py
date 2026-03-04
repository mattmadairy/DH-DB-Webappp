import app
from app import fetch_calendar_events

# Get all calendar events
calendar_events, error = fetch_calendar_events()

# Find the index of 'test' event
for i, event in enumerate(calendar_events):
    if event['summary'] == 'test':
        print(f'"test" event is at index {i} in full calendar list')
        event_id = f'cal_{i}_{int(event["start"].timestamp())}'
        print(f'Its full calendar event ID would be: {event_id}')
        break

# Find the index of 'Test 2' event
for i, event in enumerate(calendar_events):
    if event['summary'] == 'Test 2':
        print(f'"Test 2" event is at index {i} in full calendar list')
        event_id = f'cal_{i}_{int(event["start"].timestamp())}'
        print(f'Its full calendar event ID would be: {event_id}')
        break

# Check what the sign-in page would generate for today's events
import datetime
import pytz
today = datetime.datetime.now(pytz.UTC).date()

today_events = []
for event in calendar_events:
    event_date = event['start'].date()
    if event_date == today:
        today_events.append(event)

print(f'\nSign-in page would generate IDs for today\'s {len(today_events)} events:')
for i, event in enumerate(today_events):
    event_id = f'cal_{i}_{int(event["start"].timestamp())}'
    print(f'  {event["summary"]}: {event_id}')
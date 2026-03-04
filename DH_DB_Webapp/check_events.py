import app
from app import fetch_calendar_events

# Get calendar events
calendar_events, error = fetch_calendar_events()
print(f'Found {len(calendar_events)} calendar events')

# Show the events and their generated IDs
for i, event in enumerate(calendar_events):
    event_id = f'cal_{i}_{int(event["start"].timestamp())}'
    print(f'Event {i}: {event["summary"]} - ID: {event_id} - Date: {event["start"].strftime("%Y-%m-%d")}')

# Check today's events specifically
import datetime
import pytz
today = datetime.datetime.now(pytz.UTC).date()
print(f'\nToday is: {today}')

today_events = []
for event in calendar_events:
    event_date = event['start'].date()
    if event_date == today:
        today_events.append(event)

print(f'Today\'s events: {len(today_events)}')
for i, event in enumerate(today_events):
    event_id = f'cal_{i}_{int(event["start"].timestamp())}'
    print(f'  Today Event {i}: {event["summary"]} - ID: {event_id}')
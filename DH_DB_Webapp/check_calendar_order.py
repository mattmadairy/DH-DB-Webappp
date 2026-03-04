import sys
sys.path.append('.')
from app import fetch_calendar_events

calendar_events, error = fetch_calendar_events()
if error:
    print(f'Error: {error}')
    sys.exit(1)

print('Calendar events in order:')
for i, event in enumerate(calendar_events):
    print(f'  {i}: {event["summary"]} - {event["start"].strftime("%Y-%m-%d %H:%M")}')
    event_id = f'cal_{i}_{int(event["start"].timestamp())}'
    print(f'      ID: {event_id}')
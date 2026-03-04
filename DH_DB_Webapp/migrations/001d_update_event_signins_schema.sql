-- Migration: Update event_signins table to use TEXT event_id for calendar integration
-- This removes the foreign key constraint and allows string event IDs from Google Calendar

-- First, create a new table with the updated schema
CREATE TABLE event_signins_new (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT NOT NULL,
    name TEXT NOT NULL,
    email TEXT NOT NULL,
    member_number TEXT,
    signin_type TEXT NOT NULL DEFAULT 'attendee',
    skills TEXT,
    waiver_agreed INTEGER DEFAULT 0,
    is_shooter INTEGER DEFAULT 0,
    is_guest INTEGER DEFAULT 0,
    signed_in_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    signed_out_at TIMESTAMP
);

-- Copy all data from the old table to the new table
INSERT INTO event_signins_new (id, event_id, name, email, member_number, signin_type, skills, waiver_agreed, is_shooter, is_guest, signed_in_at, signed_out_at)
SELECT id, CAST(event_id AS TEXT), name, email, member_number, signin_type, skills, waiver_agreed, is_shooter, is_guest, signed_in_at, signed_out_at
FROM event_signins;

-- Drop the old table
DROP TABLE event_signins;

-- Rename the new table to the original name
ALTER TABLE event_signins_new RENAME TO event_signins;
-- Add all committee names from the committees table schema
INSERT OR IGNORE INTO committee_names (name) VALUES ('trap');
INSERT OR IGNORE INTO committee_names (name) VALUES ('still_target');
INSERT OR IGNORE INTO committee_names (name) VALUES ('rifle');
INSERT OR IGNORE INTO committee_names (name) VALUES ('pistol');
INSERT OR IGNORE INTO committee_names (name) VALUES ('archery');
INSERT OR IGNORE INTO committee_names (name) VALUES ('hunting');
-- Create committee_names reference table
CREATE TABLE IF NOT EXISTS committee_names (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL
);

-- Populate committee_names with unique committee names
INSERT OR IGNORE INTO committee_names (name) VALUES ('executive_committee');
INSERT OR IGNORE INTO committee_names (name) VALUES ('gun_bingo_social_events');
INSERT OR IGNORE INTO committee_names (name) VALUES ('building_and_grounds');
INSERT OR IGNORE INTO committee_names (name) VALUES ('membership');

-- Migration script to add committee_memberships table
CREATE TABLE IF NOT EXISTS committee_memberships (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    member_id INTEGER NOT NULL,
    committee_id INTEGER NOT NULL,
    role TEXT,
    FOREIGN KEY(member_id) REFERENCES members(id),
    FOREIGN KEY(committee_id) REFERENCES committees(id)
);

-- Optionally, migrate existing data here if needed.

-- Migrate existing committee data from old committees table to committee_memberships
-- Migrate existing committee data from old committees table to committee_memberships using committee_names
INSERT INTO committee_memberships (member_id, committee_id, role)
SELECT c.member_id, cn.id,
    CASE 
        WHEN lower(c.notes) LIKE '%' || cn.name || ' chair%' THEN 'chair'
        ELSE 'member'
    END as role
FROM committees c
JOIN committee_names cn ON (
    (c.executive_committee = 1 AND cn.name = 'executive_committee') OR
    (c.membership = 1 AND cn.name = 'membership') OR
    (c.trap = 1 AND cn.name = 'trap') OR
    (c.still_target = 1 AND cn.name = 'still_target') OR
    (c.gun_bingo_social_events = 1 AND cn.name = 'gun_bingo_social_events') OR
    (c.rifle = 1 AND cn.name = 'rifle') OR
    (c.pistol = 1 AND cn.name = 'pistol') OR
    (c.archery = 1 AND cn.name = 'archery') OR
    (c.building_and_grounds = 1 AND cn.name = 'building_and_grounds') OR
    (c.hunting = 1 AND cn.name = 'hunting')
);

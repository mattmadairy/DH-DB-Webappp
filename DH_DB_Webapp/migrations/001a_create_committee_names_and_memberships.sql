-- Step 1: Create committee_names and committee_memberships tables
CREATE TABLE IF NOT EXISTS committee_names (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL
);

CREATE TABLE IF NOT EXISTS committee_memberships (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    member_id INTEGER NOT NULL,
    committee_id INTEGER NOT NULL,
    role TEXT,
    FOREIGN KEY(member_id) REFERENCES members(id),
    FOREIGN KEY(committee_id) REFERENCES committee_names(id)
);

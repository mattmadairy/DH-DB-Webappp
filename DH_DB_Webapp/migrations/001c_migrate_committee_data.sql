-- Step 3: Migrate existing committee data from old committees table to committee_memberships using committee_names
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

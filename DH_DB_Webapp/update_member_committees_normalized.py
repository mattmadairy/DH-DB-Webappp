def update_member_committees_normalized(member_id, new_memberships):
    """
    Update the committee_memberships table for a member based on a dict:
    {committee_name: 'none'|'member'|'chair'}
    """
    from DH_DB_Webapp import database
    conn = database.get_connection()
    c = conn.cursor()
    # Get all committee names and their ids
    c.execute("SELECT id, name FROM committee_names")
    committee_map = {row['name']: row['id'] for row in c.fetchall()}
    # Remove all current memberships for this member
    c.execute("DELETE FROM committee_memberships WHERE member_id=?", (member_id,))
    # Insert new memberships
    for cname, role in new_memberships.items():
        if role in ('member', 'chair'):
            committee_id = committee_map.get(cname)
            if committee_id:
                c.execute(
                    "INSERT INTO committee_memberships (member_id, committee_id, role) VALUES (?, ?, ?)",
                    (member_id, committee_id, role)
                )
    conn.commit()
    conn.close()

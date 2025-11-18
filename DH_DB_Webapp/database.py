def get_meeting_attendance_report(year=None, month=None):
    """
    Return a list of dicts with badge_number, first_name, last_name, meeting_date, status for all meeting attendance records, filtered by year and month if provided.
    """
    conn = get_connection()
    c = conn.cursor()
    params = []
    if month == 'all':
        query = '''
            SELECT m.badge_number, m.first_name, m.last_name,
                   COUNT(CASE WHEN a.status IN ('Attended', 'Exempt') THEN 1 END) as total_meetings
            FROM members m
            LEFT JOIN meeting_attendance a ON m.id = a.member_id
            WHERE m.deleted = 0
        '''
        if year:
            query += " AND strftime('%Y', a.meeting_date) = ?"
            params.append(year)
        query += " GROUP BY m.id ORDER BY m.last_name, m.first_name"
        c.execute(query, params)
        rows = c.fetchall()
        conn.close()
        return rows
    else:
        query = '''
            SELECT m.badge_number, m.first_name, m.last_name, a.meeting_date, a.status
            FROM members m
            JOIN meeting_attendance a ON m.id = a.member_id
            WHERE m.deleted = 0
        '''
        if year:
            query += " AND strftime('%Y', a.meeting_date) = ?"
            params.append(year)
        if month:
            query += " AND strftime('%m', a.meeting_date) = ?"
            params.append(month)
        query += " ORDER BY a.meeting_date DESC, m.last_name, m.first_name"
        c.execute(query, params)
        rows = c.fetchall()
        conn.close()
        return rows
def get_meeting_years():
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT DISTINCT strftime('%Y', meeting_date) as year FROM meeting_attendance ORDER BY year DESC")
    years = [row['year'] for row in c.fetchall() if row['year']]
    conn.close()
    return years
def get_work_hours_report(start_date=None, end_date=None):
    """
    Return a list of (badge_number, first_name, last_name, total_hours, id)
    for all members, optionally filtered by date range.
    """
    conn = get_connection()
    c = conn.cursor()
    query = """
        SELECT m.badge_number, m.first_name, m.last_name,
               IFNULL(SUM(w.hours), 0) as total_hours, m.id
        FROM members m
        LEFT JOIN work_hours w ON m.id = w.member_id
        WHERE m.deleted = 0
    """
    params = []
    if start_date:
        query += " AND (w.date >= ? OR w.date IS NULL)"
        params.append(start_date)
    if end_date:
        query += " AND (w.date <= ? OR w.date IS NULL)"
        params.append(end_date)
    query += " GROUP BY m.id ORDER BY m.last_name, m.first_name"
    c.execute(query, params)
    rows = c.fetchall()
    conn.close()
    return rows
def get_dues_years():
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT DISTINCT strftime('%Y', payment_date) as year FROM dues ORDER BY year DESC")
    years = [row['year'] for row in c.fetchall() if row['year']]
    conn.close()
    return years

def get_all_dues_by_year(year=None):
    conn = get_connection()
    c = conn.cursor()
    if year:
        c.execute("SELECT d.*, m.first_name, m.last_name, m.badge_number FROM dues d JOIN members m ON d.member_id = m.id WHERE m.deleted=0 AND d.year=? ORDER BY d.payment_date ASC", (year,))
    else:
        c.execute("SELECT d.*, m.first_name, m.last_name, m.badge_number FROM dues d JOIN members m ON d.member_id = m.id WHERE m.deleted=0 ORDER BY d.payment_date ASC")
    rows = c.fetchall()
    conn.close()
    return rows
def get_all_dues():
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT d.*, m.first_name, m.last_name, m.badge_number FROM dues d JOIN members m ON d.member_id = m.id WHERE m.deleted=0 ORDER BY d.payment_date ASC")
    rows = c.fetchall()
    conn.close()
    return rows
def update_member_committees(member_id, updates):
    print(f"Updating committees for member_id={member_id} with updates={updates}")
    conn = get_connection()
    c = conn.cursor()
    # Check if row exists for member_id
    c.execute("SELECT 1 FROM committees WHERE member_id=?", (member_id,))
    exists = c.fetchone()
    if not exists:
        # Insert a new row with all committee columns set to 0 except those in updates
        c.execute("PRAGMA table_info(committees)")
        columns = [row[1] for row in c.fetchall() if row[1] != 'member_id']
        col_names = ', '.join(['member_id'] + columns)
        col_placeholders = ', '.join(['?'] * (1 + len(columns)))
        values = [member_id] + [updates.get(col, 0) for col in columns]
        c.execute(f"INSERT INTO committees ({col_names}) VALUES ({col_placeholders})", values)
    else:
        # Build SET clause dynamically
        set_clause = ', '.join([f'{k}=?' for k in updates.keys()])
        print(f"SET clause: {set_clause}")
        values = list(updates.values())
        values.append(member_id)
        print(f"Values: {values}")
        c.execute(f"UPDATE committees SET {set_clause} WHERE member_id=?", values)
    conn.commit()
    conn.close()
def update_member_position(member_id, position, term_start=None, term_end=None):
    conn = get_connection()
    c = conn.cursor()
    # Check if position exists for member
    c.execute("SELECT * FROM roles WHERE member_id=?", (member_id,))
    if c.fetchone():
        c.execute("UPDATE roles SET position=?, term_start=?, term_end=? WHERE member_id=?", (position, term_start, term_end, member_id))
    else:
        c.execute("INSERT INTO roles (member_id, position, term_start, term_end) VALUES (?, ?, ?, ?)", (member_id, position, term_start, term_end))
    conn.commit()
    conn.close()
def add_work_hours(member_id, date, activity, hours, notes):
    conn = get_connection()
    c = conn.cursor()
    c.execute("INSERT INTO work_hours (member_id, date, activity, hours, notes) VALUES (?, ?, ?, ?, ?)", (member_id, date, activity, hours, notes))
    conn.commit()
    conn.close()
import sqlite3
from datetime import datetime
import os

DB_NAME = "members.db"

def init_database():
	"""Initialize the database with all required tables if they don't exist."""
	conn = sqlite3.connect(DB_NAME)
	c = conn.cursor()
	
	# Create members table
	c.execute("""
		CREATE TABLE IF NOT EXISTS members (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			badge_number TEXT,
			membership_type TEXT,
			first_name TEXT NOT NULL,
			middle_name TEXT,
			last_name TEXT NOT NULL,
			suffix TEXT,
			nickname TEXT,
			dob TEXT,
			email TEXT,
			email2 TEXT,
			phone TEXT,
			phone2 TEXT,
			address TEXT,
			city TEXT,
			state TEXT,
			zip TEXT,
			join_date TEXT,
			sponsor TEXT,
			card_internal TEXT,
			card_external TEXT,
			deleted INTEGER DEFAULT 0,
			deleted_on TEXT
		)
	""")
	
	# Create dues table
	c.execute("""
		CREATE TABLE IF NOT EXISTS dues (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			member_id INTEGER NOT NULL,
			payment_date TEXT NOT NULL,
			amount REAL NOT NULL,
			year TEXT NOT NULL,
			method TEXT,
			notes TEXT,
			FOREIGN KEY (member_id) REFERENCES members(id)
		)
	""")
	
	# Create work_hours table
	c.execute("""
		CREATE TABLE IF NOT EXISTS work_hours (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			member_id INTEGER NOT NULL,
			date TEXT NOT NULL,
			activity TEXT NOT NULL,
			hours REAL NOT NULL,
			notes TEXT,
			FOREIGN KEY (member_id) REFERENCES members(id)
		)
	""")
	
	# Create meeting_attendance table
	c.execute("""
		CREATE TABLE IF NOT EXISTS meeting_attendance (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			member_id INTEGER NOT NULL,
			meeting_date TEXT NOT NULL,
			status TEXT NOT NULL,
			FOREIGN KEY (member_id) REFERENCES members(id)
		)
	""")
	
	# Create roles table
	c.execute("""
		CREATE TABLE IF NOT EXISTS roles (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			member_id INTEGER NOT NULL,
			position TEXT,
			term_start TEXT,
			term_end TEXT,
			FOREIGN KEY (member_id) REFERENCES members(id)
		)
	""")
	
	# Create committees table
	c.execute("""
		CREATE TABLE IF NOT EXISTS committees (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			member_id INTEGER NOT NULL,
			executive_committee INTEGER DEFAULT 0,
			gun_bingo_social_events INTEGER DEFAULT 0,
			building_and_grounds INTEGER DEFAULT 0,
			fundraising INTEGER DEFAULT 0,
			membership INTEGER DEFAULT 0,
			FOREIGN KEY (member_id) REFERENCES members(id)
		)
	""")
	
	conn.commit()
	conn.close()

def get_connection():
	conn = sqlite3.connect(DB_NAME)
	conn.row_factory = sqlite3.Row
	return conn

# Initialize database on module import
init_database()

def get_all_members():
	conn = get_connection()
	c = conn.cursor()
	c.execute("SELECT * FROM members WHERE deleted=0")
	rows = c.fetchall()
	conn.close()
	return rows

def get_member_by_id(member_id):
	conn = get_connection()
	c = conn.cursor()
	c.execute("SELECT * FROM members WHERE id=?", (member_id,))
	row = c.fetchone()
	conn.close()
	return row

def get_dues_by_member(member_id):
	conn = get_connection()
	c = conn.cursor()
	c.execute("SELECT * FROM dues WHERE member_id=? ORDER BY payment_date ASC", (member_id,))
	rows = c.fetchall()
	conn.close()
	return rows

def get_work_hours_by_member(member_id):
	conn = get_connection()
	c = conn.cursor()
	c.execute("SELECT * FROM work_hours WHERE member_id=? ORDER BY date ASC", (member_id,))
	rows = c.fetchall()
	conn.close()
	return rows

def get_meeting_attendance(member_id):
	conn = get_connection()
	c = conn.cursor()
	c.execute("SELECT * FROM meeting_attendance WHERE member_id=? ORDER BY meeting_date ASC", (member_id,))
	rows = c.fetchall()
	conn.close()
	return rows

def get_member_position(member_id):
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM roles WHERE member_id=?", (member_id,))
    row = c.fetchone()
    conn.close()
    return row

def get_member_committees(member_id):
	conn = get_connection()
	c = conn.cursor()
	c.execute("SELECT * FROM committees WHERE member_id=?", (member_id,))
	row = c.fetchone()
	conn.close()
	return dict(row) if row else {}

def add_member(data):
	conn = get_connection()
	c = conn.cursor()
	c.execute("""
		INSERT INTO members (
			badge_number, membership_type, first_name, middle_name, last_name, suffix, nickname, dob,
			email, email2, phone, phone2, address, city, state, zip, join_date, sponsor, card_internal, card_external
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	""", data)
	conn.commit()
	member_id = c.lastrowid
	conn.close()
	return member_id

def update_member(member_id, data):
	conn = get_connection()
	c = conn.cursor()
	c.execute("""
		UPDATE members SET
			badge_number=?, membership_type=?, first_name=?, middle_name=?, last_name=?, suffix=?, nickname=?, dob=?,
			email=?, email2=?, phone=?, phone2=?, address=?, city=?, state=?, zip=?, join_date=?, sponsor=?, card_internal=?, card_external=?
		WHERE id=?
	""", data + (member_id,))
	conn.commit()
	conn.close()

def update_member_section(member_id, fields):
    conn = get_connection()
    c = conn.cursor()
    set_clause = ', '.join([f'{key}=?' for key in fields.keys()])
    values = list(fields.values())
    values.append(member_id)
    c.execute(f"UPDATE members SET {set_clause} WHERE id=?", values)
    conn.commit()
    conn.close()

def soft_delete_member_by_id(member_id):
    conn = get_connection()
    c = conn.cursor()
    deleted_on = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    c.execute("UPDATE members SET deleted=1, deleted_on=? WHERE id=?", (deleted_on, member_id))
    conn.commit()
    conn.close()

def get_deleted_members():
	conn = get_connection()
	c = conn.cursor()
	c.execute("SELECT * FROM members WHERE deleted=1")
	rows = c.fetchall()
	conn.close()
	return rows

def restore_member_by_id(member_id):
	conn = get_connection()
	c = conn.cursor()
	c.execute("UPDATE members SET deleted=0 WHERE id=?", (member_id,))
	conn.commit()
	conn.close()

# Add a due for a member

def add_due(member_id, payment_date, amount, year, method, notes):
    conn = get_connection()
    c = conn.cursor()
    c.execute("INSERT INTO dues (member_id, payment_date, amount, year, method, notes) VALUES (?, ?, ?, ?, ?, ?)", (member_id, payment_date, amount, year, method, notes))
    conn.commit()
    conn.close()

def get_due_by_id(due_id):
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM dues WHERE id=?", (due_id,))
    row = c.fetchone()
    conn.close()
    return dict(row) if row else {}

def update_due(due_id, payment_date, amount, year, method, notes):
    conn = get_connection()
    c = conn.cursor()
    c.execute("UPDATE dues SET payment_date=?, amount=?, year=?, method=?, notes=? WHERE id=?", (payment_date, amount, year, method, notes, due_id))
    conn.commit()
    conn.close()

def delete_due(due_id):
    conn = get_connection()
    c = conn.cursor()
    c.execute("DELETE FROM dues WHERE id=?", (due_id,))
    conn.commit()
    conn.close()

def get_work_hours_by_id(wh_id):
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM work_hours WHERE id=?", (wh_id,))
    row = c.fetchone()
    conn.close()
    return row

def update_work_hours(wh_id, date, activity, hours, notes):
    conn = get_connection()
    c = conn.cursor()
    c.execute("UPDATE work_hours SET date=?, activity=?, hours=?, notes=? WHERE id=?", (date, activity, hours, notes, wh_id))
    conn.commit()
    conn.close()

def delete_work_hours(wh_id):
    conn = get_connection()
    c = conn.cursor()
    c.execute("DELETE FROM work_hours WHERE id=?", (wh_id,))
    conn.commit()
    conn.close()

def delete_member_permanently(member_id):
    conn = get_connection()
    c = conn.cursor()
    c.execute("DELETE FROM members WHERE id=?", (member_id,))
    conn.commit()
    conn.close()

def add_meeting_attendance(member_id, date, status):
    conn = get_connection()
    c = conn.cursor()
    c.execute("INSERT INTO meeting_attendance (member_id, meeting_date, status) VALUES (?, ?, ?)", (member_id, date, status))
    conn.commit()
    conn.close()

def get_meeting_attendance_by_id(att_id):
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM meeting_attendance WHERE id=?", (att_id,))
    row = c.fetchone()
    conn.close()
    return row

def update_meeting_attendance(att_id, date, status):
    conn = get_connection()
    c = conn.cursor()
    c.execute("UPDATE meeting_attendance SET meeting_date=?, status=? WHERE id=?", (date, status, att_id))
    conn.commit()
    conn.close()

def delete_meeting_attendance(att_id):
    conn = get_connection()
    c = conn.cursor()
    c.execute("DELETE FROM meeting_attendance WHERE id=?", (att_id,))
    conn.commit()
    conn.close()

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
        c.execute("SELECT d.*, m.first_name, m.last_name, m.badge_number FROM dues d JOIN members m ON d.member_id = m.id WHERE m.deleted=0 AND strftime('%Y', d.payment_date)=? ORDER BY d.payment_date ASC", (year,))
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

DB_NAME = "members.db"

def get_connection():
	conn = sqlite3.connect(DB_NAME)
	conn.row_factory = sqlite3.Row
	return conn

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

def add_due(member_id, payment_date, amount):
    conn = get_connection()
    c = conn.cursor()
    c.execute("INSERT INTO dues (member_id, payment_date, amount) VALUES (?, ?, ?)", (member_id, payment_date, amount))
    conn.commit()
    conn.close()

def get_due_by_id(due_id):
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM dues WHERE id=?", (due_id,))
    row = c.fetchone()
    conn.close()
    return row

def update_due(due_id, payment_date, amount):
    conn = get_connection()
    c = conn.cursor()
    c.execute("UPDATE dues SET payment_date=?, amount=? WHERE id=?", (payment_date, amount, due_id))
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

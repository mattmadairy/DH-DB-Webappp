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

def get_member_role(member_id):
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

def delete_member_permanently(member_id):
    conn = get_connection()
    c = conn.cursor()
    c.execute("DELETE FROM members WHERE id=?", (member_id,))
    conn.commit()
    conn.close()

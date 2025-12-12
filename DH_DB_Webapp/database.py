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
        query += " GROUP BY m.id ORDER BY CAST(m.badge_number AS INTEGER), m.last_name, m.first_name"
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
        query += " ORDER BY CAST(m.badge_number AS INTEGER), m.last_name, m.first_name"
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
    query += " GROUP BY m.id ORDER BY CAST(m.badge_number AS INTEGER), m.last_name, m.first_name"
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
    # Always include 2026 if not already in the list
    if '2026' not in years:
        years.insert(0, '2026')
    return years

def get_all_dues_by_year(year=None):
    conn = get_connection()
    c = conn.cursor()
    if year:
        c.execute("SELECT d.*, m.first_name, m.last_name, m.badge_number FROM dues d JOIN members m ON d.member_id = m.id WHERE m.deleted=0 AND d.year=? ORDER BY CAST(m.badge_number AS INTEGER), m.last_name, m.first_name", (year,))
    else:
        c.execute("SELECT d.*, m.first_name, m.last_name, m.badge_number FROM dues d JOIN members m ON d.member_id = m.id WHERE m.deleted=0 ORDER BY CAST(m.badge_number AS INTEGER), m.last_name, m.first_name")
    rows = c.fetchall()
    conn.close()
    return rows
def get_all_dues():
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT d.*, m.first_name, m.last_name, m.badge_number FROM dues d JOIN members m ON d.member_id = m.id WHERE m.deleted=0 ORDER BY CAST(m.badge_number AS INTEGER), m.last_name, m.first_name")
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
        columns = [row[1] for row in c.fetchall() if row[1] not in ('member_id', 'committee_id', 'notes')]
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
	
	# Create users table for authentication
	c.execute("""
		CREATE TABLE IF NOT EXISTS users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT UNIQUE NOT NULL,
			name TEXT,
			password_hash TEXT NOT NULL,
			email TEXT UNIQUE NOT NULL,
			created_at TEXT NOT NULL,
			is_active INTEGER DEFAULT 1,
			role TEXT DEFAULT 'User',
			must_change_password INTEGER DEFAULT 0,
			failed_login_attempts INTEGER DEFAULT 0,
			locked_until TEXT,
			last_login TEXT,
			last_password_change TEXT
		)
	""")
	
	# Create audit log table
	c.execute("""
		CREATE TABLE IF NOT EXISTS audit_log (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER,
			username TEXT,
			action TEXT NOT NULL,
			target_user TEXT,
			ip_address TEXT,
			user_agent TEXT,
			timestamp TEXT NOT NULL,
			success INTEGER DEFAULT 1,
			details TEXT
		)
	""")
	
	# Create password history table
	c.execute("""
		CREATE TABLE IF NOT EXISTS password_history (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER NOT NULL,
			password_hash TEXT NOT NULL,
			changed_at TEXT NOT NULL,
			FOREIGN KEY (user_id) REFERENCES users(id)
		)
	""")
	
	# Create check_ins table for kiosk functionality
	c.execute("""
		CREATE TABLE IF NOT EXISTS check_ins (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			member_number TEXT NOT NULL,
			check_in_time TEXT NOT NULL,
			activities TEXT,
			guest1_name TEXT,
			guest2_name TEXT,
			other_activity TEXT,
			sign_out_time TEXT,
			tos_accepted INTEGER DEFAULT 0,
			guest1_tos_accepted INTEGER DEFAULT 0,
			guest2_tos_accepted INTEGER DEFAULT 0,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)
	""")
	
	conn.commit()
	conn.close()

def get_connection():
	conn = sqlite3.connect(DB_NAME, timeout=30.0)  # Increase timeout for PythonAnywhere
	conn.row_factory = sqlite3.Row
	# Enable WAL mode for better concurrent access
	conn.execute('PRAGMA journal_mode=WAL')
	return conn

# Initialize database on module import
init_database()

def get_all_members():
	conn = get_connection()
	c = conn.cursor()
	c.execute("SELECT * FROM members WHERE deleted=0 ORDER BY CAST(badge_number AS INTEGER), last_name, first_name")
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

def get_member_by_badge_number(badge_number):
	"""Get member by badge number"""
	conn = get_connection()
	c = conn.cursor()
	c.execute("SELECT * FROM members WHERE badge_number=?", (badge_number,))
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

# ========== User Authentication Functions ==========

def create_user(username, password_hash, email, name=None, role='User'):
    """Create a new user account"""
    from datetime import datetime
    conn = get_connection()
    c = conn.cursor()
    try:
        # New users created by admin must change password on first login
        c.execute("""
            INSERT INTO users (username, name, password_hash, email, created_at, role, must_change_password)
            VALUES (?, ?, ?, ?, ?, ?, 1)
        """, (username, name, password_hash, email, datetime.now().isoformat(), role))
        conn.commit()
        user_id = c.lastrowid
        conn.close()
        return user_id
    except sqlite3.IntegrityError:
        conn.close()
        return None

def get_user_by_username(username):
    """Get user by username"""
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE username=?", (username,))
    user = c.fetchone()
    conn.close()
    return user

def get_user_by_id(user_id):
    """Get user by ID"""
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE id=?", (user_id,))
    user = c.fetchone()
    conn.close()
    return user

def get_user_by_email(email):
    """Get user by email"""
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE email=?", (email,))
    user = c.fetchone()
    conn.close()
    return user

def get_all_users():
    """Get all users"""
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT id, username, name, email, role, is_active, created_at, last_login FROM users ORDER BY created_at DESC")
    users = c.fetchall()
    conn.close()
    return users

def update_user_password(user_id, password_hash):
    """Update user password and clear must_change_password flag"""
    from datetime import datetime
    conn = get_connection()
    c = conn.cursor()
    c.execute("UPDATE users SET password_hash=?, must_change_password=0, last_password_change=? WHERE id=?", 
              (password_hash, datetime.now().isoformat(), user_id))
    conn.commit()
    conn.close()

# Security-related functions

def log_audit(user_id, username, action, target_user=None, ip_address=None, user_agent=None, success=True, details=None):
    """Log security-related events"""
    from datetime import datetime
    conn = get_connection()
    c = conn.cursor()
    c.execute("""
        INSERT INTO audit_log (user_id, username, action, target_user, ip_address, user_agent, timestamp, success, details)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (user_id, username, action, target_user, ip_address, user_agent, datetime.now().isoformat(), 1 if success else 0, details))
    conn.commit()
    conn.close()

def increment_failed_login(username):
    """Increment failed login attempts"""
    conn = get_connection()
    c = conn.cursor()
    c.execute("UPDATE users SET failed_login_attempts = failed_login_attempts + 1 WHERE username = ?", (username,))
    conn.commit()
    conn.close()

def reset_failed_login(user_id):
    """Reset failed login attempts to 0"""
    conn = get_connection()
    c = conn.cursor()
    c.execute("UPDATE users SET failed_login_attempts = 0, locked_until = NULL WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()

def lock_account(username, duration_minutes=30):
    """Lock user account for specified duration"""
    from datetime import datetime, timedelta
    locked_until = (datetime.now() + timedelta(minutes=duration_minutes)).isoformat()
    conn = get_connection()
    c = conn.cursor()
    c.execute("UPDATE users SET locked_until = ? WHERE username = ?", (locked_until, username))
    conn.commit()
    conn.close()

def is_account_locked(username):
    """Check if account is currently locked"""
    from datetime import datetime
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT locked_until FROM users WHERE username = ?", (username,))
    result = c.fetchone()
    conn.close()
    
    if result and result['locked_until']:
        locked_until = datetime.fromisoformat(result['locked_until'])
        if datetime.now() < locked_until:
            return True, locked_until
    return False, None

def update_last_login(user_id):
    """Update last login timestamp"""
    from datetime import datetime
    conn = get_connection()
    c = conn.cursor()
    c.execute("UPDATE users SET last_login = ? WHERE id = ?", (datetime.now().isoformat(), user_id))
    conn.commit()
    conn.close()

def add_password_history(user_id, password_hash):
    """Store password in history"""
    from datetime import datetime
    conn = get_connection()
    c = conn.cursor()
    c.execute("""
        INSERT INTO password_history (user_id, password_hash, changed_at)
        VALUES (?, ?, ?)
    """, (user_id, password_hash, datetime.now().isoformat()))
    conn.commit()
    conn.close()

def check_password_history(user_id, new_password_hash, history_count=5):
    """Check if password was used recently"""
    from werkzeug.security import check_password_hash
    conn = get_connection()
    c = conn.cursor()
    c.execute("""
        SELECT password_hash FROM password_history 
        WHERE user_id = ? 
        ORDER BY changed_at DESC 
        LIMIT ?
    """, (user_id, history_count))
    history = c.fetchall()
    conn.close()
    
    # Check current password too
    c = conn.cursor()
    c.execute("SELECT password_hash FROM users WHERE id = ?", (user_id,))
    current = c.fetchone()
    conn.close()
    
    if current:
        history.append(current)
    
    for record in history:
        if check_password_hash(record['password_hash'], new_password_hash):
            return True
    return False

def get_audit_logs(limit=100, user_id=None):
    """Get recent audit logs"""
    conn = get_connection()
    c = conn.cursor()
    if user_id:
        c.execute("SELECT * FROM audit_log WHERE user_id = ? ORDER BY timestamp DESC LIMIT ?", (user_id, limit))
    else:
        c.execute("SELECT * FROM audit_log ORDER BY timestamp DESC LIMIT ?", (limit,))
    logs = c.fetchall()
    conn.close()
    return logs

# ========== Kiosk Check-in Functions ==========

def get_active_checkin_for_member(member_number):
    """Check if a member has an active check-in (no sign-out time)"""
    conn = get_connection()
    c = conn.cursor()
    c.execute("""
        SELECT * FROM check_ins 
        WHERE member_number = ? 
        AND (sign_out_time IS NULL OR sign_out_time = '')
        ORDER BY check_in_time DESC
        LIMIT 1
    """, (member_number,))
    row = c.fetchone()
    conn.close()
    return row

def add_checkin(member_number, check_in_time, activities, guest1_name=None, guest2_name=None, other_activity=None, tos_accepted=0, guest1_tos_accepted=0, guest2_tos_accepted=0):
    """Add a new kiosk check-in"""
    conn = get_connection()
    c = conn.cursor()
    c.execute("""
        INSERT INTO check_ins (member_number, check_in_time, activities, guest1_name, guest2_name, other_activity, tos_accepted, guest1_tos_accepted, guest2_tos_accepted)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (member_number, check_in_time, activities, guest1_name, guest2_name, other_activity, tos_accepted, guest1_tos_accepted, guest2_tos_accepted))
    conn.commit()
    checkin_id = c.lastrowid
    conn.close()
    return checkin_id

def get_all_checkins(date=None):
    """Get all check-ins, optionally filtered by date"""
    conn = get_connection()
    c = conn.cursor()
    if date:
        c.execute("""
            SELECT c.*, m.first_name, m.last_name 
            FROM check_ins c
            LEFT JOIN members m ON c.member_number = m.badge_number
            WHERE DATE(c.check_in_time) = ?
            ORDER BY c.check_in_time DESC
        """, (date,))
    else:
        c.execute("""
            SELECT c.*, m.first_name, m.last_name 
            FROM check_ins c
            LEFT JOIN members m ON c.member_number = m.badge_number
            ORDER BY c.check_in_time DESC LIMIT 100
        """)
    rows = c.fetchall()
    conn.close()
    return rows

def get_today_checkins():
    """Get today's check-ins that haven't been signed out"""
    conn = get_connection()
    c = conn.cursor()
    # Get today's date in YYYY-MM-DD format from Python to ensure consistency
    import datetime
    today = datetime.date.today().strftime('%Y-%m-%d')
    c.execute("""
        SELECT * FROM check_ins 
        WHERE DATE(check_in_time) = ?
        AND (sign_out_time IS NULL OR sign_out_time = '')
        ORDER BY check_in_time DESC
    """, (today,))
    rows = c.fetchall()
    conn.close()
    return rows

def get_today_checkins_by_date(date_str):
    """Get check-ins for a specific date that haven't been signed out"""
    conn = get_connection()
    c = conn.cursor()
    c.execute("""
        SELECT * FROM check_ins 
        WHERE DATE(check_in_time) = ?
        AND (sign_out_time IS NULL OR sign_out_time = '')
        ORDER BY check_in_time DESC
    """, (date_str,))
    rows = c.fetchall()
    conn.close()
    return rows

def sign_out_checkin(checkin_id, sign_out_time):
    """Sign out a member by updating their check-in record"""
    conn = get_connection()
    c = conn.cursor()
    c.execute("UPDATE check_ins SET sign_out_time = ? WHERE id = ?", (sign_out_time, checkin_id))
    conn.commit()
    affected = c.rowcount
    conn.close()
    return affected > 0

def get_checkin_by_id(checkin_id):
    """Get a specific check-in by ID"""
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM check_ins WHERE id = ?", (checkin_id,))
    row = c.fetchone()
    conn.close()
    return row

def get_checkins_by_date_range(start_date, end_date):
    """Get check-ins within a date range"""
    conn = get_connection()
    c = conn.cursor()
    c.execute("""
        SELECT c.*, m.first_name, m.last_name 
        FROM check_ins c
        LEFT JOIN members m ON c.member_number = m.badge_number
        WHERE DATE(c.check_in_time) BETWEEN ? AND ?
        ORDER BY c.check_in_time DESC
    """, (start_date, end_date))
    rows = c.fetchall()
    conn.close()
    return rows

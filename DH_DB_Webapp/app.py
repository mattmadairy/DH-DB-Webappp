from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import generate_password_hash, check_password_hash
import database
import datetime
import socket
import os
import pytz

app = Flask(__name__)

# Disable template caching in development
app.config['TEMPLATES_AUTO_RELOAD'] = True
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0

# Set timezone to America/New_York
TIMEZONE = pytz.timezone('America/New_York')

# Load configuration
env = os.environ.get('FLASK_ENV', 'development')
from config import config
app.config.from_object(config[env])

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'
login_manager.login_message_category = 'info'

# Initialize CSRF protection
csrf = CSRFProtect(app)

# Initialize rate limiter
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

# User class for Flask-Login
class User(UserMixin):
    def __init__(self, id, username, email, role='User', is_active=True, must_change_password=False):
        self.id = id
        self.username = username
        self.email = email
        self.role = role
        self._is_active = is_active
        self.must_change_password = must_change_password
    
    def get_id(self):
        return str(self.id)
    
    @property
    def is_active(self):
        return self._is_active
    
    def is_bdfl(self):
        return self.role == 'BDFL'
    
    def is_admin(self):
        return self.role == 'Administrator'
    
    def is_admin_or_bdfl(self):
        return self.role in ('BDFL', 'Administrator')

@login_manager.user_loader
def load_user(user_id):
    user_data = database.get_user_by_id(int(user_id))
    if user_data:
        # Handle role column that might not exist in older databases
        try:
            role = user_data['role']
        except (KeyError, IndexError):
            role = 'User'
        
        # Handle must_change_password column
        try:
            must_change_password = bool(user_data['must_change_password'])
        except (KeyError, IndexError):
            must_change_password = False
        
        return User(
            id=user_data['id'],
            username=user_data['username'],
            email=user_data['email'],
            role=role,
            is_active=bool(user_data['is_active']),
            must_change_password=must_change_password
        )
    return None


def get_local_ip():
    """Get the local IP address of the host machine"""
    try:
        # Create a socket connection to get the local IP
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except Exception:
        return "127.0.0.1"

# Jinja filter to format ISO date as mm-dd-yyyy
def format_mmddyyyy(value):
    if not value:
        return ''
    try:
        from datetime import datetime
        dt = datetime.strptime(value, '%Y-%m-%d')
        return dt.strftime('%m-%d-%Y')
    except Exception:
        return value

app.jinja_env.filters['format_mmddyyyy'] = format_mmddyyyy

# Jinja filter to format datetime as mm-dd-yyyy   hh:mm (24-hour)
def format_datetime(value):
    if not value:
        return ''
    try:
        dt = datetime.datetime.strptime(value, '%Y-%m-%d %H:%M:%S')
        date_part = dt.strftime('%m-%d-%Y')
        time_part = dt.strftime('%H:%M')
        return date_part + '   ' + time_part
    except Exception:
        return value

app.jinja_env.filters['format_datetime'] = format_datetime

def get_member_stats():
	"""Calculate member statistics for sidebar display"""
	all_members = database.get_all_members()
	life_count = len([m for m in all_members if m['membership_type'] == 'Life'])
	voting_count = len([m for m in all_members if m['membership_type'] in ['Probationary', 'Associate', 'Active']])
	total_count = len(all_members)
	return {
		'life_members': life_count,
		'voting_members': voting_count,
		'total_members': total_count
	}

# Security headers middleware
@app.after_request
def set_security_headers(response):
	"""Add security headers to all responses"""
	response.headers['X-Content-Type-Options'] = 'nosniff'
	response.headers['X-Frame-Options'] = 'DENY'
	response.headers['X-XSS-Protection'] = '1; mode=block'
	response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
	response.headers['Content-Security-Policy'] = "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'"
	return response

# Authentication routes
@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def login():
	if current_user.is_authenticated:
		return redirect(url_for('index'))
	
	if request.method == 'POST':
		username = request.form.get('username')
		password = request.form.get('password')
		
		user_data = database.get_user_by_username(username)
		
		# Check if account is locked
		if user_data:
			is_locked, locked_until = database.is_account_locked(username)
			if is_locked:
				remaining = (locked_until - datetime.datetime.now()).total_seconds() / 60
				flash(f'Account is locked due to too many failed login attempts. Try again in {int(remaining)} minutes.', 'error')
				database.log_audit(
					user_id=user_data['id'],
					username=username,
					action='login_attempt',
					ip_address=request.remote_addr,
					user_agent=request.headers.get('User-Agent'),
					success=False,
					details='Account locked'
				)
				return render_template('login.html')
		
		if user_data and user_data['is_active']:
			# Handle must_change_password column
			try:
				must_change_password = bool(user_data['must_change_password'])
			except (KeyError, IndexError):
				must_change_password = False
			
			# If password reset is required, log them in regardless of password and redirect
			if must_change_password:
				# Handle role column that might not exist in older databases
				try:
					role = user_data['role']
				except (KeyError, IndexError):
					role = 'User'
				
				user = User(
					id=user_data['id'],
					username=user_data['username'],
					email=user_data['email'],
					role=role,
					is_active=bool(user_data['is_active']),
					must_change_password=must_change_password
				)
				login_user(user)
				database.update_last_login(user_data['id'])
				database.log_audit(
					user_id=user_data['id'],
					username=username,
					action='login',
					ip_address=request.remote_addr,
					user_agent=request.headers.get('User-Agent'),
					success=True,
					details='Password reset required'
				)
				flash('Your password has been reset. You must change it before continuing.', 'info')
				return redirect(url_for('change_password'))
			
			# Normal login flow - check password
			if check_password_hash(user_data['password_hash'], password):
				# Handle role column that might not exist in older databases
				try:
					role = user_data['role']
				except (KeyError, IndexError):
					role = 'User'
				
				user = User(
					id=user_data['id'],
					username=user_data['username'],
					email=user_data['email'],
					role=role,
					is_active=bool(user_data['is_active']),
					must_change_password=must_change_password
				)
				login_user(user)
				
				# Reset failed login attempts and update last login
				database.reset_failed_login(user_data['id'])
				database.update_last_login(user_data['id'])
				database.log_audit(
					user_id=user_data['id'],
					username=username,
					action='login',
					ip_address=request.remote_addr,
					user_agent=request.headers.get('User-Agent'),
					success=True
				)
				
				flash('Login successful!', 'info')
				next_page = request.args.get('next')
				return redirect(next_page) if next_page else redirect(url_for('index'))
			else:
				# Increment failed login attempts
				database.increment_failed_login(username)
				
				# Check if we need to lock the account
				user_data = database.get_user_by_username(username)  # Refresh data
				if user_data and user_data['failed_login_attempts'] >= 5:
					database.lock_account(username, duration_minutes=30)
					flash('Too many failed login attempts. Your account has been locked for 30 minutes.', 'error')
					database.log_audit(
						user_id=user_data['id'],
						username=username,
						action='account_locked',
						ip_address=request.remote_addr,
						user_agent=request.headers.get('User-Agent'),
						success=False,
						details=f"Failed attempts: {user_data['failed_login_attempts']}"
					)
				else:
					flash('Invalid username or password.', 'error')
					database.log_audit(
						user_id=user_data['id'] if user_data else None,
						username=username,
						action='login_attempt',
						ip_address=request.remote_addr,
						user_agent=request.headers.get('User-Agent'),
						success=False,
						details='Invalid password'
					)
		elif user_data and not user_data['is_active']:
			flash('Your account has been deactivated. Please contact an administrator.', 'error')
			database.log_audit(
				user_id=user_data['id'],
				username=username,
				action='login_attempt',
				ip_address=request.remote_addr,
				user_agent=request.headers.get('User-Agent'),
				success=False,
				details='Account inactive'
			)
		else:
			flash('Invalid username or password.', 'error')
			database.log_audit(
				user_id=None,
				username=username,
				action='login_attempt',
				ip_address=request.remote_addr,
				user_agent=request.headers.get('User-Agent'),
				success=False,
				details='Username not found'
			)
	
	return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
	if current_user.is_authenticated:
		return redirect(url_for('index'))
	
	if request.method == 'POST':
		username = request.form.get('username')
		email = request.form.get('email')
		password = request.form.get('password')
		confirm_password = request.form.get('confirm_password')
		
		# Validation
		if not username or not email or not password:
			flash('All fields are required.', 'error')
			return render_template('register.html')
		
		if password != confirm_password:
			flash('Passwords do not match.', 'error')
			return render_template('register.html')
		
		if len(password) < 6:
			flash('Password must be at least 6 characters long.', 'error')
			return render_template('register.html')
		
		# Check if username or email already exists
		if database.get_user_by_username(username):
			flash('Username already exists.', 'error')
			return render_template('register.html')
		
		if database.get_user_by_email(email):
			flash('Email already registered.', 'error')
			return render_template('register.html')
		
		# Create new user
		password_hash = generate_password_hash(password)
		user_id = database.create_user(username, password_hash, email)
		
		if user_id:
			flash('Registration successful! Please log in.', 'info')
			return redirect(url_for('login'))
		else:
			flash('An error occurred during registration. Please try again.', 'error')
	
	return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
	logout_user()
	flash('You have been logged out.', 'info')
	return redirect(url_for('login'))

@app.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
	if request.method == 'POST':
		current_password = request.form.get('current_password')
		new_password = request.form.get('new_password')
		confirm_password = request.form.get('confirm_password')
		
		# Validation
		if not current_password or not new_password or not confirm_password:
			flash('All fields are required.', 'error')
			return render_template('change_password.html')
		
		# Verify current password
		user_data = database.get_user_by_id(current_user.id)
		if not check_password_hash(user_data['password_hash'], current_password):
			flash('Current password is incorrect.', 'error')
			return render_template('change_password.html')
		
		# Check new passwords match
		if new_password != confirm_password:
			flash('New passwords do not match.', 'error')
			return render_template('change_password.html')
		
		# Check password length
		if len(new_password) < 6:
			flash('Password must be at least 6 characters long.', 'error')
			return render_template('change_password.html')
		
		# Check password complexity
		if not any(c.isupper() for c in new_password):
			flash('Password must contain at least one uppercase letter.', 'error')
			return render_template('change_password.html')
		if not any(c.islower() for c in new_password):
			flash('Password must contain at least one lowercase letter.', 'error')
			return render_template('change_password.html')
		if not any(c.isdigit() for c in new_password):
			flash('Password must contain at least one number.', 'error')
			return render_template('change_password.html')
		
		# Check password history (prevent reuse of last 5 passwords)
		password_hash = generate_password_hash(new_password)
		if database.check_password_history(current_user.id, new_password, history_count=5):
			flash('Cannot reuse a recent password. Please choose a different password.', 'error')
			return render_template('change_password.html')
		
		# Update password
		database.update_user_password(current_user.id, password_hash)
		database.add_password_history(current_user.id, password_hash)
		database.log_audit(
			user_id=current_user.id,
			username=current_user.username,
			action='password_change',
			ip_address=request.remote_addr,
			user_agent=request.headers.get('User-Agent'),
			success=True
		)
		
		flash('Password changed successfully!', 'info')
		return redirect(url_for('index'))
	
	return render_template('change_password.html')

@app.route('/admin/users/reset-password/<int:user_id>', methods=['POST'])
@login_required
def reset_user_password(user_id):
	# Only BDFL and Administrator can reset passwords
	if not current_user.is_admin_or_bdfl():
		flash('Access denied. Only administrators can reset passwords.', 'error')
		return redirect(url_for('index'))
	
	# Get the target user to check their role
	target_user = database.get_user_by_id(user_id)
	if target_user and target_user['role'] == 'BDFL':
		# Only BDFL can reset their own password or another BDFL's password
		if not current_user.is_bdfl():
			flash('Access denied. Cannot reset BDFL user password.', 'error')
			return redirect(url_for('admin_users'))
		# If current user is BDFL, they can only reset their own BDFL password
		if current_user.is_bdfl() and target_user['id'] != current_user.id:
			flash('Access denied. Cannot reset another BDFL user password.', 'error')
			return redirect(url_for('admin_users'))
	
	# Reset password to "Changem3" and set must_change_password flag
	password_hash = generate_password_hash('Changem3')
	database.update_user_password(user_id, password_hash)
	database.add_password_history(user_id, password_hash)
	
	# Set must_change_password flag
	import sqlite3
	conn = sqlite3.connect(database.DB_NAME)
	conn.execute('UPDATE users SET must_change_password = 1 WHERE id = ?', (user_id,))
	conn.commit()
	conn.close()
	
	user_data = database.get_user_by_id(user_id)
	if user_data:
		database.log_audit(
			user_id=current_user.id,
			username=current_user.username,
			action='password_reset',
			target_user=user_data['username'],
			ip_address=request.remote_addr,
			user_agent=request.headers.get('User-Agent'),
			success=True
		)
		flash(f'Password reset for user "{user_data["username"]}". New password: Changem3', 'info')
	else:
		flash('Password reset successfully.', 'info')
	
	return redirect(url_for('admin_users'))

@app.route('/admin/users/toggle-status/<int:user_id>', methods=['POST'])
@login_required
def toggle_user_status(user_id):
	# Only BDFL and Administrator can toggle user status
	if not current_user.is_admin_or_bdfl():
		flash('Access denied. Only administrators can enable/disable users.', 'error')
		return redirect(url_for('index'))
	
	user_data = database.get_user_by_id(user_id)
	if not user_data:
		flash('User not found.', 'error')
		return redirect(url_for('admin_users'))
	
	# Cannot disable BDFL users
	try:
		user_role = user_data['role']
	except (KeyError, TypeError):
		user_role = None
	
	if user_role == 'BDFL':
		flash('Cannot disable BDFL users.', 'error')
		return redirect(url_for('admin_users'))
	
	# Toggle is_active status
	try:
		current_status = user_data['is_active']
	except (KeyError, TypeError):
		current_status = 1
	
	new_status = 0 if current_status else 1
	
	import sqlite3
	conn = sqlite3.connect(database.DB_NAME)
	conn.execute('UPDATE users SET is_active = ? WHERE id = ?', (new_status, user_id))
	conn.commit()
	conn.close()
	
	status_text = 'enabled' if new_status else 'disabled'
	database.log_audit(
		user_id=current_user.id,
		username=current_user.username,
		action='user_status_change',
		target_user=user_data['username'],
		ip_address=request.remote_addr,
		user_agent=request.headers.get('User-Agent'),
		success=True,
		details=status_text
	)
	flash(f'User "{user_data["username"]}" has been {status_text}.', 'info')
	
	return redirect(url_for('admin_users'))

@app.route('/admin/users/get/<int:user_id>', methods=['GET'])
@login_required
def get_user(user_id):
	# Only BDFL and Administrator can access this endpoint
	if not current_user.is_admin_or_bdfl():
		return {'error': 'Access denied'}, 403
	
	# Administrator cannot view BDFL user details
	user_data = database.get_user_by_id(user_id)
	if user_data and user_data['role'] == 'BDFL' and not current_user.is_bdfl():
		return {'error': 'Access denied'}, 403
	
	user_data = database.get_user_by_id(user_id)
	if user_data:
		return {
			'id': user_data['id'],
			'username': user_data['username'],
			'name': user_data['name'],
			'email': user_data['email'],
			'role': user_data['role']
		}
	return {'error': 'User not found'}, 404

@app.route('/admin/users/edit', methods=['POST'])
@login_required
def edit_user():
	# Only BDFL and Administrator can edit users
	if not current_user.is_admin_or_bdfl():
		flash('Access denied. Only administrators can edit users.', 'error')
		return redirect(url_for('index'))
	
	user_id = request.form.get('user_id')
	
	# Administrator cannot edit BDFL users
	target_user = database.get_user_by_id(int(user_id)) if user_id else None
	if target_user and target_user['role'] == 'BDFL' and not current_user.is_bdfl():
		flash('Access denied. Cannot edit BDFL user.', 'error')
		return redirect(url_for('admin_users'))
	username = request.form.get('username')
	name = request.form.get('name')
	email = request.form.get('email')
	role = request.form.get('role')  # Only BDFL can change roles
	
	# Validation
	if not user_id or not username or not email:
		flash('Username and email are required.', 'error')
		return redirect(url_for('admin_users'))
	
	# Check if username already exists for a different user
	existing_user = database.get_user_by_username(username)
	if existing_user and existing_user['id'] != int(user_id):
		flash('Username already exists.', 'error')
		return redirect(url_for('admin_users'))
	
	# Check if email already exists for a different user
	existing_user = database.get_user_by_email(email)
	if existing_user and existing_user['id'] != int(user_id):
		flash('Email already registered.', 'error')
		return redirect(url_for('admin_users'))
	
	# Update user
	import sqlite3
	conn = sqlite3.connect(database.DB_NAME)
	
	# Only BDFL can update roles
	if role and current_user.is_bdfl():
		conn.execute('UPDATE users SET username = ?, name = ?, email = ?, role = ? WHERE id = ?', 
					 (username, name, email, role, user_id))
		database.log_audit(
			user_id=current_user.id,
			username=current_user.username,
			action='user_edit',
			target_user=username,
			ip_address=request.remote_addr,
			user_agent=request.headers.get('User-Agent'),
			success=True,
			details=f'Updated role to {role}'
		)
	else:
		conn.execute('UPDATE users SET username = ?, name = ?, email = ? WHERE id = ?', 
					 (username, name, email, user_id))
		database.log_audit(
			user_id=current_user.id,
			username=current_user.username,
			action='user_edit',
			target_user=username,
			ip_address=request.remote_addr,
			user_agent=request.headers.get('User-Agent'),
			success=True
		)
	conn.commit()
	conn.close()
	
	flash(f'User "{username}" updated successfully!', 'info')
	return redirect(url_for('admin_users'))

@app.route('/admin/users', methods=['GET', 'POST'])
@login_required
def admin_users():
	# Only BDFL and Administrator can access this page
	if not current_user.is_admin_or_bdfl():
		flash('Access denied. Only administrators can access the admin panel.', 'error')
		return redirect(url_for('index'))
	
	if request.method == 'POST':
		username = request.form.get('username')
		name = request.form.get('name')
		email = request.form.get('email')
		password = request.form.get('password')
		role = request.form.get('role', 'User')  # Default to User if not specified
		
		# Only BDFL can assign Administrator role
		if role == 'Administrator' and not current_user.is_bdfl():
			role = 'User'
		
		# Validation
		if not username or not email or not password:
			flash('Username, email, and password are required.', 'error')
		elif len(password) < 6:
			flash('Password must be at least 6 characters long.', 'error')
		elif not any(c.isupper() for c in password):
			flash('Password must contain at least one uppercase letter.', 'error')
		elif not any(c.islower() for c in password):
			flash('Password must contain at least one lowercase letter.', 'error')
		elif not any(c.isdigit() for c in password):
			flash('Password must contain at least one number.', 'error')
		elif database.get_user_by_username(username):
			flash('Username already exists.', 'error')
		elif database.get_user_by_email(email):
			flash('Email already registered.', 'error')
		else:
			# Create new user
			password_hash = generate_password_hash(password)
			user_id = database.create_user(username, password_hash, email, name, role)
			
			if user_id:
				database.add_password_history(user_id, password_hash)
				database.log_audit(
					user_id=current_user.id,
					username=current_user.username,
					action='user_create',
					target_user=username,
					ip_address=request.remote_addr,
					user_agent=request.headers.get('User-Agent'),
					success=True,
					details=f'Created with role: {role}'
				)
				flash(f'User "{username}" created successfully!', 'info')
			else:
				flash('An error occurred during user creation.', 'error')
	
	# Get all users
	all_users = database.get_all_users()
	member_stats = get_member_stats()
	return render_template('admin_users.html', users=all_users, active_page='admin_users', member_stats=member_stats)

# Before request handler to check for password change requirement
@app.before_request
def check_password_change_required():
	# Skip check for static files, login, logout, and change_password routes
	if request.endpoint in ['static', 'login', 'logout', 'change_password', 'register']:
		return
	
	# Check if user is authenticated and needs to change password
	if current_user.is_authenticated and hasattr(current_user, 'must_change_password') and current_user.must_change_password:
		if request.endpoint != 'change_password':
			return redirect(url_for('change_password'))

# Protected routes
@app.route('/add_work_hours/<int:member_id>', methods=['POST'])
@login_required
def add_work_hours(member_id):
	date = request.form.get('date')
	hours = request.form.get('hours')
	description = request.form.get('description', '')
	database.add_work_hours(member_id, date, hours, description)
	return redirect(url_for('member_details', member_id=member_id))

@app.route('/dues_report')
@login_required
def dues_report():
	year = request.args.get('year')
	years = database.get_dues_years()
	if not year:
		# Default to current year if available, else first year in list
		now = datetime.datetime.now()
		current_year = str(now.year)
		if current_year in years:
			year = current_year
		elif years:
			year = years[0]
		else:
			year = None
	dues = database.get_all_dues_by_year(year)
	now = datetime.datetime.now()
	member_stats = get_member_stats()
	return render_template('dues_report.html', dues=dues, years=years, selected_year=year, now=now, active_page='dues_report', member_stats=member_stats)

@app.route('/dues_email_list')
@login_required
def dues_email_list():
	year = request.args.get('year')
	if not year:
		# Default to current year
		now = datetime.datetime.now()
		year = str(now.year)
	
	# Get all dues for the selected year
	dues = database.get_all_dues_by_year(year)
	
	# Get unique member IDs from dues
	member_ids = list(set([due['member_id'] for due in dues]))
	
	# Get member details for those who paid
	all_members = database.get_all_members()
	paid_members = [m for m in all_members if m['id'] in member_ids]
	
	# Collect all emails (primary and secondary)
	emails = []
	for member in paid_members:
		if member['email']:
			emails.append(member['email'])
		if member['email2']:
			emails.append(member['email2'])
	
	# Remove duplicates and sort
	emails = sorted(list(set(emails)))
	
	member_stats = get_member_stats()
	return render_template('email_list.html', emails=emails, member_type=f'Paid Dues {year}', count=len(emails), member_stats=member_stats)

@app.route('/dues_unpaid_email_list')
@login_required
def dues_unpaid_email_list():
	year = request.args.get('year')
	if not year:
		# Default to current year
		now = datetime.datetime.now()
		year = str(now.year)
	
	# Get all dues for the selected year
	dues = database.get_all_dues_by_year(year)
	
	# Get unique member IDs who paid
	paid_member_ids = list(set([due['member_id'] for due in dues]))
	
	# Get all members
	all_members = database.get_all_members()
	
	# Filter for Probationary, Associate, and Active members who have NOT paid
	unpaid_members = [m for m in all_members 
					  if m['membership_type'] in ['Probationary', 'Associate', 'Active'] 
					  and m['id'] not in paid_member_ids]
	
	# Collect all emails (primary and secondary)
	emails = []
	for member in unpaid_members:
		if member['email']:
			emails.append(member['email'])
		if member['email2']:
			emails.append(member['email2'])
	
	# Remove duplicates and sort
	emails = sorted(list(set(emails)))
	
	member_stats = get_member_stats()
	return render_template('email_list.html', emails=emails, member_type=f'Unpaid Dues {year}', count=len(emails), member_stats=member_stats)

def add_work_hours(member_id):
	date = request.form['date']
	activity = request.form['activity']
	hours = request.form['hours']
	notes = request.form['notes']
	database.add_work_hours(member_id, date, activity, hours, notes)
	return ('', 204)

# Work Hours Report route
@app.route('/work_hours_report')
@login_required
def work_hours_report():
	year = request.args.get('year')
	# Get all work hours for all members for the selected year
	if year:
		start_date = f"{year}-01-01"
		end_date = f"{year}-12-31"
	else:
		now = datetime.datetime.now()
		year = now.year
		start_date = f"{year}-01-01"
		end_date = f"{year}-12-31"
	work_hours = database.get_work_hours_report(start_date=start_date, end_date=end_date)
	years = database.get_dues_years()  # reuse dues years for dropdown
	now = datetime.datetime.now()
	member_stats = get_member_stats()
	return render_template('work_hours_report.html', work_hours=work_hours, years=years, selected_year=year, now=now, active_page='work_hours_report', member_stats=member_stats)

@app.route('/add_meeting_attendance/<int:member_id>', methods=['POST'])
@login_required
def add_meeting_attendance(member_id):
    date = request.form['date']
    status = request.form['status']
    database.add_meeting_attendance(member_id, date, status)
    return ('', 204)

@app.route('/', methods=['GET'])
@login_required
def index():
	search = request.args.get('search', '').strip()
	member_type = request.args.get('member_type', 'All')
	all_members = database.get_all_members()
	# Filter by member type
	if member_type and member_type != 'All':
		members = [m for m in all_members if m['membership_type'] == member_type]
	else:
		members = all_members
	# Filter by search (all columns)
	if search:
		search_lower = search.lower()
		def member_matches(m):
			return any(search_lower in str(m[col]).lower() if m[col] is not None else False for col in m.keys())
		members = [m for m in members if member_matches(m)]
	
	# Calculate member counts for each type
	member_types_list = ["All", "Probationary", "Associate", "Active", "Life", "Honorary", "Prospective", "Wait List", "Former"]
	member_counts = {}
	for mt in member_types_list:
		if mt == "All":
			member_counts[mt] = len(all_members)
		else:
			member_counts[mt] = len([m for m in all_members if m['membership_type'] == mt])
	
	member_stats = get_member_stats()
	return render_template('index.html', members=members, search=search, member_type=member_type, member_types=member_types_list, member_counts=member_counts, active_page='home', member_stats=member_stats)

@app.route('/member/<int:member_id>')
@login_required
def member_details(member_id):
	member = database.get_member_by_id(member_id)
	if not member:
		return "Member not found", 404
	member = dict(member) if member else None
	dues = database.get_dues_by_member(member_id)
	work_hours = database.get_work_hours_by_member(member_id)
	total_work_hours = sum(wh['hours'] for wh in work_hours)
	attendance = database.get_meeting_attendance(member_id)
	position = database.get_member_position(member_id)
	committees = database.get_member_committees(member_id)
	total_meetings = sum(1 for att in attendance if att['status'] in ['Attended', 'Exempt'])
	exclude_keys = {'member id', 'committee id', 'member_id', 'committee_id', 'notes'}
	# Get master list of all possible committee columns from the committees table
	import sqlite3
	conn = sqlite3.connect(database.DB_NAME)
	c = conn.cursor()
	c.execute("PRAGMA table_info(committees)")
	all_committee_columns = [row[1] for row in c.fetchall() if row[1].lower().replace('_', ' ') not in exclude_keys and row[1] != 'member_id']
	conn.close()
	committee_names = all_committee_columns
	# Ensure committees dict has all keys, default to 0 if missing
	if committees:
		for cname in committee_names:
			if cname not in committees:
				committees[cname] = 0
	else:
		committees = {cname: 0 for cname in committee_names}
	committee_display_names = {k: ' '.join(word.capitalize() for word in k.replace('_', ' ').split()) for k in committee_names}
	# Map raw activity names to display names
	activity_display_names = {
		'general_maintenance': 'General Maintenance',
		'event_setup': 'Event Setup',
		'event_cleanup': 'Event Cleanup',
		'fundraising': 'Fundraising',
		'committee_work': 'Committee Work',
		'building_and_grounds': 'Building/Grounds',
		'gun_bingo_social_events': 'Gun Bingo/Social Events',
		'executive_committee': 'Executive',
		'other': 'Other'
	}
	import datetime
	current_year = datetime.datetime.now().year
	dues_years = list(range(current_year + 1, current_year - 10, -1))
	return render_template(
		'member_details.html',
		member=member,
		dues=dues,
		dues_years=dues_years,
		work_hours=work_hours,
		total_work_hours=total_work_hours,
		attendance=attendance,
		meetings=attendance,
		position=position,
		committees=committees,
		committee_names=committee_names,
		committee_display_names=committee_display_names,
		total_meetings=total_meetings,
		work_activity_display_names=activity_display_names,
		current_year=current_year
	)

# Add /reports route for the Reports page
@app.route('/reports')
@login_required
def reports():
	return render_template('reports.html', active_page='reports')

# Member Report route
@app.route('/member_report/<int:member_id>')
@login_required
def member_report(member_id):
	member = database.get_member_by_id(member_id)
	if not member:
		return "Member not found", 404
	dues = database.get_dues_by_member(member_id)
	work_hours = database.get_work_hours_by_member(member_id)
	attendance = database.get_meeting_attendance(member_id)
	position = database.get_member_position(member_id)
	committees = database.get_member_committees(member_id)
	import datetime
	now = datetime.datetime.now()
	exclude_keys = {'member id', 'committee id', 'member_id', 'committee_id', 'notes'}
	committee_names = [k for k in committees.keys() if k.lower().replace('_', ' ') not in exclude_keys] if committees else []
	committee_display_names = {k: ' '.join(word.capitalize() for word in k.replace('_', ' ').split()) for k in committee_names}
	activity_display_names = {
		'general_maintenance': 'General Maintenance',
		'event_setup': 'Event Setup',
		'event_cleanup': 'Event Cleanup',
		'fundraising': 'Fundraising',
		'committee_work': 'Committee Work',
		'building_and_grounds': 'Building/Grounds',
		'gun_bingo_social_events': 'Gun Bingo/Social Events',
		'executive_committee': 'Executive',
		'other': 'Other'
	}
	return render_template(
		'member_report.html',
		member=member,
		dues=dues,
		work_hours=work_hours,
		attendance=attendance,
		position=position,
		committees=committees,
		committee_names=committee_names,
		committee_display_names=committee_display_names,
		work_activity_display_names=activity_display_names,
		now=now
	)

# Soft delete member (move to recycle bin)
@app.route('/delete_member/<int:member_id>', methods=['POST'])
@login_required
def delete_member(member_id):
	database.soft_delete_member_by_id(member_id)
	return redirect(url_for('index'))

# Recycle bin page
@app.route('/recycle_bin')
@login_required
def recycle_bin():
	deleted_members = database.get_deleted_members()
	member_stats = get_member_stats()
	return render_template('recycle_bin.html', deleted_members=deleted_members, active_page='recycle_bin', member_stats=member_stats)

# Restore ALL members from recycle bin
@app.route('/recycle_bin/restore_all', methods=['POST'])
@login_required
def recycle_bin_restore_all():
	deleted_members = database.get_deleted_members()
	for m in deleted_members:
		try:
			database.restore_member_by_id(m['id'])
		except Exception:
			# Continue restoring others even if one fails
			continue
	return redirect(url_for('recycle_bin'))

# Permanently DELETE ALL members in recycle bin
@app.route('/recycle_bin/delete_all', methods=['POST'])
@login_required
def recycle_bin_delete_all():
	deleted_members = database.get_deleted_members()
	for m in deleted_members:
		try:
			database.delete_member_permanently(m['id'])
		except Exception:
			continue
	return redirect(url_for('recycle_bin'))

# Restore member from recycle bin
@app.route('/restore_member/<int:member_id>', methods=['POST'])
@login_required
def restore_member(member_id):
	database.restore_member_by_id(member_id)
	return redirect(url_for('recycle_bin'))

# Edit Member route
@app.route('/edit_member/<int:member_id>', methods=['GET', 'POST'])
@login_required
def edit_member(member_id):
	member = database.get_member_by_id(member_id)
	if not member:
		return "Member not found", 404
	if request.method == 'POST':
		data = (
			request.form['badge_number'],
			request.form['membership_type'],
			request.form['first_name'],
			request.form.get('middle_name', ''),
			request.form['last_name'],
			request.form.get('suffix', ''),
			request.form.get('nickname', ''),
			request.form['dob'],
			request.form['email'],
			request.form.get('email2', ''),
			request.form['phone'],
			request.form.get('phone2', ''),
			request.form['address'],
			request.form['city'],
			request.form['state'],
			request.form['zip'],
			request.form['join_date'],
			request.form['sponsor'],
			request.form['card_internal'],
			request.form['card_external'],
		)
		database.update_member(member_id, data)
		return redirect(url_for('index'))
	return render_template('edit_member.html', member=member)

# Add Member route
@app.route('/add_member', methods=['GET', 'POST'])
@login_required
def add_member():
	if request.method == 'POST':
		data = (
			request.form['badge_number'],
			request.form['membership_type'],
			request.form['first_name'],
			request.form.get('middle_name', ''),
			request.form['last_name'],
			request.form.get('suffix', ''),
			request.form.get('nickname', ''),
			request.form['dob'],
			request.form['email'],
			request.form.get('email2', ''),
			request.form['phone'],
			request.form.get('phone2', ''),
			request.form['address'],
			request.form['city'],
			request.form['state'],
			request.form['zip'],
			request.form['join_date'],
			request.form['sponsor'],
			request.form['card_internal'],
			request.form['card_external'],
		)
		database.add_member(data)
		return redirect(url_for('index'))
	return render_template('add_member.html')

# Edit Section route
@app.route('/edit_section/<int:member_id>', methods=['GET', 'POST'])
@login_required
def edit_section(member_id):
	section = request.args.get('section')
	member = database.get_member_by_id(member_id)
	if not member:
		return "Member not found", 404
	if request.method == 'POST':
		try:
			# Update only the requested section
			if section == 'personal':
				database.update_member_section(member_id, {
					'first_name': request.form['first_name'],
					'middle_name': request.form['middle_name'],
					'last_name': request.form['last_name'],
					'suffix': request.form['suffix'],
					'nickname': request.form['nickname'],
					'dob': request.form['dob'],
				})
			elif section == 'membership':
				database.update_member_section(member_id, {
					'badge_number': request.form['badge_number'],
					'membership_type': request.form['membership_type'],
					'join_date': request.form['join_date'],
					'sponsor': request.form['sponsor'],
					'card_internal': request.form['card_internal'],
					'card_external': request.form['card_external'],
				})
				# Update position in roles table
				database.update_member_position(
					member_id,
					request.form['position'],
					request.form.get('term_start', None),
					request.form.get('term_end', None)
				)
			elif section == 'contact':
				database.update_member_section(member_id, {
					'email': request.form['email'],
					'email2': request.form['email2'],
					'phone': request.form['phone'],
					'phone2': request.form['phone2'],
				})
			elif section == 'address':
				database.update_member_section(member_id, {
					'address': request.form['address'],
					'city': request.form['city'],
					'state': request.form['state'],
					'zip': request.form['zip'],
				})
			elif section == 'dues':
				# Validate required fields
				payment_date = request.form.get('payment_date')
				amount = request.form.get('amount')
				year = request.form.get('year')
				
				if not payment_date or not amount or not year:
					raise ValueError(f"Missing required fields: payment_date={payment_date}, amount={amount}, year={year}")
				
				database.add_due(
					member_id,
					payment_date,
					amount,
					year,
					request.form.get('method', ''),
					request.form.get('notes', '')
				)
			elif section == 'committees':
				import logging
				logging.basicConfig(level=logging.DEBUG)
				# Get master list of all possible committee columns from the committees table
				import sqlite3
				conn = sqlite3.connect(database.DB_NAME)
				c = conn.cursor()
				c.execute("PRAGMA table_info(committees)")
				committee_names = [row[1] for row in c.fetchall() if row[1] not in ('member_id', 'committee_id', 'notes')]
				conn.close()
				updates = {}
				chair_list = []
				for cname in committee_names:
					form_key = f'committee_{cname}'
					value = request.form.get(form_key)
					updates[cname] = 1 if value == '1' else 0
					logging.debug(f"Committee: {cname}, Form Key: {form_key}, Value: {value}, Update: {updates[cname]}")
					# Check if chair checkbox is selected
					chair_key = f'chair_{cname}'
					chair_value = request.form.get(chair_key)
					if chair_value == '1':
						chair_list.append(f"{cname} Chair")
						logging.debug(f"Chair selected for: {cname}")
				# Build notes string with all chair designations
				updates['notes'] = ', '.join(chair_list) if chair_list else ''
				logging.debug(f"Updates dict: {updates}")
				logging.debug(f"Notes field: {updates['notes']}")
				database.update_member_committees(member_id, updates)
				logging.debug(f"Successfully updated committees for member {member_id}")
			return ('', 204)  # AJAX expects empty response
		except Exception as e:
			print(f"Error updating section {section} for member {member_id}: {e}")
			import traceback
			traceback.print_exc()
			return jsonify({'error': str(e)}), 400
	# For GET, just show a message (should not be used with popup)
	return f"Edit {section} for member {member_id}"  # Replace with render_template as needed

@app.route('/get_due/<int:due_id>')
@login_required
def get_due(due_id):
	due = database.get_due_by_id(due_id)
	if not due:
		return {"error": "Due not found"}, 404
	return {
		"id": due["id"],
		"payment_date": due["payment_date"],
		"amount": due["amount"],
		"year": due["year"],
		"method": due["method"] if "method" in due.keys() else "",
		"notes": due["notes"] if "notes" in due.keys() else ""
	}
@app.route('/edit_due/<int:due_id>', methods=['POST'])
@login_required
def edit_due(due_id):
	payment_date = request.form['payment_date']
	amount = request.form['amount']
	year = request.form['year']
	method = request.form.get('method', '')
	notes = request.form.get('notes', '')
	database.update_due(due_id, payment_date, amount, year, method, notes)
	return ('', 204)

@app.route('/delete_due/<int:due_id>', methods=['POST'])
@login_required
def delete_due(due_id):
    database.delete_due(due_id)
    return ('', 204)

@app.route('/delete_member_permanently/<int:member_id>', methods=['POST'])
@login_required
def delete_member_permanently(member_id):
    database.delete_member_permanently(member_id)
    return redirect(url_for('recycle_bin'))

@app.route('/get_work_hours/<int:wh_id>')
@login_required
def get_work_hours(wh_id):
    wh = database.get_work_hours_by_id(wh_id)
    if not wh:
        return {"error": "Not found"}, 404
    return {
        "id": wh["id"],
        "date": wh["date"],
        "activity": wh["activity"],
        "hours": wh["hours"],
        "notes": wh["notes"]
    }

@app.route('/edit_work_hours/<int:wh_id>', methods=['POST'])
@login_required
def edit_work_hours(wh_id):
    date = request.form['date']
    activity = request.form['activity']
    hours = request.form['hours']
    notes = request.form['notes']
    database.update_work_hours(wh_id, date, activity, hours, notes)
    return ('', 204)

@app.route('/delete_work_hours/<int:wh_id>', methods=['POST'])
@login_required
def delete_work_hours(wh_id):
    database.delete_work_hours(wh_id)
    return ('', 204)

@app.route('/get_meeting_attendance/<int:att_id>')
@login_required
def get_meeting_attendance(att_id):
    att = database.get_meeting_attendance_by_id(att_id)
    if not att:
        return {"error": "Not found"}, 404
    return {
        "id": att["id"],
        "meeting_date": att["meeting_date"],
        "status": att["status"]
    }

@app.route('/edit_meeting_attendance/<int:att_id>', methods=['POST'])
@login_required
def edit_meeting_attendance(att_id):
    date = request.form['date']
    status = request.form['status']
    database.update_meeting_attendance(att_id, date, status)
    return ('', 204)

@app.route('/delete_meeting_attendance/<int:att_id>', methods=['POST'])
@login_required
def delete_meeting_attendance(att_id):
    database.delete_meeting_attendance(att_id)
    return ('', 204)

@app.route('/meeting_attendance_report', endpoint='meeting_attendance_report')
@login_required
def meeting_attendance_report():
	year = request.args.get('year')
	month = request.args.get('month') or 'all'
	years = database.get_meeting_years()
	months = [
		{'value': 'all', 'name': 'All Months'},
		{'value': '01', 'name': 'January'},
		{'value': '02', 'name': 'February'},
		{'value': '03', 'name': 'March'},
		{'value': '04', 'name': 'April'},
		{'value': '05', 'name': 'May'},
		{'value': '06', 'name': 'June'},
		{'value': '07', 'name': 'July'},
		{'value': '08', 'name': 'August'},
		{'value': '09', 'name': 'September'},
		{'value': '10', 'name': 'October'},
		{'value': '11', 'name': 'November'},
		{'value': '12', 'name': 'December'}
	]
	attendance = database.get_meeting_attendance_report(year=year, month=month)
	now = datetime.datetime.now()
	member_stats = get_member_stats()
	return render_template('meeting_attendance_report.html', attendance=attendance, years=years, selected_year=year, months=months, selected_month=month, now=now, active_page='meeting_attendance_report', member_stats=member_stats)

@app.route('/committees')
@login_required
def committees():
	import sqlite3
	conn = sqlite3.connect(database.DB_NAME)
	c = conn.cursor()
	c.execute("PRAGMA table_info(committees)")
	exclude_keys = {'member id', 'committee id', 'member_id', 'committee_id', 'notes'}
	committee_names = [row[1] for row in c.fetchall() if row[1].lower().replace('_', ' ') not in exclude_keys and row[1] != 'member_id']
	committee_display_names = {k: ' '.join(word.capitalize() for word in k.replace('_', ' ').split()) for k in committee_names}
	# Get all members and their committee memberships
	members = database.get_all_members()
	committee_members = {cname: [] for cname in committee_names}
	for member in members:
		member_committees = database.get_member_committees(member['id'])
		position = database.get_member_position(member['id'])
		for cname in committee_names:
			if member_committees.get(cname, 0) == 1:
				member_copy = dict(member)
				# Check if member is chair of this committee
				notes = member_committees.get('notes', '')
				is_chair = notes and (cname + ' chair') in notes.lower()
				member_copy['is_chair'] = is_chair
				
				if cname == 'executive_committee':
					member_copy['role'] = position['position'] if position and 'position' in position.keys() else ''
					if position and (('term_start' in position.keys() and position['term_start']) or ('term_end' in position.keys() and position['term_end'])):
						term_start = position['term_start'] if 'term_start' in position.keys() and position['term_start'] else ''
						term_end = position['term_end'] if 'term_end' in position.keys() and position['term_end'] else ''
						if term_start and term_end:
							member_copy['term'] = f"{term_start} until {term_end}"
						elif term_start:
							member_copy['term'] = f"{term_start}"
						elif term_end:
							member_copy['term'] = f"until {term_end}"
						else:
							member_copy['term'] = ''
					else:
						member_copy['term'] = ''
				committee_members[cname].append(member_copy)
	conn.close()
	
	# Add special "Committee Chairs" option
	chair_members = []
	for member in members:
		member_committees = database.get_member_committees(member['id'])
		if member_committees and member_committees.get('notes', '') and 'chair' in member_committees.get('notes', '').lower():
			# Parse which committees they chair and format them
			member_copy = dict(member)
			notes = member_committees.get('notes', '')
			# Extract committee names from notes (format: "committee_name Chair, other_committee Chair")
			chair_committees = []
			for part in notes.split(','):
				part = part.strip()
				if 'chair' in part.lower():
					# Remove " Chair" suffix and format the committee name
					committee_name = part.replace(' Chair', '').replace(' chair', '').strip()
					# Format: capitalize each word and replace underscores with spaces
					formatted_name = ' '.join(word.capitalize() for word in committee_name.replace('_', ' ').split())
					chair_committees.append(formatted_name)
			member_copy['chair_of'] = ', '.join(chair_committees)
			chair_members.append(member_copy)
	committee_members['committee_chairs'] = chair_members
	
	import datetime
	now = datetime.datetime.now()
	selected_committee = request.args.get('committee')
	member_stats = get_member_stats()
	return render_template('committees.html', committee_names=committee_names, committee_display_names=committee_display_names, committee_members=committee_members, selected_committee=selected_committee, now=now, active_page='committees', member_stats=member_stats)

@app.route('/committee_email_list')
@login_required
def committee_email_list():
	committee = request.args.get('committee')
	if not committee:
		return redirect(url_for('committees'))
	
	# Get all members
	all_members = database.get_all_members()
	
	# Handle committee chairs specially
	if committee == 'committee_chairs':
		committee_member_list = []
		for member in all_members:
			member_committees = database.get_member_committees(member['id'])
			if member_committees and member_committees.get('notes', '') and 'chair' in member_committees.get('notes', '').lower():
				committee_member_list.append(member)
		committee_display = 'Committee Chairs'
	else:
		# Filter members who are in the selected committee
		committee_member_list = []
		for member in all_members:
			member_committees = database.get_member_committees(member['id'])
			if member_committees and member_committees.get(committee, 0) == 1:
				committee_member_list.append(member)
		# Format committee name for display
		committee_display = ' '.join(word.capitalize() for word in committee.replace('_', ' ').split())
	
	# Collect all emails (primary and secondary)
	emails = []
	for member in committee_member_list:
		if member['email']:
			emails.append(member['email'])
		if member['email2']:
			emails.append(member['email2'])
	
	# Remove duplicates and sort
	emails = sorted(list(set(emails)))
	
	member_stats = get_member_stats()
	return render_template('email_list.html', emails=emails, member_type=f'{committee_display} Committee', count=len(emails), member_stats=member_stats)

@app.route('/email_list')
@login_required
def email_list():
	member_type = request.args.get('member_type', 'All')
	all_members = database.get_all_members()
	
	# Filter by member type
	if member_type and member_type != 'All':
		members = [m for m in all_members if m['membership_type'] == member_type]
	else:
		members = all_members
	
	# Collect all emails (primary and secondary)
	emails = []
	for member in members:
		if member['email']:
			emails.append(member['email'])
		if member['email2']:
			emails.append(member['email2'])
	
	# Remove duplicates and sort
	emails = sorted(list(set(emails)))
	
	member_stats = get_member_stats()
	return render_template('email_list.html', emails=emails, member_type=member_type, count=len(emails), member_stats=member_stats)

# ========== Favicon Route ==========

@app.route('/favicon.ico')
def favicon():
	"""Serve the favicon"""
	from flask import send_from_directory
	return send_from_directory(os.path.join(app.root_path, 'static'),
							   'Club_logo.ico', mimetype='image/vnd.microsoft.icon')

# ========== Kiosk Routes ==========

@app.route('/kiosk')
def kiosk():
	"""Serve the kiosk check-in page (no login required)"""
	return render_template('kiosk.html')

@app.route('/kiosk/submit', methods=['POST'])
@csrf.exempt  # Exempt CSRF for kiosk since it's a public terminal
def kiosk_submit():
	"""Handle kiosk check-in form submission"""
	try:
		# Get form data
		member_number = request.form.get('memberNumber')
		activities = request.form.getlist('activities')
		other_activity = request.form.get('otherActivity', '')
		guest1 = request.form.get('guest1', '')
		guest2 = request.form.get('guest2', '')
		
		# Validate member number
		if not member_number:
			return jsonify({'success': False, 'error': 'Member number is required'}), 400
		
		# Check if member exists in the database
		member = database.get_member_by_badge_number(member_number)
		if not member:
			return jsonify({
				'success': False, 
				'error': f'Member #{member_number} not found. Please check the member number and try again.'
			}), 404
		
		# Check if member already has an active check-in
		existing_checkin = database.get_active_checkin_for_member(member_number)
		if existing_checkin:
			return jsonify({
				'success': False, 
				'error': f'Member #{member_number} is already checked in. Please sign out first before checking in again.'
			}), 400
		
		# Validate activities
		if not activities:
			return jsonify({'success': False, 'error': 'At least one activity must be selected'}), 400
		
		# Insert check-in record
		activities_str = ', '.join(activities)
		check_in_time = datetime.datetime.now(TIMEZONE).strftime('%Y-%m-%d %H:%M:%S')
		
		checkin_id = database.add_checkin(
			member_number=member_number,
			check_in_time=check_in_time,
			activities=activities_str,
			guest1_name=guest1 if guest1 else None,
			tos_accepted=1,
			guest1_tos_accepted=1 if guest1 else 0,
			guest2_name=guest2 if guest2 else None,
			guest2_tos_accepted=1 if guest2 else 0,
			other_activity=other_activity if other_activity else None
		)
		
		return jsonify({
			'success': True,
			'message': 'Check-in recorded successfully',
			'id': checkin_id,
			'member_number': member_number,
			'activities': activities,
			'guests': [g for g in [guest1, guest2] if g]
		})
		
	except Exception as e:
		print(f"Error processing check-in: {e}")
		return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/kiosk/today-checkins', methods=['GET'])
@csrf.exempt  # Exempt CSRF for kiosk
def kiosk_today_checkins():
	"""Get today's check-ins for the kiosk display"""
	try:
		# Get today's date in the configured timezone
		today = datetime.datetime.now(TIMEZONE).strftime('%Y-%m-%d')
		records = database.get_today_checkins_by_date(today)
		checkins = [dict(row) for row in records]
		return jsonify({'success': True, 'checkins': checkins})
	except Exception as e:
		print(f"Error fetching today's check-ins: {e}")
		return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/kiosk/signout/<int:checkin_id>', methods=['POST'])
@csrf.exempt  # Exempt CSRF for kiosk
def kiosk_sign_out(checkin_id):
	"""Sign out a member by updating their check-in record with sign-out time"""
	try:
		sign_out_time = datetime.datetime.now(TIMEZONE).strftime('%Y-%m-%d %H:%M:%S')
		success = database.sign_out_checkin(checkin_id, sign_out_time)
		
		if not success:
			return jsonify({'success': False, 'error': 'Check-in record not found'}), 404
		
		return jsonify({
			'success': True,
			'message': 'Signed out successfully',
			'sign_out_time': sign_out_time
		})
	except Exception as e:
		print(f"Error signing out: {e}")
		return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/kiosk/report')
@login_required
def kiosk_report():
	"""View kiosk check-in reports (requires login)"""
	date_filter = request.args.get('date')
	start_date = request.args.get('start_date')
	end_date = request.args.get('end_date')
	
	if start_date and end_date:
		checkins = database.get_checkins_by_date_range(start_date, end_date)
	elif date_filter:
		checkins = database.get_all_checkins(date=date_filter)
	else:
		# Default to today
		today = datetime.date.today().strftime('%Y-%m-%d')
		checkins = database.get_all_checkins(date=today)
	
	member_stats = get_member_stats()
	return render_template('kiosk_report.html', 
						   checkins=checkins, 
						   member_stats=member_stats,
						   date_filter=date_filter,
						   start_date=start_date,
						   end_date=end_date,
						   active_page='kiosk_report')

if __name__ == "__main__":
    import sys
    import os
    
    local_ip = get_local_ip()
    port = 5000
    
    # Display startup info
    print("\n" + "="*60)
    print("DH Member Database - Server Starting")
    print("="*60)
    print(f"Local access:   http://127.0.0.1:{port}")
    print(f"Network access: http://{local_ip}:{port}")
    print("="*60 + "\n")
    
    # Run the app without console (use pythonw.exe or run in background)
    if '--background' in sys.argv or getattr(sys, 'frozen', False):
        # Running as background service or frozen executable
        import logging
        logging.basicConfig(filename='app.log', level=logging.INFO)
        app.run(debug=False, host='0.0.0.0', port=port, use_reloader=False)
    else:
        app.run(debug=True, host='0.0.0.0', port=port)

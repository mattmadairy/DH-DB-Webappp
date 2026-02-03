
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, make_response
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import json

# Place this after 'app = Flask(__name__)' and all app config

# Context processor to inject applications into all templates
def register_context_processors(app):
	@app.context_processor
	def inject_applications():
		try:
			from flask_login import current_user
			import database
			if current_user.is_authenticated and current_user.is_admin_or_bdfl():
				applications = database.get_all_applications(status='pending')
			else:
				applications = []
		except Exception:
			applications = []
		return dict(applications=applications)

# After all imports and before any route definitions:
app = Flask(__name__)
register_context_processors(app)

from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import generate_password_hash, check_password_hash
import database
import datetime
import socket
import os
import pytz

# Disable template caching in development
app.config['TEMPLATES_AUTO_RELOAD'] = True
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0

# Set timezone to America/New_York
TIMEZONE = pytz.timezone('America/New_York')

# Load configuration
env = os.environ.get('FLASK_ENV', 'development')
from config import config
app.config.from_object(config[env])

# Document descriptions management
DESCRIPTIONS_FILE = os.path.join(app.root_path, 'document_descriptions.json')

def load_document_config():
	"""Load document configuration including descriptions and order"""
	try:
		if os.path.exists(DESCRIPTIONS_FILE):
			with open(DESCRIPTIONS_FILE, 'r') as f:
				return json.load(f)
	except:
		pass
	return {"descriptions": {}, "order": []}

def save_document_config(config):
	"""Save document configuration including descriptions and order"""
	try:
		with open(DESCRIPTIONS_FILE, 'w') as f:
			json.dump(config, f, indent=2)
	except Exception as e:
		print(f"Error saving config: {e}")

def load_document_descriptions():
	"""Load custom document descriptions from JSON file"""
	config = load_document_config()
	return config.get("descriptions", {})

def save_document_descriptions(descriptions):
	"""Save custom document descriptions to JSON file"""
	config = load_document_config()
	config["descriptions"] = descriptions
	save_document_config(config)

def load_document_order():
	"""Load document display order"""
	config = load_document_config()
	return config.get("order", [])

def save_document_order(order):
	"""Save document display order"""
	config = load_document_config()
	config["order"] = order
	save_document_config(config)

def get_document_title(doc_key):
	"""Get display title for a document based on its key"""
	titles = {
		'articles of incorporation': 'Articles of Incorporation',
		'constitution': 'Bylaws',
		'range rules': 'Range Rules',
		'range rules draft': 'Range rules draft',
		'membership handbook': 'Membership Handbook',
		'event calendar': 'Event Calendar',
		'committees': 'Committee Guidelines',
		'dues fees': 'Dues & Fees Information',
		'range safety': 'Range Safety Guidelines'
	}
	return titles.get(doc_key, doc_key.replace('_', ' ').replace('-', ' ').title())

def get_document_icon(doc_key):
	"""Get icon for a document based on its key"""
	icons = {
		'articles of incorporation': '📄',
		'constitution': '📋',
		'range rules': '🎯',
		'range rules draft': '📝',
		'membership handbook': '📖',
		'event calendar': '📅',
		'committees': '👥',
		'dues fees': '💰',
		'range safety': '⚠️'
	}
	return icons.get(doc_key, '📄')

def get_document_description(filename):
	"""Get description for a document, falling back to defaults"""
	doc_key = filename.replace('.pdf', '').lower().replace('_', ' ').replace('-', ' ')
	descriptions = load_document_descriptions()
	
	# Return custom description if it exists
	if doc_key in descriptions:
		return descriptions[doc_key]
	
	# Return default descriptions
	defaults = {
		'constitution': 'The Bylaws of the Dug Hill Rod & Gun Club, including organizational structure, rules, procedures, and governing principles.',
		'articles of incorporation': 'The legal Articles of Incorporation for the Dug Hill Rod & Gun Club, establishing the organization as a legal entity.',
		'membership handbook': 'Complete guide for members including club policies, benefits, responsibilities, and important contact information.',
		'range safety': 'Essential safety guidelines and procedures for all shooting activities at the club ranges.',
		'event calendar': 'Upcoming club events, meetings, shoots, and activities schedule.',
		'dues fees': 'Current membership dues, range fees, and payment information for all club services.',
		'committees': 'Information about club committees, roles, responsibilities, and how to get involved.'
	}
	
	return defaults.get(doc_key, 'Club document available for download.')

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'
login_manager.login_message_category = 'info'

# Initialize CSRF protection
csrf = CSRFProtect(app)

# Initialize rate limiter
if env == 'development':
    # Disable rate limiting in development
    limiter = Limiter(app=app, key_func=get_remote_address)
else:
    # Production limits
    limiter = Limiter(
        app=app,
        key_func=get_remote_address,
        default_limits=["500 per day", "100 per hour"],
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
        return self.role in ('Administrator', 'BDFL')
    
    def is_admin_or_bdfl(self):
        return self.role in ('BDFL', 'Administrator')
    
    def is_user(self):
        return self.role in ('User', 'Administrator', 'BDFL')
    
    def has_access_level(self, required_level):
        """Check if user has at least the required access level (hierarchical)"""
        levels = {'User': 1, 'Administrator': 2, 'BDFL': 3}
        user_level = levels.get(self.role, 0)
        required_level_value = levels.get(required_level, 999)
        return user_level >= required_level_value

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

# Jinja filter to format datetime as mm-dd-yyyy hh:mm AM/PM (12-hour)
def format_datetime_12hr(value):
    if not value:
        return ''
    try:
        dt = datetime.datetime.strptime(value, '%Y-%m-%d %H:%M:%S')
        return dt.strftime('%m-%d-%Y %I:%M %p')
    except Exception:
        return value

app.jinja_env.filters['format_datetime_12hr'] = format_datetime_12hr

# Jinja filter to format name as "Last, First"
def format_name_last_first(value):
    if not value or value == '-':
        return value or '-'
    try:
        # Split the name by spaces
        parts = value.strip().split()
        if len(parts) >= 2:
            # Assume the last part is the last name, everything else is first/middle
            last_name = parts[-1]
            first_middle = ' '.join(parts[:-1])
            return f"{last_name}, {first_middle}"
        else:
            # If only one part, return as is
            return value
    except Exception:
        return value

app.jinja_env.filters['format_name_last_first'] = format_name_last_first

def get_member_stats():
	all_members = database.get_all_members()
	life_count = len([m for m in all_members if m['membership_type'] == 'Life'])
	voting_count = len([m for m in all_members if m['membership_type'] in ['Probationary', 'Associate', 'Active']])
	total_count = len(all_members)
	return {
		'life_members': life_count,
		'voting_members': voting_count,
		'total_members': total_count
	}

def get_pending_application_count():
	"""Get the count of pending membership applications"""
	try:
		applications = database.get_all_applications(status='pending')
		return len(applications)
	except:
		return 0

# Security headers middleware
@app.after_request
def set_security_headers(response):
	"""Add security headers to all responses"""
	response.headers['X-Content-Type-Options'] = 'nosniff'
	response.headers['X-Frame-Options'] = 'DENY'
	response.headers['X-XSS-Protection'] = '1; mode=block'
	response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
	response.headers['Content-Security-Policy'] = "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline' https://js.stripe.com; frame-src https://js.stripe.com; connect-src 'self' https://api.stripe.com"
	return response

# Decorator for admin-only routes
def admin_required(f):
	from functools import wraps
	@wraps(f)
	def decorated_function(*args, **kwargs):
		if not current_user.is_authenticated:
			return redirect(url_for('login'))
		if not current_user.is_admin_or_bdfl():
			flash('Access denied. You do not have permission to view this page.', 'danger')
			return redirect(url_for('member_dashboard'))
		return f(*args, **kwargs)
	return decorated_function

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
@admin_required
def reset_user_password(user_id):
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
@admin_required
def toggle_user_status(user_id):
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

@app.route('/admin/users/delete/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def delete_user(user_id):
	user_data = database.get_user_by_id(user_id)
	if not user_data:
		flash('User not found.', 'error')
		return redirect(url_for('admin_users'))
	
	# Cannot delete BDFL users or self
	try:
		user_role = user_data['role']
	except (KeyError, TypeError):
		user_role = None
	
	if user_role == 'BDFL':
		flash('Cannot delete BDFL users.', 'error')
		return redirect(url_for('admin_users'))
	
	if user_id == current_user.id:
		flash('Cannot delete your own account.', 'error')
		return redirect(url_for('admin_users'))
	
	# Delete the user
	import sqlite3
	conn = sqlite3.connect(database.DB_NAME)
	conn.execute('DELETE FROM users WHERE id = ?', (user_id,))
	conn.commit()
	conn.close()
	
	database.log_audit(
		user_id=current_user.id,
		username=current_user.username,
		action='user_delete',
		target_user=user_data['username'],
		ip_address=request.remote_addr,
		user_agent=request.headers.get('User-Agent'),
		success=True,
		details='User permanently deleted'
	)
	flash(f'User "{user_data["username"]}" has been permanently deleted.', 'info')
	
	return redirect(url_for('admin_users'))

@app.route('/admin/users/get/<int:user_id>', methods=['GET'])
@login_required
@admin_required
def get_user(user_id):
	
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
@admin_required
def edit_user():
	
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
	
	# Update user using database function
	if role and current_user.is_bdfl():
		database.update_user(user_id, username, name, email, role)
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
		database.update_user(user_id, username, name, email)
		database.log_audit(
			user_id=current_user.id,
			username=current_user.username,
			action='user_edit',
			target_user=username,
			ip_address=request.remote_addr,
			user_agent=request.headers.get('User-Agent'),
			success=True
		)
	
	flash(f'User "{username}" updated successfully!', 'info')
	return redirect(url_for('admin_users'))

@app.route('/admin/users', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_users():
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
	all_users = [dict(user) for user in database.get_all_users()]
	
	# Add member_id to each user if they have a member record
	for user in all_users:
		member = database.get_member_by_email(user['email'])
		user['member_id'] = member['id'] if member else None
	
	member_stats = get_member_stats()
	pending_applications = get_pending_application_count()
	
	return render_template('admin_users.html', users=all_users, active_page='admin_users', member_stats=member_stats, pending_applications=pending_applications)

@app.route('/admin/applications', methods=['GET'])
@login_required
@admin_required
def admin_applications():
	# Get pending applications
	applications = database.get_all_applications(status='pending')
	
	member_stats = get_member_stats()
	pending_applications = get_pending_application_count()
	
	return render_template('admin_applications.html', applications=applications, active_page='admin_applications', member_stats=member_stats, pending_applications=pending_applications)

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
@admin_required
def add_work_hours(member_id):
	date = request.form.get('date')
	activity = request.form.get('activity')
	hours = request.form.get('hours')
	notes = request.form.get('notes', '')
	try:
		database.add_work_hours(member_id, date, activity, hours, notes)
		return ('', 204)
	except Exception as e:
		return jsonify({'error': str(e)}), 400

@app.route('/dues_report')
@login_required
@admin_required
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
	pending_applications = get_pending_application_count()
	total_dues_revenue = sum(float(due['amount'] or 0) for due in dues)
	return render_template('dues_report.html', dues=dues, years=years, selected_year=year, now=now, active_page='dues_report', member_stats=member_stats, total_dues_revenue=total_dues_revenue, pending_applications=pending_applications)

@app.route('/dues_email_list')
@login_required
@admin_required
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
@admin_required
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

@app.route('/dues_export_csv')
@login_required
@admin_required
def dues_export_csv():
	year = request.args.get('year')
	if not year:
		now = datetime.datetime.now()
		year = str(now.year)
	
	dues = database.get_all_dues_by_year(year)
	
	# Create CSV content
	import csv
	import io
	
	output = io.StringIO()
	writer = csv.writer(output)
	
	# Write header
	writer.writerow(['Badge Number', 'Last Name', 'First Name', 'Payment Date', 'Amount', 'Year', 'Method', 'Notes'])
	
	# Write data
	for due in dues:
		writer.writerow([
			due['badge_number'],
			due['last_name'],
			due['first_name'],
			due['payment_date'],
			due['amount'],
			due['year'],
			due['method'],
			due['notes'] or ''
		])
	
	# Create response
	output.seek(0)
	response = make_response(output.getvalue())
	response.headers['Content-Type'] = 'text/csv'
	response.headers['Content-Disposition'] = f'attachment; filename=dues_paid_{year}.csv'
	return response

@app.route('/dues_unpaid_export_csv')
@login_required
@admin_required
def dues_unpaid_export_csv():
	year = request.args.get('year')
	if not year:
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
	
	# Sort by badge number
	unpaid_members.sort(key=lambda x: int(x['badge_number']) if x['badge_number'].isdigit() else 0)
	
	# Create CSV content
	import csv
	import io
	
	output = io.StringIO()
	writer = csv.writer(output)
	
	# Write header
	writer.writerow(['Badge Number', 'Last Name', 'First Name', 'Membership Type', 'Email', 'Secondary Email', 'Phone'])
	
	# Write data
	for member in unpaid_members:
		writer.writerow([
			member['badge_number'],
			member['last_name'],
			member['first_name'],
			member['membership_type'],
			member['email'] or '',
			member['email2'] or '',
			member['phone'] or ''
		])
	
	# Create response
	output.seek(0)
	response = make_response(output.getvalue())
	response.headers['Content-Type'] = 'text/csv'
	response.headers['Content-Disposition'] = f'attachment; filename=dues_unpaid_{year}.csv'
	return response

@app.route('/work_hours_export_csv')
@login_required
@admin_required
def work_hours_export_csv():
	year = request.args.get('year')
	if not year:
		now = datetime.datetime.now()
		year = str(now.year)
	
	start_date = f"{year}-01-01"
	end_date = f"{year}-12-31"
	work_hours = database.get_work_hours_report(start_date=start_date, end_date=end_date)
	
	# Create CSV content
	import csv
	import io
	
	output = io.StringIO()
	writer = csv.writer(output)
	
	# Write header
	writer.writerow(['Badge Number', 'Last Name', 'First Name', 'Total Hours'])
	
	# Write data
	for wh in work_hours:
		writer.writerow([
			wh[0],  # badge_number
			wh[2],  # last_name
			wh[1],  # first_name
			wh[3]   # total_hours
		])
	
	# Create response
	output.seek(0)
	response = make_response(output.getvalue())
	response.headers['Content-Type'] = 'text/csv'
	response.headers['Content-Disposition'] = f'attachment; filename=work_hours_{year}.csv'
	return response

@app.route('/meeting_attendance_export_csv')
@login_required
@admin_required
def meeting_attendance_export_csv():
	year = request.args.get('year')
	month = request.args.get('month') or 'all'
	
	attendance = database.get_meeting_attendance_report(year=year, month=month)
	
	# Create CSV content
	import csv
	import io
	
	output = io.StringIO()
	writer = csv.writer(output)
	
	# Write header
	if month == 'all':
		writer.writerow(['Badge Number', 'Last Name', 'First Name', 'Total Meetings Attended'])
	else:
		writer.writerow(['Badge Number', 'Last Name', 'First Name', 'Meeting Date', 'Status'])
	
	# Write data
	for att in attendance:
		if month == 'all':
			writer.writerow([
				att[0],  # badge_number
				att[2],  # last_name
				att[1],  # first_name
				att[3]   # total_meetings
			])
		else:
			writer.writerow([
				att[0],  # badge_number
				att[2],  # last_name
				att[1],  # first_name
				att[3],  # meeting_date
				att[4]   # status
			])
	
	# Create response
	output.seek(0)
	response = make_response(output.getvalue())
	response.headers['Content-Type'] = 'text/csv'
	
	# Create filename based on filters
	if month == 'all':
		filename = f'meeting_attendance_{year}.csv' if year else 'meeting_attendance_all.csv'
	else:
		month_name = ['January', 'February', 'March', 'April', 'May', 'June', 
					 'July', 'August', 'September', 'October', 'November', 'December'][int(month)-1]
		filename = f'meeting_attendance_{year}_{month_name}.csv' if year else f'meeting_attendance_{month_name}.csv'
	
	response.headers['Content-Disposition'] = f'attachment; filename={filename}'
	return response

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
@admin_required
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
	pending_applications = get_pending_application_count()
	return render_template('work_hours_report.html', work_hours=work_hours, years=years, selected_year=year, now=now, active_page='work_hours_report', member_stats=member_stats, pending_applications=pending_applications)

@app.route('/add_meeting_attendance/<int:member_id>', methods=['POST'])
@login_required
@admin_required
def add_meeting_attendance(member_id):
    date = request.form['date']
    status = request.form['status']
    try:
        database.add_meeting_attendance(member_id, date, status)
        return ('', 204)
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/', methods=['GET'])
@login_required
def index():
	# Check if user is admin first
	if current_user.is_admin_or_bdfl():
		# Admin dashboard - show all members
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
		applications = database.get_all_applications(status='pending')
		pending_applications = get_pending_application_count()
		return render_template('index.html', members=members, search=search, member_type=member_type, member_types=member_types_list, member_counts=member_counts, active_page='home', member_stats=member_stats, applications=applications, pending_applications=pending_applications)
	else:
		# Regular user - check if they have a member record
		member = database.get_member_by_email(current_user.email)
		if member:
			# User has a member record - show their member dashboard
			return member_dashboard()
		else:
			# Regular user without member record - show message
			return render_template('member_dashboard.html', member=None, active_page='dashboard')

@app.route('/admin', methods=['GET'])
@login_required
def admin_dashboard():
	if not current_user.is_admin_or_bdfl():
		flash('Access denied. Admin privileges required.', 'error')
		return redirect(url_for('index'))
	
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
	applications = database.get_all_applications(status='pending')
	pending_applications = get_pending_application_count()
	return render_template('index.html', members=members, search=search, member_type=member_type, member_types=member_types_list, member_counts=member_counts, active_page='home', member_stats=member_stats, applications=applications, pending_applications=pending_applications)

@app.route('/member-dashboard')
@login_required
def member_dashboard():
	# Get year parameters for filtering
	selected_work_year = request.args.get('work_year')
	selected_meeting_year = request.args.get('meeting_year')
	
	# For regular users, try to find their member record by email
	member = database.get_member_by_email(current_user.email)
	if not member:
		# If no member found, show a message
		return render_template('member_dashboard.html', member=None, active_page='dashboard')
	
	member = dict(member) if member else None
	dues = database.get_dues_by_member(member['id']) if member else []
	work_hours = database.get_work_hours_by_member_and_year(member['id'], selected_work_year) if member else []
	total_work_hours = sum(wh['hours'] for wh in work_hours) if work_hours else 0
	attendance = database.get_meeting_attendance_by_member_and_year(member['id'], selected_meeting_year) if member else []
	total_meetings = sum(1 for att in attendance if att['status'] in ['Attended', 'Exempt']) if attendance else 0
	
	# Get committee memberships
	committees = []
	if member:
		member_committees = database.get_member_committees_new(member['id'])
		for committee in member_committees:
			committee_dict = dict(committee)
			committees.append({
				'name': committee_dict.get('name', '').replace('_', ' ').title(),
				'role': committee_dict.get('role', '').title()
			})
	
	# Get executive positions from roles table
	executive_position = None
	executive_term = None
	if member:
		member_position = database.get_member_position(member['id'])
		if member_position:
			position = member_position['position']
			if position:
				executive_position = position
				term_start = member_position['term_start']
				term_end = member_position['term_end']
				if term_start and term_end:
					formatted_start = format_mmddyyyy(term_start)
					formatted_end = format_mmddyyyy(term_end)
					executive_term = f"({formatted_start} until {formatted_end})"
	
	# Get recent check-ins (last 30 days)
	checkins = []
	if member and member.get('badge_number'):
		checkins = database.get_member_checkins_last_30_days(member['badge_number'])
	
	# Get work hours and meeting attendance years for dropdowns
	work_hours_years = database.get_work_hours_years() if member else []
	meeting_attendance_years = database.get_meeting_attendance_years() if member else []
	
	return render_template('member_dashboard.html', 
							member=member, 
							dues=dues, 
							work_hours=work_hours, 
							total_work_hours=total_work_hours,
							work_hours_years=work_hours_years,
							selected_work_year=selected_work_year,
							attendance=attendance,
							total_meetings=total_meetings,
							meeting_attendance_years=meeting_attendance_years,
							selected_meeting_year=selected_meeting_year,
							committees=committees,
							executive_position=executive_position,
							executive_term=executive_term,
							checkins=checkins,
							active_page='dashboard',
							is_admin=current_user.is_admin_or_bdfl())



@app.route('/member-documents')
@login_required
def member_documents():
	# For regular users, try to find their member record by email
	member = database.get_member_by_email(current_user.email)
	if not member:
		# If no member found, show a message
		return render_template('member_documents.html', member=None, active_page='documents')
	
	member = dict(member) if member else None
	
	# Get list of PDF files in static directory
	static_dir = app.static_folder
	pdf_files = []
	if os.path.exists(static_dir):
		for filename in os.listdir(static_dir):
			if filename.lower().endswith('.pdf'):
				pdf_files.append(filename)
	
	# Filter out meeting minutes PDFs from regular documents
	all_meeting_minutes = database.get_all_meeting_minutes()
	meeting_minutes_filenames = {minutes['pdf_filename'] for minutes in all_meeting_minutes}
	regular_pdf_files = [f for f in pdf_files if f not in meeting_minutes_filenames]
	
	# Load document order and descriptions
	document_order = load_document_order()
	file_descriptions = load_document_descriptions()
	
	# Create ordered list of documents
	ordered_files = []
	# First add documents that are in the saved order
	for doc_key in document_order:
		for filename in regular_pdf_files:
			file_key = filename.replace('.pdf', '').lower().replace('_', ' ').replace('-', ' ')
			if file_key == doc_key:
				ordered_files.append(filename)
				break
	
	# Create title and icon dictionaries for template
	document_titles = {}
	document_icons = {}
	file_descriptions_dict = {}
	for filename in ordered_files:
		doc_key = filename.replace('.pdf', '').lower().replace('_', ' ').replace('-', ' ')
		document_titles[filename] = get_document_title(doc_key)
		document_icons[filename] = get_document_icon(doc_key)
		file_descriptions_dict[filename] = file_descriptions.get(doc_key, get_document_description(filename))
	
	# Get meeting minutes
	selected_year = request.args.get('year')
	available_years = database.get_available_years()
	
	# Default to current year if no year selected, but only if current year has data
	if not selected_year:
		if '2026' in available_years:
			selected_year = '2026'
		else:
			selected_year = 'all'
	
	if selected_year and selected_year != 'all':
		meeting_minutes = database.get_meeting_minutes_by_year(selected_year)
	else:
		meeting_minutes = database.get_all_meeting_minutes()
	
	return render_template('member_documents.html', 
							member=member, 
							active_page='documents',
							is_admin=current_user.is_admin_or_bdfl(),
							pdf_files=ordered_files,
							file_descriptions=file_descriptions_dict,
							document_titles=document_titles,
							document_icons=document_icons,
							document_order=document_order,
							meeting_minutes=meeting_minutes,
							available_years=available_years,
							selected_year=selected_year,
							pending_applications=get_pending_application_count())


@app.route('/upload_document/<filename>', methods=['POST'])
@login_required
def upload_document(filename):
	# Only allow admin and BDFL users to upload documents
	if not current_user.is_admin_or_bdfl():
		flash('Access denied. Only administrators can upload documents.', 'danger')
		return redirect(url_for('member_documents'))
	
	if 'file' not in request.files:
		flash('No file selected.', 'danger')
		return redirect(url_for('member_documents'))
	
	file = request.files['file']
	if file.filename == '':
		flash('No file selected.', 'danger')
		return redirect(url_for('member_documents'))
	
	# Validate file type
	if not file.filename.lower().endswith('.pdf'):
		flash('Only PDF files are allowed.', 'danger')
		return redirect(url_for('member_documents'))
	
	# Ensure filename ends with .pdf and is safe
	if not filename.endswith('.pdf'):
		filename = filename + '.pdf'
	
	# Basic security check - prevent path traversal
	if '..' in filename or '/' in filename or '\\' in filename:
		flash('Invalid filename.', 'danger')
		return redirect(url_for('member_documents'))
	
	try:
		# Save file to static directory
		file_path = os.path.join(app.static_folder, filename)
		file.save(file_path)
		flash(f'Document "{filename}" uploaded successfully!', 'success')
	except Exception as e:
		flash(f'Error uploading file: {str(e)}', 'danger')
	
	return redirect(url_for('member_documents'))


@app.route('/upload_new_document', methods=['POST'])
@login_required
def upload_new_document():
	# Only allow admin and BDFL users to upload documents
	if not current_user.is_admin_or_bdfl():
		flash('Access denied. Only administrators can upload documents.', 'danger')
		return redirect(url_for('member_documents'))
	
	if 'file' not in request.files:
		flash('No file selected.', 'danger')
		return redirect(url_for('member_documents'))
	
	file = request.files['file']
	title = request.form.get('title', '').strip()
	description = request.form.get('description', '').strip()
	
	if file.filename == '' or not title or not description:
		flash('All fields are required.', 'danger')
		return redirect(url_for('member_documents'))
	
	# Validate file type
	if not file.filename.lower().endswith('.pdf'):
		flash('Only PDF files are allowed.', 'danger')
		return redirect(url_for('member_documents'))
	
	# Generate filename from title (convert to lowercase, replace spaces with underscores, remove special chars)
	filename = ''.join(c for c in title.lower().replace(' ', '_') if c.isalnum() or c == '_')
	if not filename:
		flash('Invalid title. Please use only letters, numbers, and spaces.', 'danger')
		return redirect(url_for('member_documents'))
	
	filename = filename + '.pdf'
	
	# Check if file already exists
	file_path = os.path.join(app.static_folder, filename)
	if os.path.exists(file_path):
		flash(f'Document "{filename}" already exists. Use the replace button to update it.', 'warning')
		return redirect(url_for('member_documents'))
	
	try:
		# Save file to static directory
		file.save(file_path)
		
		# Save the custom description
		doc_key = filename.replace('.pdf', '').lower().replace('_', ' ').replace('-', ' ')
		descriptions = load_document_descriptions()
		descriptions[doc_key] = description
		save_document_descriptions(descriptions)
		
		# Add the new document to the end of the order list
		document_order = load_document_order()
		if doc_key not in document_order:
			document_order.append(doc_key)
			save_document_order(document_order)
		
		flash(f'Document "{title}" uploaded successfully!', 'success')
	except Exception as e:
		flash(f'Error uploading file: {str(e)}', 'danger')
	
	return redirect(url_for('member_documents'))


@app.route('/delete_document/<filename>', methods=['POST'])
@login_required
def delete_document(filename):
	# Only allow admin and BDFL users to delete documents
	if not current_user.is_admin_or_bdfl():
		flash('Access denied. Only administrators can delete documents.', 'danger')
		return redirect(url_for('member_documents'))
	
	# Ensure filename ends with .pdf and is safe
	if not filename.endswith('.pdf'):
		filename = filename + '.pdf'
	
	# Basic security check - prevent path traversal
	if '..' in filename or '/' in filename or '\\' in filename:
		flash('Invalid filename.', 'danger')
		return redirect(url_for('member_documents'))
	
	# Check if this file is associated with meeting minutes
	all_meeting_minutes = database.get_all_meeting_minutes()
	for minutes in all_meeting_minutes:
		if minutes['pdf_filename'] == filename:
			flash('This document is associated with meeting minutes and cannot be deleted from here. Delete the meeting minutes entry instead.', 'warning')
			return redirect(url_for('member_documents'))
	
	file_path = os.path.join(app.static_folder, filename)
	
	# Check if file exists
	if not os.path.exists(file_path):
		flash(f'Document "{filename}" not found.', 'warning')
		return redirect(url_for('member_documents'))
	
	try:
		# Delete the file
		os.remove(file_path)
		
		# Remove from document descriptions and order
		doc_key = filename.replace('.pdf', '').lower().replace('_', ' ').replace('-', ' ')
		descriptions = load_document_descriptions()
		if doc_key in descriptions:
			del descriptions[doc_key]
			save_document_descriptions(descriptions)
		
		document_order = load_document_order()
		if doc_key in document_order:
			document_order.remove(doc_key)
			save_document_order(document_order)
		
		flash(f'Document "{filename}" deleted successfully!', 'success')
	except Exception as e:
		flash(f'Error deleting file: {str(e)}', 'danger')
	
	return redirect(url_for('member_documents'))


@app.route('/update_description/<filename>', methods=['POST'])
@login_required
def update_description(filename):
	# Only allow admin and BDFL users to update documents
	if not current_user.is_admin_or_bdfl():
		flash('Access denied. Only administrators can update documents.', 'danger')
		return redirect(url_for('member_documents'))
	
	new_title = request.form.get('title', '').strip()
	new_description = request.form.get('description', '').strip()
	doc_key = filename.replace('.pdf', '').lower().replace('_', ' ').replace('-', ' ')
	
	if not new_description:
		flash('Description cannot be empty.', 'warning')
		return redirect(url_for('member_documents'))
	
	# Handle file upload if provided
	file = request.files.get('file')
	if file and file.filename:
		# Validate file type
		if not file.filename.lower().endswith('.pdf'):
			flash('Only PDF files are allowed.', 'danger')
			return redirect(url_for('member_documents'))
		
		# Save the new file
		file_path = os.path.join(app.static_folder, filename)
		file.save(file_path)
		flash(f'File "{filename}" replaced successfully!', 'success')
	
	# Load current descriptions, update, and save
	descriptions = load_document_descriptions()
	descriptions[doc_key] = new_description
	save_document_descriptions(descriptions)
	
	# For now, we'll keep titles as they are in the template
	# Title editing could be implemented later if needed
	
	flash(f'Document "{filename}" updated successfully!', 'success')
	return redirect(url_for('member_documents'))


@app.route('/reorder_documents', methods=['POST'])
@login_required
def reorder_documents():
	# Only allow admin and BDFL users to reorder documents
	if not current_user.is_admin_or_bdfl():
		flash('Access denied. Only administrators can reorder documents.', 'danger')
		return redirect(url_for('member_documents'))
	
	# Get the new order from the form
	new_order = request.form.getlist('document_order[]')
	
	if not new_order:
		flash('No order provided.', 'warning')
		return redirect(url_for('member_documents'))
	
	# Save the new order
	save_document_order(new_order)
	
	flash('Document order updated successfully!', 'success')
	return redirect(url_for('member_documents'))


@app.route('/add_meeting_minutes', methods=['POST'])
@login_required
def add_meeting_minutes():
	# Only allow admin and BDFL users to add meeting minutes
	if not current_user.is_admin_or_bdfl():
		flash('Access denied. Only administrators can add meeting minutes.', 'danger')
		return redirect(url_for('member_documents'))
	
	title = request.form.get('title', '').strip()
	meeting_date = request.form.get('meeting_date', '').strip()
	description = ''  # No longer collected from form
	content = ''  # No longer collected from form
	
	if not title or not meeting_date:
		flash('Title and meeting date are required.', 'danger')
		return redirect(url_for('member_documents'))
	
	# Handle optional PDF file upload
	pdf_filename = None
	if 'pdf_file' in request.files and request.files['pdf_file'].filename:
		file = request.files['pdf_file']
		if file.filename.lower().endswith('.pdf'):
			# Generate unique filename
			import uuid
			filename = f"meeting_minutes_{uuid.uuid4().hex}.pdf"
			file_path = os.path.join(app.static_folder, filename)
			file.save(file_path)
			pdf_filename = filename
		else:
			flash('Only PDF files are allowed for attachments.', 'danger')
			return redirect(url_for('member_documents'))
	
	try:
		database.add_meeting_minutes(title, meeting_date, description, content, pdf_filename)
		flash('Meeting minutes added successfully!', 'success')
	except Exception as e:
		flash(f'Error adding meeting minutes: {str(e)}', 'danger')
	
	return redirect(url_for('member_documents'))


@app.route('/edit_meeting_minutes/<int:minutes_id>', methods=['POST'])
@login_required
def edit_meeting_minutes(minutes_id):
	# Only allow admin and BDFL users to edit meeting minutes
	if not current_user.is_admin_or_bdfl():
		flash('Access denied. Only administrators can edit meeting minutes.', 'danger')
		return redirect(url_for('member_documents'))
	
	title = request.form.get('title', '').strip()
	meeting_date = request.form.get('meeting_date', '').strip()
	description = ''  # No longer collected from form
	content = ''  # No longer collected from form
	
	if not title or not meeting_date:
		flash('Title and meeting date are required.', 'danger')
		return redirect(url_for('member_documents'))
	
	# Handle optional PDF file upload
	pdf_filename = None
	if 'pdf_file' in request.files and request.files['pdf_file'].filename:
		file = request.files['pdf_file']
		if file.filename.lower().endswith('.pdf'):
			# Generate unique filename
			import uuid
			filename = f"meeting_minutes_{uuid.uuid4().hex}.pdf"
			file_path = os.path.join(app.static_folder, filename)
			file.save(file_path)
			pdf_filename = filename
		else:
			flash('Only PDF files are allowed for attachments.', 'danger')
			return redirect(url_for('member_documents'))
	
	try:
		database.update_meeting_minutes(minutes_id, title, meeting_date, description, content, pdf_filename)
		flash('Meeting minutes updated successfully!', 'success')
	except Exception as e:
		flash(f'Error updating meeting minutes: {str(e)}', 'danger')
	
	return redirect(url_for('member_documents'))


@app.route('/delete_meeting_minutes/<int:minutes_id>', methods=['POST'])
@login_required
def delete_meeting_minutes(minutes_id):
	# Only allow admin and BDFL users to delete meeting minutes
	if not current_user.is_admin_or_bdfl():
		flash('Access denied. Only administrators can delete meeting minutes.', 'danger')
		return redirect(url_for('member_documents'))
	
	try:
		# Delete the record and get the PDF filename
		pdf_filename = database.delete_meeting_minutes(minutes_id)
		
		# Delete the associated PDF file if it exists
		if pdf_filename:
			file_path = os.path.join(app.static_folder, pdf_filename)
			if os.path.exists(file_path):
				os.remove(file_path)
		
		flash('Meeting minutes deleted successfully!', 'success')
	except Exception as e:
		flash(f'Error deleting meeting minutes: {str(e)}', 'danger')
	
	return redirect(url_for('member_documents'))


@app.route('/member/<int:member_id>')
@login_required
def member_details(member_id):
	# Check if user can access this member's details
	if not current_user.is_admin_or_bdfl():
		# For regular users, only allow access to their own member record
		user_member = database.get_member_by_email(current_user.email)
		if not user_member or user_member['id'] != member_id:
			flash('Access denied. You can only view your own member details.', 'danger')
			return redirect(url_for('member_dashboard'))
	
	member = database.get_member_by_id(member_id)
	if not member:
		return "Member not found", 404
	member = dict(member) if member else None
	dues = database.get_dues_by_member(member_id)
	work_hours = database.get_work_hours_by_member(member_id)
	total_work_hours = sum(wh['hours'] for wh in work_hours)
	attendance = database.get_meeting_attendance(member_id)
	position = database.get_member_position(member_id)
	# Use new normalized committee structure
	committee_rows = database.get_all_committees()
	committee_names = [row['name'] for row in committee_rows]
	committee_display_names = {k: ' '.join(word.capitalize() for word in k.replace('_', ' ').split()) for k in committee_names}
	# Get this member's committees and roles
	member_committees = database.get_member_committees_new(member_id)
	# Build a dict: {committee_name: 1/0, ...} and {committee_name: 'chair'/'member'}
	committees = {cname: 0 for cname in committee_names}
	committee_roles = {cname: '' for cname in committee_names}
	for row in member_committees:
		row = dict(row)
		cname = row.get('name') or row.get('committee_name')
		if cname:
			committees[cname] = 1
			committee_roles[cname] = row['role']

	total_meetings = sum(1 for att in attendance if att['status'] in ['Attended', 'Exempt'])
	activity_display_names = {
		'general_maintenance': 'General Maintenance',
		'event_setup': 'Event Setup',
		'event_cleanup': 'Event Cleanup',
		'committee_work': 'Committee Work',
		'building_and_grounds': 'Building/Grounds',
		'gun_bingo_social_events': 'Gun Bingo/Social Events',
		'executive_committee': 'Executive',
		'other': 'Other'
	}
	import datetime
	current_year = datetime.datetime.now().year
	dues_years = list(range(current_year + 1, current_year - 10, -1))
	pending_applications = get_pending_application_count()
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
		committee_roles=committee_roles,
		committee_names=committee_names,
		committee_display_names=committee_display_names,
		total_meetings=total_meetings,
		work_activity_display_names=activity_display_names,
		current_year=current_year,
		pending_applications=pending_applications
	)
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
@admin_required
def delete_member(member_id):
	database.soft_delete_member_by_id(member_id)
	# Disable user account
	member = database.get_member_by_id(member_id)
	if member:
		user = database.get_user_by_email(member['email'])
		if user:
			database.update_user_active_status(user['id'], False)
	return redirect(url_for('index'))

# Recycle bin page
@app.route('/recycle_bin')
@login_required
@admin_required
def recycle_bin():
	deleted_members = database.get_deleted_members()
	member_stats = get_member_stats()
	pending_applications = get_pending_application_count()
	return render_template('recycle_bin.html', deleted_members=deleted_members, active_page='recycle_bin', member_stats=member_stats, pending_applications=pending_applications)

# Restore ALL members from recycle bin
@app.route('/recycle_bin/restore_all', methods=['POST'])
@login_required
def recycle_bin_restore_all():
	deleted_members = database.get_deleted_members()
	for m in deleted_members:
		try:
			database.restore_member_by_id(m['id'])
			# Re-enable user account based on membership type
			active_statuses = ['Probationary', 'Associate', 'Active', 'Life']
			is_active = m['membership_type'] in active_statuses
			user = database.get_user_by_email(m['email'])
			if user:
				database.update_user_active_status(user['id'], is_active)
		except Exception:
			# Continue restoring others even if one fails
			continue
	return redirect(url_for('recycle_bin'))

# Permanently DELETE ALL members in recycle bin
@app.route('/recycle_bin/delete_all', methods=['POST'])
@login_required
@admin_required
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
	# Re-enable user account based on membership type
	member = database.get_member_by_id(member_id)
	if member:
		active_statuses = ['Probationary', 'Associate', 'Active', 'Life']
		is_active = member['membership_type'] in active_statuses
		user = database.get_user_by_email(member['email'])
		if user:
			database.update_user_active_status(user['id'], is_active)
	return redirect(url_for('recycle_bin'))

@app.route('/bulk_actions')
@login_required
@admin_required
def bulk_actions():
	member_stats = get_member_stats()
	committee_names = [row['name'] for row in database.get_all_committees()]
	committee_display_names = {k: ' '.join(word.capitalize() for word in k.replace('_', ' ').split()) for k in committee_names}
	pending_applications = get_pending_application_count()
	return render_template('bulk_actions.html', active_page='bulk_actions', member_stats=member_stats, committee_names=committee_names, committee_display_names=committee_display_names, pending_applications=pending_applications)

@app.route('/api/get_all_members', methods=['GET'])
@login_required
@admin_required
def api_get_all_members():
	try:
		members = database.get_all_members()
		# Convert Row objects to dictionaries and exclude Life and Honorary members
		members_list = []
		for member in members:
			# Skip Life and Honorary members
			if member['membership_type'] in ['Life', 'Honorary']:
				continue
			members_list.append({
				'id': member['id'],
				'badge_number': member['badge_number'],
				'first_name': member['first_name'],
				'last_name': member['last_name']
			})
		return jsonify(members_list)
	except Exception as e:
		return jsonify({'error': str(e)}), 400

@app.route('/api/get_all_members_for_bulk', methods=['GET'])
@login_required
@admin_required
def api_get_all_members_for_bulk():
	try:
		members = database.get_all_members()
		# Convert Row objects to dictionaries and include ALL members for bulk operations
		members_list = []
		for member in members:
			members_list.append({
				'id': member['id'],
				'badge_number': member['badge_number'],
				'first_name': member['first_name'],
				'last_name': member['last_name']
			})
		return jsonify(members_list)
	except Exception as e:
		return jsonify({'error': str(e)}), 400

@app.route('/bulk_add_dues', methods=['POST'])
@csrf.exempt
@login_required
@admin_required
def bulk_add_dues():
	try:
		data = request.get_json()
		
		if not data:
			return jsonify({'success': False, 'message': 'No data received'}), 400
		
		year = data.get('year')
		amount = data.get('amount')
		method = data.get('method')
		date = data.get('date')
		notes = data.get('notes', '')
		member_ids = data.get('member_ids', [])
		
		# Validate required fields
		if not year:
			return jsonify({'success': False, 'message': 'Year is required'}), 400
		if not amount:
			return jsonify({'success': False, 'message': 'Amount is required'}), 400
		if not method:
			return jsonify({'success': False, 'message': 'Payment method is required'}), 400
		if not date:
			return jsonify({'success': False, 'message': 'Date is required'}), 400
		if not member_ids:
			return jsonify({'success': False, 'message': 'No members selected'}), 400
		
		success_count = 0
		errors = []
		for member_id in member_ids:
			try:
				database.add_due(int(member_id), date, float(amount), year, method, notes)
				success_count += 1
			except Exception as e:
				error_msg = f"Member {member_id}: {str(e)}"
				print(error_msg)
				errors.append(error_msg)
				continue
		
		response = {'success': True, 'count': success_count}
		if errors:
			response['errors'] = errors
		
		return jsonify(response)
	except Exception as e:
		print(f"Bulk add dues error: {str(e)}")
		import traceback
		traceback.print_exc()
		return jsonify({'success': False, 'message': str(e)}), 400

@app.route('/bulk_add_work_hours', methods=['POST'])
@csrf.exempt
@login_required
@admin_required
def bulk_add_work_hours():
	try:
		data = request.get_json()
		
		if not data:
			return jsonify({'success': False, 'message': 'No data received'}), 400
		
		date = data.get('date')
		activity = data.get('activity')
		hours = data.get('hours')
		notes = data.get('notes', '')
		member_ids = data.get('member_ids', [])
		
		# Validate required fields
		if not date:
			return jsonify({'success': False, 'message': 'Date is required'}), 400
		if not activity:
			return jsonify({'success': False, 'message': 'Activity is required'}), 400
		if not hours:
			return jsonify({'success': False, 'message': 'Hours is required'}), 400
		if not member_ids:
			return jsonify({'success': False, 'message': 'No members selected'}), 400
		
		success_count = 0
		errors = []
		for member_id in member_ids:
			try:
				database.add_work_hours(int(member_id), date, activity, float(hours), notes)
				success_count += 1
			except Exception as e:
				error_msg = f"Member {member_id}: {str(e)}"
				print(error_msg)
				errors.append(error_msg)
				continue
		
		response = {'success': True, 'count': success_count}
		if errors:
			response['errors'] = errors
		
		return jsonify(response)
	except Exception as e:
		print(f"Bulk add work hours error: {str(e)}")
		import traceback
		traceback.print_exc()
		return jsonify({'success': False, 'message': str(e)}), 400

@app.route('/bulk_add_meeting_attendance', methods=['POST'])
@csrf.exempt
@login_required
@admin_required
def bulk_add_meeting_attendance():
	try:
		data = request.get_json()
		
		if not data:
			return jsonify({'success': False, 'message': 'No data received'}), 400
		
		date = data.get('date')
		status = data.get('status')
		member_ids = data.get('member_ids', [])
		
		# Validate required fields
		if not date:
			return jsonify({'success': False, 'message': 'Date is required'}), 400
		if not status:
			return jsonify({'success': False, 'message': 'Status is required'}), 400
		if not member_ids:
			return jsonify({'success': False, 'message': 'No members selected'}), 400
		
		# Validate status
		valid_statuses = ['Attended', 'Exempt', 'Absent']
		if status not in valid_statuses:
			return jsonify({'success': False, 'message': 'Invalid status. Must be one of: ' + ', '.join(valid_statuses)}), 400
		
		success_count = 0
		errors = []
		for member_id in member_ids:
			try:
				database.add_meeting_attendance(int(member_id), date, status)
				success_count += 1
			except Exception as e:
				error_msg = f"Member {member_id}: {str(e)}"
				print(error_msg)
				errors.append(error_msg)
				continue
		
		response = {'success': True, 'count': success_count}
		if errors:
			response['errors'] = errors
		
		return jsonify(response)
	except Exception as e:
		print(f"Bulk add meeting attendance error: {str(e)}")
		import traceback
		traceback.print_exc()
		return jsonify({'success': False, 'message': str(e)}), 400

# Edit Member route
@app.route('/edit_member/<int:member_id>', methods=['GET', 'POST'])
@login_required
@admin_required
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
@csrf.exempt
@login_required
@admin_required
def add_member():
	if request.method == 'POST':
		try:
			data = (
				request.form.get('badge_number', ''),
				request.form.get('membership_type', ''),
				request.form.get('first_name', ''),
				request.form.get('middle_name', ''),
				request.form.get('last_name', ''),
				request.form.get('suffix', ''),
				request.form.get('nickname', ''),
				request.form.get('dob', ''),
				request.form.get('email', ''),
				request.form.get('email2', ''),
				request.form.get('phone', ''),
				request.form.get('phone2', ''),
				request.form.get('address', ''),
				request.form.get('city', ''),
				request.form.get('state', ''),
				request.form.get('zip', ''),
				request.form.get('join_date', ''),
				request.form.get('sponsor', ''),
				request.form.get('card_internal', ''),
				request.form.get('card_external', ''),
			)
			member_id = database.add_member(data)
			
			# Create user account
			membership_type = request.form.get('membership_type', '')
			active_statuses = ['Probationary', 'Associate', 'Active', 'Life']
			is_active = membership_type in active_statuses
			email = request.form.get('email', '')
			if email:
				existing_user = database.get_user_by_email(email)
				if not existing_user:
					from werkzeug.security import generate_password_hash
					name = f"{request.form.get('first_name', '')} {request.form.get('last_name', '')}".strip()
					username = email
					password_hash = generate_password_hash('password')
					database.create_user(username, password_hash, email, name, 'User', is_active)
			
			database.log_audit(
				user_id=current_user.id,
				username=current_user.username,
				action='add_member',
				ip_address=request.remote_addr,
				user_agent=request.headers.get('User-Agent'),
				success=True,
				details=f"Added member {request.form.get('first_name')} {request.form.get('last_name')} (Badge: {request.form.get('badge_number')})"
			)
			flash(f'Member {request.form.get("first_name")} {request.form.get("last_name")} added successfully!', 'success')
			return jsonify({'success': True, 'member_id': member_id}), 200
		except Exception as e:
			database.log_audit(
				user_id=current_user.id,
				username=current_user.username,
				action='add_member',
				ip_address=request.remote_addr,
				user_agent=request.headers.get('User-Agent'),
				success=False,
				details=f"Error: {str(e)}"
			)
			return jsonify({'success': False, 'error': str(e)}), 400
	return render_template('add_member.html')

# Edit Section route
@app.route('/edit_section/<int:member_id>', methods=['GET', 'POST'])
@csrf.exempt
@login_required
def edit_section(member_id):
	section = request.args.get('section')
	member = database.get_member_by_id(member_id)
	if not member:
		return "Member not found", 404
	if request.method == 'POST':
		try:
			print(f"[DEBUG] Received POST to /edit_section/{member_id} with section={section}")
			print(f"[DEBUG] Form data: {request.form.to_dict(flat=False)}")
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
				old_membership_type = member['membership_type']
				new_membership_type = request.form['membership_type']
				database.update_member_section(member_id, {
					'badge_number': request.form['badge_number'],
					'membership_type': new_membership_type,
					'join_date': request.form['join_date'] or None,
					'application_submitted': request.form.get('application_submitted') or None,
					'introduced_date': request.form.get('introduced_date') or None,
					'background_check_submitted': request.form.get('background_check_submitted') or None,
					'background_check_passed': request.form.get('background_check_passed') or None,
					'sponsor': request.form['sponsor'],
					'card_internal': request.form['card_internal'],
					'card_external': request.form['card_external'],
					'member_notes': request.form['member_notes'],
				})
				# Update user active status if membership type changed
				if old_membership_type != new_membership_type:
					active_statuses = ['Probationary', 'Associate', 'Active', 'Life']
					is_active = new_membership_type in active_statuses
					user = database.get_user_by_email(member['email'])
					if user:
						database.update_user_active_status(user['id'], is_active)
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
				# Use normalized committee_memberships table
				committee_names = [row['name'] for row in database.get_all_committees()]
				new_memberships = {}
				for cname in committee_names:
					is_member = request.form.get(f'committee_{cname}') == '1'
					is_chair = request.form.get(f'chair_{cname}') == '1'
					if is_member:
						new_memberships[cname] = 'chair' if is_chair else 'member'
					else:
						new_memberships[cname] = 'none'
				database.update_member_committees_normalized(member_id, new_memberships)
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
@admin_required
def delete_due(due_id):
    database.delete_due(due_id)
    return ('', 204)

@app.route('/delete_member_permanently/<int:member_id>', methods=['POST'])
@login_required
@admin_required
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
@admin_required
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
@admin_required
def delete_meeting_attendance(att_id):
    database.delete_meeting_attendance(att_id)
    return ('', 204)

@app.route('/meeting_attendance_report', endpoint='meeting_attendance_report')
@login_required
@admin_required
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
	pending_applications = get_pending_application_count()
	return render_template('meeting_attendance_report.html', attendance=attendance, years=years, selected_year=year, months=months, selected_month=month, now=now, active_page='meeting_attendance_report', member_stats=member_stats, pending_applications=pending_applications)

@app.route('/committees')
@login_required
@admin_required
def committees():
	# Use new normalized schema
	committee_names = [row['name'] for row in database.get_all_committees()]
	committee_display_names = {k: ' '.join(word.capitalize() for word in k.replace('_', ' ').split()) for k in committee_names}
	committee_members = {cname: [] for cname in committee_names}
	# Get all committee_names with ids
	committee_name_rows = database.get_all_committees()
	committee_name_id_map = {row['name']: row['id'] for row in committee_name_rows}
	# For each committee, get members
	for cname, cid in committee_name_id_map.items():
		members = database.get_committee_members(cid)
		unique_members = {}
		for member in members:
			member_copy = dict(member)
			mid = member_copy['id']
			# If already present, prefer 'chair' role
			if mid in unique_members:
				if member_copy.get('role') == 'chair':
					unique_members[mid] = member_copy
			else:
				unique_members[mid] = member_copy
			member_copy['is_chair'] = (member_copy.get('role') == 'chair')
			if cname == 'executive_committee':
				position = database.get_member_position(member['id'])
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
		committee_members[cname] = list(unique_members.values())
	# Add special "Committee Chairs" option
	chair_members = []
	for cname, cid in committee_name_id_map.items():
		members = database.get_committee_members(cid)
		for member in members:
			member_dict = dict(member)
			if member_dict.get('role') == 'chair':
				member_copy = dict(member)
				member_copy['chair_of'] = committee_display_names[cname]
				chair_members.append(member_copy)
	committee_members['committee_chairs'] = chair_members
	import datetime
	now = datetime.datetime.now()
	selected_committee = request.args.get('committee')
	member_stats = get_member_stats()
	pending_applications = get_pending_application_count()
	return render_template('committees.html', committee_names=committee_names, committee_display_names=committee_display_names, committee_members=committee_members, selected_committee=selected_committee, now=now, active_page='committees', member_stats=member_stats, pending_applications=pending_applications)

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
		# Filter members who are in the selected committee (handle both int 1 and str '1')
		committee_member_list = []
		for member in all_members:
			member_committees = database.get_member_committees(member['id'])
			if member_committees and (committee in member_committees) and (str(member_committees.get(committee)) == '1' or member_committees.get(committee) == 1):
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
@admin_required
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
	pending_applications = get_pending_application_count()
	return render_template('kiosk_report.html', 
						   checkins=checkins, 
						   member_stats=member_stats,
						   date_filter=date_filter,
						   start_date=start_date,
						   end_date=end_date,
						   active_page='kiosk_report',
						   pending_applications=pending_applications)

@app.route('/kiosk_export_csv')
@login_required
@admin_required
def kiosk_export_csv():
	date_filter = request.args.get('date')
	start_date = request.args.get('start_date')
	end_date = request.args.get('end_date')
	
	if start_date and end_date:
		checkins = database.get_checkins_by_date_range(start_date, end_date)
		filename = f'checkins_{start_date}_to_{end_date}.csv'
	elif date_filter:
		checkins = database.get_all_checkins(date=date_filter)
		filename = f'checkins_{date_filter}.csv'
	else:
		# Default to today
		today = datetime.date.today().strftime('%Y-%m-%d')
		checkins = database.get_all_checkins(date=today)
		filename = f'checkins_{today}.csv'
	
	# Create CSV content
	import csv
	import io
	
	output = io.StringIO()
	writer = csv.writer(output)
	
	# Write header
	writer.writerow(['Check-in Time', 'Check-out Time', 'Member Number', 'First Name', 'Last Name', 'Duration'])
	
	# Write data
	for checkin in checkins:
		# Calculate duration if checked out
		duration = ''
		if checkin['check_out_time']:
			check_in_dt = datetime.datetime.fromisoformat(checkin['check_in_time'])
			check_out_dt = datetime.datetime.fromisoformat(checkin['check_out_time'])
			duration_delta = check_out_dt - check_in_dt
			total_seconds = int(duration_delta.total_seconds())
			hours, remainder = divmod(total_seconds, 3600)
			minutes, seconds = divmod(remainder, 60)
			duration = f"{hours:02d}:{minutes:02d}:{seconds:02d}"
		
		writer.writerow([
			checkin['check_in_time'],
			checkin['check_out_time'] or '',
			checkin['member_number'],
			checkin['first_name'] or '',
			checkin['last_name'] or '',
			duration
		])
	
	# Create response
	output.seek(0)
	response = make_response(output.getvalue())
	response.headers['Content-Type'] = 'text/csv'
	response.headers['Content-Disposition'] = f'attachment; filename={filename}'
	return response

# Confirmation page route
@app.route('/application_confirmation')
def application_confirmation():
	return render_template('application_confirmation.html')

# Membership Application route
@app.route('/membership_application', methods=['GET', 'POST'])
@csrf.exempt
def membership_application():
	if request.method == 'POST':
		data = (
			request.form['first_name'],
			request.form.get('middle_name', ''),
			request.form['last_name'],
			request.form.get('suffix', ''),
			request.form.get('nickname', ''),
			request.form['sex'],
			request.form['date_of_birth'],
			request.form['email'],
			request.form.get('email2', ''),
			request.form['phone'],
			request.form.get('phone2', ''),
			request.form['address'],
			request.form['city'],
			request.form['state'],
			request.form['zip'],
			request.form.get('sponsor', ''),
			request.form.get('hql', ''),
			request.form.get('carry_permit', ''),
			request.form.get('hunters_education', ''),
			request.form.get('felony_conviction', ''),
			request.form.get('felony_details', ''),
			request.form.get('inactive_docket', ''),
			request.form.get('inactive_docket_details', ''),
			request.form.get('restraining_order', ''),
			request.form.get('restraining_order_details', ''),
			request.form.get('firearm_legal', ''),
			request.form.get('firearm_legal_details', ''),
			'on' if request.form.get('payment_confirmation') else '',
			'on' if request.form.get('waiver_agreement') else ''
		)
		database.add_application(data)
		return redirect(url_for('application_confirmation'))
	return render_template('membership_application.html', success=False)



@app.route('/admin/application/<int:app_id>')
@login_required
@admin_required
def view_application(app_id):
	"""View application details"""
	if not current_user.is_admin_or_bdfl():
		return jsonify({'error': 'Access denied'}), 403
	
	app = database.get_application_by_id(app_id)
	if not app:
		return jsonify({'error': 'Application not found'}), 404
	
	return jsonify(dict(app))

@app.route('/admin/application/<int:app_id>/approve', methods=['POST'])
@login_required
@admin_required
@csrf.exempt
def approve_application(app_id):
	"""Approve an application and create member"""
	if not current_user.is_admin_or_bdfl():
		if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
			return jsonify({'success': False, 'message': 'Access denied. Only administrators can approve applications.'}), 403
		flash('Access denied. Only administrators can approve applications.', 'error')
		return redirect(url_for('admin_applications'))
	
	badge_number = request.form.get('badge_number')
	if not badge_number:
		if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
			return jsonify({'success': False, 'message': 'Badge number is required to approve application.'}), 400
		flash('Badge number is required to approve application.', 'error')
		return redirect(url_for('admin_applications'))
	
	success = database.approve_application(app_id, current_user.id, badge_number)
	if success:
		if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
			return jsonify({'success': True, 'message': f'Application approved! Member created with badge number {badge_number}.'})
		flash(f'Application approved! Member created with badge number {badge_number}.', 'info')
	else:
		if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
			return jsonify({'success': False, 'message': 'Failed to approve application.'}), 500
		flash('Failed to approve application.', 'error')
	return redirect(url_for('admin_applications'))

@app.route('/admin/application/<int:app_id>/reject', methods=['POST'])
@login_required
@admin_required
@csrf.exempt
def reject_application(app_id):
	"""Reject an application"""
	if not current_user.is_admin_or_bdfl():
		if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
			return jsonify({'success': False, 'message': 'Access denied. Only administrators can reject applications.'}), 403
		flash('Access denied. Only administrators can reject applications.', 'error')
		return redirect(url_for('admin_applications'))
	
	notes = request.form.get('notes', '')
	success = database.reject_application(app_id, current_user.id, notes)
	if success:
		if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
			return jsonify({'success': True, 'message': 'Application rejected.'})
		flash('Application rejected.', 'info')
	else:
		if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
			return jsonify({'success': False, 'message': 'Failed to reject application.'}), 500
		flash('Failed to reject application.', 'error')
	return redirect(url_for('admin_applications'))

# Initialize database on startup
database.init_database()

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

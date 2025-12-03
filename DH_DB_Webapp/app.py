from flask import Flask, render_template, request, redirect, url_for
import database
import datetime
import socket

app = Flask(__name__)

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

@app.route('/add_work_hours/<int:member_id>', methods=['POST'])
@app.route('/dues_report')

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

def add_work_hours(member_id):
	date = request.form['date']
	activity = request.form['activity']
	hours = request.form['hours']
	notes = request.form['notes']
	database.add_work_hours(member_id, date, activity, hours, notes)
	return ('', 204)

# Work Hours Report route
@app.route('/work_hours_report')
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
def add_meeting_attendance(member_id):
    date = request.form['date']
    status = request.form['status']
    database.add_meeting_attendance(member_id, date, status)
    return ('', 204)

@app.route('/', methods=['GET'])
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
	return render_template(
		'member_details.html',
		member=member,
		dues=dues,
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
def reports():
	return render_template('reports.html', active_page='reports')

# Member Report route
@app.route('/member_report/<int:member_id>')
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
def delete_member(member_id):
	database.soft_delete_member_by_id(member_id)
	return redirect(url_for('index'))

# Recycle bin page
@app.route('/recycle_bin')
def recycle_bin():
	deleted_members = database.get_deleted_members()
	member_stats = get_member_stats()
	return render_template('recycle_bin.html', deleted_members=deleted_members, active_page='recycle_bin', member_stats=member_stats)

# Restore ALL members from recycle bin
@app.route('/recycle_bin/restore_all', methods=['POST'])
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
def restore_member(member_id):
	database.restore_member_by_id(member_id)
	return redirect(url_for('recycle_bin'))

# Edit Member route
@app.route('/edit_member/<int:member_id>', methods=['GET', 'POST'])
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
def edit_section(member_id):
	section = request.args.get('section')
	member = database.get_member_by_id(member_id)
	if not member:
		return "Member not found", 404
	if request.method == 'POST':
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
			database.add_due(
				member_id,
				request.form['payment_date'],
				request.form['amount'],
				request.form['year'],
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
			for cname in committee_names:
				form_key = f'committee_{cname}'
				value = request.form.get(form_key)
				updates[cname] = 1 if value == '1' else 0
				logging.debug(f"Committee: {cname}, Form Key: {form_key}, Value: {value}, Update: {updates[cname]}")
			logging.debug(f"Updates dict: {updates}")
			try:
				database.update_member_committees(member_id, updates)
				logging.debug(f"Successfully updated committees for member {member_id}")
			except Exception as e:
				logging.error(f"Error updating committees for member {member_id}: {e}")
				import traceback
				logging.error(traceback.format_exc())
		return ('', 204)  # AJAX expects empty response
	# For GET, just show a message (should not be used with popup)
	return f"Edit {section} for member {member_id}"  # Replace with render_template as needed

@app.route('/get_due/<int:due_id>')
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
def edit_due(due_id):
	payment_date = request.form['payment_date']
	amount = request.form['amount']
	year = request.form['year']
	method = request.form.get('method', '')
	notes = request.form.get('notes', '')
	database.update_due(due_id, payment_date, amount, year, method, notes)
	return ('', 204)

@app.route('/delete_due/<int:due_id>', methods=['POST'])
def delete_due(due_id):
    database.delete_due(due_id)
    return ('', 204)

@app.route('/delete_member_permanently/<int:member_id>', methods=['POST'])
def delete_member_permanently(member_id):
    database.delete_member_permanently(member_id)
    return redirect(url_for('recycle_bin'))

@app.route('/get_work_hours/<int:wh_id>')
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
def edit_work_hours(wh_id):
    date = request.form['date']
    activity = request.form['activity']
    hours = request.form['hours']
    notes = request.form['notes']
    database.update_work_hours(wh_id, date, activity, hours, notes)
    return ('', 204)

@app.route('/delete_work_hours/<int:wh_id>', methods=['POST'])
def delete_work_hours(wh_id):
    database.delete_work_hours(wh_id)
    return ('', 204)

@app.route('/get_meeting_attendance/<int:att_id>')
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
def edit_meeting_attendance(att_id):
    date = request.form['date']
    status = request.form['status']
    database.update_meeting_attendance(att_id, date, status)
    return ('', 204)

@app.route('/delete_meeting_attendance/<int:att_id>', methods=['POST'])
def delete_meeting_attendance(att_id):
    database.delete_meeting_attendance(att_id)
    return ('', 204)

@app.route('/meeting_attendance_report', endpoint='meeting_attendance_report')
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
				if cname == 'executive_committee':
					member_copy = dict(member)
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
				else:
					committee_members[cname].append(member)
	conn.close()
	import datetime
	now = datetime.datetime.now()
	selected_committee = request.args.get('committee')
	member_stats = get_member_stats()
	return render_template('committees.html', committee_names=committee_names, committee_display_names=committee_display_names, committee_members=committee_members, selected_committee=selected_committee, now=now, active_page='committees', member_stats=member_stats)

@app.route('/email_list')
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

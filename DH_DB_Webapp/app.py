from flask import Flask, render_template, request, redirect, url_for
import database

app = Flask(__name__)

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
	# Filter by search
	if search:
		search_lower = search.lower()
		members = [m for m in members if search_lower in str(m['first_name']).lower() or search_lower in str(m['last_name']).lower() or search_lower in str(m['badge_number']).lower()]
	member_types = ["All", "Probationary", "Associate", "Active", "Life", "Honorary", "Prospective", "Wait List", "Former"]
	return render_template('index.html', members=members, search=search, member_type=member_type, member_types=member_types)

# Member details route
@app.route('/member/<int:member_id>')
def member_details(member_id):
	member = database.get_member_by_id(member_id)
	if not member:
		return "Member not found", 404
	member = dict(member) if member else None
	dues = database.get_dues_by_member(member_id)
	work_hours = database.get_work_hours_by_member(member_id)
	attendance = database.get_meeting_attendance(member_id)
	role = database.get_member_role(member_id)
	committees = database.get_member_committees(member_id)
	return render_template(
		'member_details.html',
		member=member,
		dues=dues,
		work_hours=work_hours,
		attendance=attendance,
		role=role,
		committees=committees
	)

# Member Report route
@app.route('/member_report/<int:member_id>')
def member_report(member_id):
	member = database.get_member_by_id(member_id)
	if not member:
		return "Member not found", 404
	dues = database.get_dues_by_member(member_id)
	work_hours = database.get_work_hours_by_member(member_id)
	attendance = database.get_meeting_attendance(member_id)
	role = database.get_member_role(member_id)
	committees = database.get_member_committees(member_id)
	return render_template(
		'member_report.html',
		member=member,
		dues=dues,
		work_hours=work_hours,
		attendance=attendance,
		role=role,
		committees=committees
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
	return render_template('recycle_bin.html', deleted_members=deleted_members)

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
            database.add_due(member_id, request.form['payment_date'], request.form['amount'])
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
        "amount": due["amount"]
    }

@app.route('/edit_due/<int:due_id>', methods=['POST'])
def edit_due(due_id):
    payment_date = request.form['payment_date']
    amount = request.form['amount']
    database.update_due(due_id, payment_date, amount)
    return ('', 204)

@app.route('/delete_due/<int:due_id>', methods=['POST'])
def delete_due(due_id):
    database.delete_due(due_id)
    return ('', 204)

@app.route('/delete_member_permanently/<int:member_id>', methods=['POST'])
def delete_member_permanently(member_id):
    database.delete_member_permanently(member_id)
    return redirect(url_for('recycle_bin'))

if __name__ == '__main__':
	app.run(debug=True)
